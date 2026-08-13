//! Mist parameters for the shared MCP Streamable HTTP transport.

use mecmcp_auth::{BearerSyntax, CallerCtx, TokenStoreFile};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, CallerScopes, HostOriginPolicy,
    HttpServeError, HttpTransportBuildError, HttpTransportConfig, LimitsConfig,
    NoAuthAcknowledgement, ScopePreflight, ServePlan, TransportIdentity,
    build_streamable_http_router, serve_router,
};
use rustmistmcp_core::{MistGrant, MistTarget};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

use crate::{MistHandler, RESTRICTED_TOOLS};

/// Authentication configuration for HTTP transport.
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// Authenticated with a token store file.
    Authenticated(Arc<TokenStoreFile<MistGrant>>),
    /// Explicitly unauthenticated (requires operator acknowledgement).
    ExplicitlyUnauthenticated,
}

/// Why a handler built without a Mist credential refuses live calls.
///
/// This used to cite `mecmcp#90`, the vendor-neutral cloud foundation. That
/// has landed and `MistHandler::from_config` builds a real client, so what is
/// missing here is the credential itself — including the one the `/api/v1/self`
/// startup identity probe needs.
pub const LIVE_MIST_BLOCKER: &str = "no Mist credential is configured, so live Mist requests and the /api/v1/self startup identity probe are unavailable";

/// Mist-aware early scope check for raw `org_id` and `site_id` arguments.
///
/// The pinned shared token schema temporarily persists canonical target
/// subjects in its `devices` field. This preflight translates wire arguments
/// to `org/<uuid>` and `site/<uuid>` before consulting that shared scope.
/// Handler authorization remains the final boundary.
#[derive(Debug, Clone, Copy)]
pub struct MistScopePreflight {
    restricted_tools: &'static [&'static str],
}

impl MistScopePreflight {
    /// Construct a preflight with the product's restricted-read registry.
    #[must_use]
    pub const fn new(restricted_tools: &'static [&'static str]) -> Self {
        Self { restricted_tools }
    }

    fn request_exceeds_scope(
        &self,
        value: &Value,
        tools: &mecmcp_auth::ScopeSet,
        devices: &mecmcp_auth::ScopeSet,
    ) -> bool {
        if value.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let Some(params) = value.get("params") else {
            return false;
        };
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return false;
        };
        if !tools.allows_tool(tool, self.restricted_tools) {
            return true;
        }
        let Some(arguments) = params.get("arguments") else {
            return false;
        };
        let Some(arguments) = arguments.as_object() else {
            return true;
        };
        if target_map_exceeds_scope(arguments, devices) {
            return true;
        }
        ["path", "query"].into_iter().any(|container| {
            arguments.get(container).is_some_and(|value| {
                if value.is_null() {
                    return false;
                }
                value
                    .as_object()
                    .is_none_or(|values| target_map_exceeds_scope(values, devices))
            })
        })
    }
}

fn target_map_exceeds_scope(
    values: &serde_json::Map<String, Value>,
    targets: &mecmcp_auth::ScopeSet,
) -> bool {
    ["org_id", "site_id"].into_iter().any(|field| {
        values.get(field).is_some_and(|value| {
            value
                .as_str()
                .and_then(|id| canonical_target(field, id))
                .is_none_or(|subject| !targets.allows(&subject))
        })
    })
}

fn canonical_target(field: &str, id: &str) -> Option<String> {
    match field {
        "org_id" => MistTarget::org(id).ok(),
        "site_id" => MistTarget::site(id).ok(),
        _ => None,
    }
    .map(|target| target.subject())
}

impl ScopePreflight for MistScopePreflight {
    fn check(&self, body: &[u8], caller: CallerScopes<'_>) -> Result<(), String> {
        if body.is_empty() {
            return Ok(());
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return Ok(());
        };
        // Clone ScopeSets to avoid capture issues in closures
        let devices = caller.devices.clone();
        let tools = caller.tools.clone();
        let denied = match &value {
            Value::Array(values) => values
                .iter()
                .any(|value| self.request_exceeds_scope(value, &tools, &devices)),
            value => self.request_exceeds_scope(value, &tools, &devices),
        };
        if denied {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

/// Build the complete shared HTTP router with Mist-owned identity and scope
/// fields.
///
/// Metrics remain disabled by default at the binary boundary because the
/// shared `/metrics` route is intentionally unauthenticated.
///
/// # Errors
///
/// Returns an error when shared HTTP limits or router composition are invalid.
pub fn build_http_router(
    handler: MistHandler,
    auth_config: AuthConfig,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    shutdown: CancellationToken,
) -> Result<ServePlan, HttpTransportBuildError> {
    let identity =
        TransportIdentity::new("rustmistmcp", "mist", "rustmistmcp", ["org_id", "site_id"]);
    let host_origin = HostOriginPolicy::enforced(allowed_hosts, allowed_origins);

    let config = match auth_config {
        AuthConfig::Authenticated(store_file) => {
            let auth_store = store_file.clone();
            let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
                let snapshot = auth_store.store();
                snapshot.authenticate(candidate).map(CallerCtx::from)
            });
            let boundary = BearerBoundary::new(
                authenticator,
                BearerResponseProfile::detailed("rustmistmcp"),
            )
            .with_preflight(MistScopePreflight::new(RESTRICTED_TOOLS));
            HttpTransportConfig::authenticated(identity, limits, host_origin, shutdown, boundary)
        }
        AuthConfig::ExplicitlyUnauthenticated => HttpTransportConfig::unauthenticated(
            identity,
            limits,
            host_origin,
            shutdown,
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        ),
    }
    .with_metrics(enable_metrics);

    build_streamable_http_router(move || Ok::<_, std::io::Error>(handler.clone()), config)
}

/// Install the shared Unix SIGHUP hook for token snapshots only.
///
/// A failed parse retains the last verified snapshot. Mist configuration,
/// credentials, clients, listener addresses, TLS, and audit sinks are
/// immutable for the process lifetime and require restart.
///
/// # Errors
///
/// Returns an error if the platform signal handler cannot be installed.
pub fn install_token_reload_handler(store: Arc<TokenStoreFile<MistGrant>>) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || match store.reload() {
        Ok(()) => tracing::info!(tokens = store.store().len(), "token store reloaded"),
        Err(error) => {
            tracing::error!(%error, "token reload failed; retaining previous snapshot");
        }
    })
}

/// Serve the shared HTTP router over plain HTTP or supplied TLS.
///
/// # Errors
///
/// Returns router construction, bind, or serving failures.
#[allow(clippy::too_many_arguments)]
pub async fn serve_http(
    handler: MistHandler,
    address: SocketAddr,
    auth_config: AuthConfig,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: CancellationToken,
    shutdown_timeout: std::time::Duration,
) -> Result<(), HttpServeError> {
    let plan = build_http_router(
        handler,
        auth_config,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        shutdown,
    )
    .map_err(|error| HttpServeError::Serve {
        address,
        error: std::io::Error::other(error.to_string()),
    })?;
    serve_router(plan, address, tls, shutdown_timeout).await
}
