//! Mist parameters for the shared MCP Streamable HTTP transport.

use anyhow::{Context as _, Result};
use axum::Router;
use mecmcp_auth::{BearerSyntax, CallerCtx, TokenStoreFile};
use mecmcp_runtime::{
    cli::Cli,
    cli_validate::{CliRefusal, ServeValidation, ValidatedServe},
};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, CallerScopes, HostOriginPolicy,
    HttpTransportConfig, LimitsConfig, ScopePreflight, TransportIdentity,
    build_streamable_http_router, serve_router,
};
use rustmistmcp_core::{MistGrant, MistTarget};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};

use crate::{MistHandler, RESTRICTED_TOOLS};

/// Production Mist calls and the `/api/v1/self` startup identity probe remain
/// unavailable until the vendor-neutral cloud foundation tracked by
/// `mecmcp#90` lands.
pub const LIVE_MIST_BLOCKER: &str =
    "mecmcp#90 blocks live Mist requests and the required /api/v1/self startup identity probe";

/// Apply RustMistMCP's stricter remote listener policy through the shared
/// validation API.
///
/// Unlike the shared compatibility default, this consumer requires at least
/// one exact allowed Host and browser Origin for every off-loopback listener.
///
/// # Errors
///
/// Returns the first shared CLI refusal for an unsafe or ambiguous setting.
pub fn validate_runtime_serve(cli: &Cli) -> Result<ValidatedServe, CliRefusal> {
    let allowed_hosts = cli
        .allowed_host
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let allowed_origins = cli
        .allowed_origin
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    mecmcp_runtime::cli_validate::validate_serve(&ServeValidation {
        transport: cli.transport,
        host: &cli.host,
        tokens_file: cli.tokens_file.as_deref(),
        tls_cert: cli.tls_cert.as_deref(),
        tls_key: cli.tls_key.as_deref(),
        allow_no_auth: cli.allow_no_auth,
        allow_insecure_bind: cli.allow_insecure_bind,
        allowed_hosts: &allowed_hosts,
        allowed_origins: &allowed_origins,
        require_allowed_host_off_loopback: true,
        require_allowed_origin_off_loopback: true,
    })
}

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

    fn request_exceeds_scope(&self, value: &Value, caller: CallerScopes<'_>) -> bool {
        if value.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let Some(params) = value.get("params") else {
            return false;
        };
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return false;
        };
        if !caller.tools.allows_tool(tool, self.restricted_tools) {
            return true;
        }
        let Some(arguments) = params.get("arguments") else {
            return false;
        };
        let Some(arguments) = arguments.as_object() else {
            return true;
        };
        if target_map_exceeds_scope(arguments, caller.devices) {
            return true;
        }
        ["path", "query"].into_iter().any(|container| {
            arguments.get(container).is_some_and(|value| {
                if value.is_null() {
                    return false;
                }
                value
                    .as_object()
                    .is_none_or(|values| target_map_exceeds_scope(values, caller.devices))
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
        let denied = match value {
            Value::Array(values) => values
                .iter()
                .any(|value| self.request_exceeds_scope(value, caller)),
            value => self.request_exceeds_scope(&value, caller),
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
    token_store: Option<Arc<TokenStoreFile<MistGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
) -> Result<Router> {
    let body_limit = limits.max_request_body_bytes;
    let identity =
        TransportIdentity::new("rustmistmcp", "mist", "rustmistmcp", ["org_id", "site_id"]);
    let mut config = HttpTransportConfig::new(
        identity,
        limits,
        HostOriginPolicy::enforced(allowed_hosts, allowed_origins),
    )
    .with_metrics(enable_metrics);

    if let Some(store_file) = token_store {
        let auth_store = store_file.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_store.store();
            snapshot.authenticate(candidate).map(CallerCtx::from)
        });
        let boundary = BearerBoundary::new(
            authenticator,
            BearerResponseProfile::detailed("rustmistmcp"),
            body_limit,
        )
        .with_preflight(MistScopePreflight::new(RESTRICTED_TOOLS));
        config = config.with_bearer(boundary);
    }

    build_streamable_http_router(move || Ok::<_, std::io::Error>(handler.clone()), config)
        .context("building shared Mist Streamable HTTP router")
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
/// The pinned shared listener cannot yet consume a shutdown coordinator and
/// does not provide graceful HTTP drain/SIGTERM composition (`mecmcp#156`).
///
/// # Errors
///
/// Returns router construction, bind, or serving failures.
#[allow(clippy::too_many_arguments)]
pub async fn serve_http(
    handler: MistHandler,
    address: SocketAddr,
    token_store: Option<Arc<TokenStoreFile<MistGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let router = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
    )?;
    serve_router(router, address, tls)
        .await
        .context("serving Mist Streamable HTTP")
}
