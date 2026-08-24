//! Curated read-only Mist MCP handler.

mod change_set;
mod wan;
mod wan_write;

use std::{collections::BTreeMap, sync::Arc};

use mecmcp_auth::CallerCtx;
use mecmcp_server::{
    ResultFormat, ResultLimits, audit_scope, authorize_call, caller_from_extensions,
    filter_tools_for_scope, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustmistmcp_core::{
    BlockedMistClient, Catalog, MAX_ENCODED_CURSOR_BYTES, MistClient, MistError, MistGrant,
    MistRequest, MistResponseBody, MistTarget,
    catalog::{MistCapability, MistOperation, TargetSelector},
    validate_mist_endpoint,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use url::Url;

/// Exact MCP tool registry used for token validation and drift tests.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_mist_change_set",
    "approve_mist_change_set",
    "get_mist_change_set",
    "get_mist_device",
    "get_mist_device_stats",
    "get_mist_insight",
    "get_mist_operation_schema",
    "get_mist_org",
    "get_mist_rrm",
    "get_mist_self",
    "get_mist_site",
    "get_mist_sle",
    "get_mist_sle_impact",
    "get_mist_wan_config",
    "get_mist_wan_edge_stats",
    "invoke_mist_privileged_read",
    "invoke_mist_read",
    "list_mist_applications",
    "list_mist_orgs",
    "list_mist_rogues",
    "list_mist_sites",
    "list_mist_sle_metrics",
    "list_mist_upgrades",
    "list_mist_wan_config",
    "list_mist_wan_edges",
    "list_mist_wlans",
    "plan_mist_change",
    "search_mist_alarms",
    "search_mist_audit_logs",
    "search_mist_bgp_peers",
    "search_mist_clients",
    "search_mist_events",
    "search_mist_inventory",
    "search_mist_operations",
    "search_mist_peer_paths",
    "search_mist_service_path_events",
    "search_mist_tunnels",
    "troubleshoot_mist",
];

/// Privileged reads excluded from wildcard tool scope.
pub const RESTRICTED_TOOLS: &[&str] = &[
    "apply_mist_change_set",
    "approve_mist_change_set",
    "get_mist_change_set",
    "get_mist_device",
    "get_mist_self",
    "get_mist_wan_config",
    "invoke_mist_privileged_read",
    "list_mist_wan_config",
    "list_mist_wlans",
    "plan_mist_change",
    "search_mist_audit_logs",
];

const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

fn audited_tool_result<T, E>(
    audit: &mut mecmcp_audit::AuditScope,
    result: Result<T, E>,
) -> CallToolResult
where
    T: Serialize,
    E: std::fmt::Display,
{
    let domain_error = result.as_ref().err().map(ToString::to_string);
    let output = tool_result(result, ResultFormat::PrettyJson, RESULT_LIMITS);
    if output.is_error == Some(true) {
        audit.fail(domain_error.unwrap_or_else(|| {
            "successful domain result failed bounded MCP result conversion".to_owned()
        }));
    } else {
        audit.succeed();
    }
    output
}

type PathValues = BTreeMap<String, String>;
type QueryValues = BTreeMap<String, serde_json::Value>;
type NamedMaps = (PathValues, QueryValues);

struct CatalogRead {
    tool: &'static str,
    operation_id: String,
    path: PathValues,
    query: QueryValues,
    cursor: Option<rustmistmcp_core::MistCursor>,
    capability: MistCapability,
}

/// Failure to construct the immutable Mist handler.
#[derive(Debug, thiserror::Error)]
pub enum MistServerError {
    /// The configured endpoint is not an HTTPS origin.
    #[error("invalid Mist handler endpoint")]
    InvalidEndpoint,
    /// An allowlisted organization is not a canonical UUID.
    #[error("invalid Mist organization allowlist")]
    InvalidOrganization,
    /// The embedded catalog failed its integrity checks.
    #[error("invalid embedded Mist catalog: {0}")]
    Catalog(#[from] rustmistmcp_core::catalog::CatalogError),
    /// Failed to load credential from file.
    #[error("credential load failed: {0}")]
    CredentialLoad(String),
    /// Failed to construct HTTP client.
    #[error("HTTP client construction failed: {0}")]
    ClientConstruction(String),
    /// Failed to load change-set lifecycle state.
    #[error("change-set state load failed: {0}")]
    ChangeSetState(String),
}

/// Mist MCP handler with catalogued reads and change-set-gated writes.
///
/// Serves read-only Mist tools and mutating tools gated through the
/// plan → approve → apply → verify change-set lifecycle. Write tools do not
/// exist yet, but the coordinator is mounted to prepare for them.
#[derive(Clone)]
pub struct MistHandler {
    #[allow(dead_code)]
    origin: Url,
    #[allow(dead_code)]
    allowed_orgs: Arc<[String]>,
    /// Immutable site inventory discovered during startup, keyed by site UUID.
    sites: Arc<BTreeMap<String, String>>,
    #[allow(dead_code)]
    catalog: Arc<Catalog>,
    client: Arc<dyn MistClient>,
    /// Change-set lifecycle state for gated writes.
    #[allow(dead_code)]
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// SSDF evidence recorder, when the pipeline is configured.
    ///
    /// Held here rather than reached through the coordinator, because mecmcp
    /// emits the four records from its *lifecycle* APIs -- `create_change_set`,
    /// `approve_change_set`, `commit_operation` -- and this server drives the
    /// coordinator through `insert_change_set` / `update_change_set` instead.
    /// Attaching a recorder to the coordinator alone produces nothing at all
    /// here, so the emission points are ours to place.
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    /// Whether lab mode is enabled (auto-waive on creation).
    lab_mode: bool,
    tool_router: ToolRouter<Self>,
}

/// Default change-set limits for this consumer.
///
/// A Mist change set holds one action over one object, so the per-set ceilings
/// are deliberately small; the store ceiling is what bounds a runaway client.
fn change_set_limits() -> mecmcp_changeset::OperationLimits {
    mecmcp_changeset::OperationLimits {
        max_operations: 64,
        max_change_sets: 64,
        max_actions_per_set: 1,
        max_change_set_bytes: 256 * 1024,
        max_state_bytes: 4 * 1024 * 1024,
        max_targets_per_set: 1,
        max_preview_bytes: 128 * 1024,
    }
}

/// Load the coordinator for a handler.
///
/// `None` keeps state in memory, which is what tests want. Production passes
/// `/var/lib/rustmistmcp/changeset-state.json`, the path packaging reserves.
fn load_coordinator(
    path: Option<&std::path::Path>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
) -> Result<Arc<mecmcp_changeset::ChangesetCoordinator>, MistServerError> {
    let mut coordinator = mecmcp_changeset::ChangesetCoordinator::load(
        path,
        change_set_limits(),
        std::time::Duration::from_secs(3600),
        lab_mode,
    )
    .map_err(|error| MistServerError::ChangeSetState(error.to_string()))?;
    if let Some(recorder) = evidence {
        coordinator = coordinator.with_evidence(recorder);
    }
    Ok(Arc::new(coordinator))
}

impl MistHandler {
    /// Construct the no-network default handler used when no credential is available.
    ///
    /// No credential is read and no socket is opened.
    pub fn blocked(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
    ) -> Result<Self, MistServerError> {
        Self::with_client(endpoint, allowed_orgs, sites, Arc::new(BlockedMistClient))
    }
    /// The transport this handler will actually use.
    ///
    /// Exposed so a test can assert which client the *production* constructor
    /// built. A test that constructs the handler itself cannot see the wiring
    /// at all — which is how `from_config` shipped returning the stub.
    #[must_use]
    pub fn client(&self) -> &Arc<dyn MistClient> {
        &self.client
    }

    /// Construct a production handler with real HTTPS client.
    ///
    /// Loads the credential from the config's credential_file and constructs
    /// an HttpMistClient with mecmcp-http.
    ///
    /// # Errors
    ///
    /// Returns errors for invalid config, credential load failure, or client
    /// construction failure.
    pub fn from_config(
        config: &rustmistmcp_core::MistConfig,
        sites: BTreeMap<String, String>,
    ) -> Result<Self, MistServerError> {
        Self::from_config_with_lab_mode(config, sites, false, None)
    }

    /// Construct a production handler with optional lab mode.
    ///
    /// When `lab_mode` is true, change sets are waived on creation with no
    /// second-principal approval required.
    ///
    /// # Errors
    ///
    /// Returns errors for invalid config, credential load failure, or client
    /// construction failure.
    pub fn from_config_with_lab_mode(
        config: &rustmistmcp_core::MistConfig,
        sites: BTreeMap<String, String>,
        lab_mode: bool,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    ) -> Result<Self, MistServerError> {
        // Load credential using mecmcp-secret (enforces mode 0600)
        let credential = mecmcp_secret::load_from_file(
            &config.credential_file,
            mecmcp_secret::SecretLimits::default(),
        )
        .map_err(|error| MistServerError::CredentialLoad(error.to_string()))?;

        // Build HttpMistClient
        let catalog = Arc::new(rustmistmcp_core::Catalog::embedded()?);
        let http_client = rustmistmcp_core::HttpMistClient::new(
            &config.endpoint,
            credential.expose().to_owned(),
            catalog.clone(),
            rustmistmcp_core::HttpMistClientConfig::default(),
        )
        .map_err(|error| MistServerError::ClientConstruction(error.to_string()))?;

        // Load change-set coordinator with production path
        let coordinator = load_coordinator(
            Some(std::path::Path::new(
                "/var/lib/rustmistmcp/changeset-state.json",
            )),
            lab_mode,
            evidence.clone(),
        )?;

        let origin = validate_mist_endpoint(&config.endpoint)
            .map_err(|_| MistServerError::InvalidEndpoint)?;
        let allowed_orgs = &config.allowed_orgs;
        if allowed_orgs.is_empty()
            || allowed_orgs.len() > 256
            || allowed_orgs
                .iter()
                .any(|org_id| MistTarget::org(org_id).is_err())
            || allowed_orgs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != allowed_orgs.len()
        {
            return Err(MistServerError::InvalidOrganization);
        }
        if sites.len() > 4096
            || sites.iter().any(|(site_id, org_id)| {
                MistTarget::site(site_id).is_err()
                    || MistTarget::org(org_id).is_err()
                    || !allowed_orgs.iter().any(|allowed| allowed == org_id)
            })
        {
            return Err(MistServerError::InvalidOrganization);
        }
        Ok(Self {
            origin,
            allowed_orgs: allowed_orgs.clone().into(),
            sites: Arc::new(sites),
            catalog,
            client: Arc::new(http_client),
            coordinator,
            evidence,
            lab_mode,
            tool_router: Self::mist_tool_router(),
        })
    }

    /// Construct a handler around an injected Mist client.
    pub fn with_client(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
        client: Arc<dyn MistClient>,
    ) -> Result<Self, MistServerError> {
        Self::with_client_options(endpoint, allowed_orgs, sites, client, None, false)
    }

    /// Same as [`Self::with_client`], but lets a caller pick the change-set
    /// state file and enable lab mode.
    ///
    /// Exists so tests can exercise the `--lab-mode` waive path and prove the
    /// resulting record survives a save/reload cycle. `state_path` of `None`
    /// keeps state in memory, which is what most tests want.
    pub fn with_client_options(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
        client: Arc<dyn MistClient>,
        state_path: Option<&std::path::Path>,
        lab_mode: bool,
    ) -> Result<Self, MistServerError> {
        let origin =
            validate_mist_endpoint(endpoint).map_err(|_| MistServerError::InvalidEndpoint)?;
        if allowed_orgs.is_empty()
            || allowed_orgs.len() > 256
            || allowed_orgs
                .iter()
                .any(|org_id| MistTarget::org(org_id).is_err())
            || allowed_orgs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != allowed_orgs.len()
        {
            return Err(MistServerError::InvalidOrganization);
        }
        if sites.len() > 4096
            || sites.iter().any(|(site_id, org_id)| {
                MistTarget::site(site_id).is_err()
                    || MistTarget::org(org_id).is_err()
                    || !allowed_orgs.iter().any(|allowed| allowed == org_id)
            })
        {
            return Err(MistServerError::InvalidOrganization);
        }
        Ok(Self {
            origin,
            allowed_orgs: allowed_orgs.into(),
            sites: Arc::new(sites),
            catalog: Arc::new(Catalog::embedded()?),
            client,
            coordinator: load_coordinator(state_path, lab_mode, None)?,
            evidence: None,
            lab_mode,
            tool_router: Self::mist_tool_router(),
        })
    }

    async fn dispatch_catalogued_read(
        &self,
        read: CatalogRead,
        extensions: &rmcp::model::Extensions,
    ) -> CallToolResult {
        let CatalogRead {
            tool,
            operation_id,
            path,
            query,
            cursor,
            capability: required_capability,
        } = read;
        let caller = caller_from_extensions::<MistGrant>(extensions);
        let operation = match self.catalog.operation(&operation_id) {
            Some(operation) => operation,
            None => {
                let mut audit = audit_scope(caller, tool, "read", Vec::new());
                let error = MistCallError::UnknownOperation;
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        };
        let target = match target_for(operation.target_selectors.as_slice(), &path) {
            Ok(target) => target,
            Err(error) => {
                let mut audit = audit_scope(caller, tool, "read", Vec::new());
                audit.deny("target");
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        };
        let targets = target
            .as_ref()
            .map(|target| vec![target.subject()])
            .unwrap_or_default();
        let mut audit = audit_scope(caller, tool, "read", targets);
        audit.meta("operation_id", operation_id.clone());

        if operation.method != "GET" || operation.capability != required_capability {
            let error = MistCallError::WrongCapability;
            audit.deny("capability");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        if caller.is_none() && operation.capability == MistCapability::PrivilegedRead {
            let error = MistCallError::Authorization(
                "privileged Mist reads require authenticated caller context".to_owned(),
            );
            audit.deny("caller");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        if let Err(error) = authorize_call(
            caller,
            tool,
            target.as_ref().map(|target| target.subject()).as_deref(),
            RESTRICTED_TOOLS,
        ) {
            audit.deny("scope");
            return tool_result::<ReadEnvelope, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        if let Err(error) =
            authorize_grant(caller, &operation_id, operation.capability, target.as_ref())
        {
            audit.deny("grant");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        if let Some(target) = &target {
            let configured = if target.to_string().starts_with("org/") {
                self.allowed_orgs.iter().any(|org| org == target.id())
            } else if target.to_string().starts_with("site/") {
                self.sites
                    .get(target.id())
                    .is_some_and(|org_id| self.allowed_orgs.iter().any(|org| org == org_id))
            } else {
                false
            };
            if !configured {
                let error = MistCallError::OrganizationNotConfigured;
                audit.deny("profile");
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        }
        if let Err(error) = validate_page_limit(&query) {
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }

        let request = MistRequest {
            operation_id,
            path,
            query,
            json: None,
            cursor,
        };
        let request = match request.validate(&self.catalog, &self.origin) {
            Ok(request) => request,
            Err(error) => {
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::Mist(error)),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        };
        let expected_operation_id = request.operation_id.clone();
        let request_path = request.path.clone();
        let request_query = request.query.clone();
        let response = match self.client.execute(request).await {
            Ok(response) => response,
            Err(error) => {
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::Mist(error)),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        };
        if response.operation_id != expected_operation_id {
            let error = MistError::InvalidResponse {
                operation_id: expected_operation_id,
                reason: "response operation does not match request operation".to_owned(),
            };
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(MistCallError::Mist(error)),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        let mut response = match response.validate(&self.catalog, &self.origin) {
            Ok(response) => response,
            Err(error) => {
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::Mist(error)),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        };
        if !(200..300).contains(&response.status) {
            let error = if response.status == 429 {
                MistError::RateLimited {
                    retry_after_secs: None,
                }
            } else {
                MistError::Service(format!("Mist API returned HTTP {}", response.status))
            };
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(MistCallError::Mist(error)),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        if let Some(cursor) = response.cursor.take() {
            response.cursor =
                match cursor.with_request_context(request_path, request_query, target.clone()) {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        audit.fail(&error);
                        return tool_result::<ReadEnvelope, _>(
                            Err(MistCallError::Mist(error)),
                            ResultFormat::PrettyJson,
                            RESULT_LIMITS,
                        );
                    }
                };
        }
        let envelope = ReadEnvelope::from_response(response, target.as_ref());
        audited_tool_result(&mut audit, Ok::<_, MistCallError>(envelope))
    }

    async fn dispatch_named<T: Serialize>(
        &self,
        tool: &'static str,
        operation_id: &'static str,
        args: T,
        path_names: &[&str],
        capability: MistCapability,
        extensions: &rmcp::model::Extensions,
    ) -> CallToolResult {
        let (path, query) = match named_maps(args, path_names) {
            Ok(values) => values,
            Err(error) => {
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                );
            }
        };
        self.dispatch_catalogued_read(
            CatalogRead {
                tool,
                operation_id: operation_id.to_owned(),
                path,
                query,
                cursor: None,
                capability,
            },
            extensions,
        )
        .await
    }

    async fn invoke_dispatcher(
        &self,
        tool: &'static str,
        args: InvokeReadArgs,
        capability: MistCapability,
        extensions: &rmcp::model::Extensions,
    ) -> CallToolResult {
        if args.cursor.is_some() && (args.path.is_some() || args.query.is_some()) {
            let error = MistCallError::Mist(MistError::InvalidCursor(
                "cursor cannot be combined with path or query".to_owned(),
            ));
            let mut audit = audit_scope(
                caller_from_extensions::<MistGrant>(extensions),
                tool,
                "read",
                Vec::new(),
            );
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }
        let (path, query, cursor) = match args.cursor {
            Some(encoded) => {
                let malformed = encoded.is_empty()
                    || encoded.len() > MAX_ENCODED_CURSOR_BYTES
                    || encoded.len() % 2 != 0
                    || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit());
                let decoded = if malformed {
                    None
                } else {
                    hex::decode(encoded)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                };
                let Some(cursor): Option<rustmistmcp_core::MistCursor> = decoded else {
                    let error = MistCallError::Mist(MistError::InvalidCursor(
                        "opaque cursor is malformed".to_owned(),
                    ));
                    let mut audit = audit_scope(
                        caller_from_extensions::<MistGrant>(extensions),
                        tool,
                        "read",
                        Vec::new(),
                    );
                    audit.fail(&error);
                    return tool_result::<ReadEnvelope, _>(
                        Err(error),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    );
                };
                let Some((path, query, stored_target)) = cursor.request_context() else {
                    let error = MistCallError::Mist(MistError::InvalidCursor(
                        "opaque cursor has no request context".to_owned(),
                    ));
                    let mut audit = audit_scope(
                        caller_from_extensions::<MistGrant>(extensions),
                        tool,
                        "read",
                        Vec::new(),
                    );
                    audit.fail(&error);
                    return tool_result::<ReadEnvelope, _>(
                        Err(error),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    );
                };
                let path = path.clone();
                let query = query.clone();
                let operation = self.catalog.operation(&args.operation_id);
                let derived_target = operation
                    .and_then(|operation| {
                        target_for(operation.target_selectors.as_slice(), &path).ok()
                    })
                    .flatten();
                if derived_target.as_ref() != stored_target {
                    let error = MistCallError::Mist(MistError::InvalidCursor(
                        "cursor target does not match its request context".to_owned(),
                    ));
                    let mut audit = audit_scope(
                        caller_from_extensions::<MistGrant>(extensions),
                        tool,
                        "read",
                        Vec::new(),
                    );
                    audit.fail(&error);
                    return tool_result::<ReadEnvelope, _>(
                        Err(error),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    );
                }
                (path, query, Some(cursor))
            }
            None => (
                args.path.unwrap_or_default(),
                args.query.unwrap_or_default(),
                None,
            ),
        };
        self.dispatch_catalogued_read(
            CatalogRead {
                tool,
                operation_id: args.operation_id,
                path,
                query,
                cursor,
                capability,
            },
            extensions,
        )
        .await
    }

    fn operation_visible(
        &self,
        caller: Option<&CallerCtx<MistGrant>>,
        operation: &MistOperation,
    ) -> bool {
        let dispatcher = match operation.capability {
            MistCapability::OrdinaryRead => "invoke_mist_read",
            MistCapability::PrivilegedRead => "invoke_mist_privileged_read",
            _ => return false,
        };
        if operation.target_selectors.contains(&TargetSelector::Msp) {
            return false;
        }
        let Some(caller) = caller else {
            return operation.capability == MistCapability::OrdinaryRead;
        };
        if !caller.tools.allows_tool(dispatcher, RESTRICTED_TOOLS) {
            return false;
        }
        let grant = caller.grant.as_ref();
        if operation.capability == MistCapability::PrivilegedRead && grant.is_none() {
            return false;
        }
        if grant.is_some_and(|grant| {
            !grant.allows_operation(&operation.operation_id)
                || !grant.actions.contains(&operation.capability)
        }) {
            return false;
        }
        operation
            .target_selectors
            .iter()
            .all(|selector| match selector {
                TargetSelector::None => true,
                TargetSelector::Org => self.allowed_orgs.iter().any(|org_id| {
                    let target = MistTarget::org(org_id).expect("validated organization");
                    caller.devices.allows(&target.subject())
                        && grant.is_none_or(|grant| grant.allows_target(&target))
                }),
                TargetSelector::Site => self.sites.iter().any(|(site_id, org_id)| {
                    self.allowed_orgs.iter().any(|allowed| allowed == org_id)
                        && MistTarget::site(site_id).is_ok_and(|target| {
                            caller.devices.allows(&target.subject())
                                && grant.is_none_or(|grant| grant.allows_target(&target))
                        })
                }),
                TargetSelector::Msp => false,
            })
    }
}

#[derive(Debug, thiserror::Error)]
enum MistCallError {
    #[error("unknown or unauthorized Mist operation")]
    UnknownOperation,
    #[error("operation is not permitted by this read dispatcher")]
    WrongCapability,
    #[error("{0}")]
    Authorization(String),
    #[error("the authenticated caller lacks the exact Mist operation/action/target grant")]
    Grant,
    #[error("MSP targets are not supported by the v1 authorization model")]
    MspTarget,
    #[error("the catalogued target is missing or malformed")]
    InvalidTarget,
    #[error("the organization is not configured or authorized")]
    OrganizationNotConfigured,
    #[error("query limit must be an integer from 1 through 100")]
    InvalidLimit,
    #[error("catalog search requires a 1-128 byte query and a result limit from 1 through 50")]
    InvalidSearch,
    #[error("exactly one of org_id or site_id is required")]
    AmbiguousScope,
    #[error(transparent)]
    Mist(#[from] MistError),
}

#[derive(serde::Serialize)]
struct ReadEnvelope {
    operation_id: String,
    target: Option<String>,
    status: u16,
    content_type: &'static str,
    data: serde_json::Value,
    next_cursor: Option<String>,
    truncated: bool,
}

#[derive(Serialize)]
struct LocalOrgView {
    source: &'static str,
    organizations: Vec<LocalOrg>,
}

#[derive(Serialize)]
struct LocalOrg {
    id: String,
    target: String,
}

impl ReadEnvelope {
    fn from_response(
        response: rustmistmcp_core::MistResponse,
        target: Option<&MistTarget>,
    ) -> Self {
        let (content_type, data) = match response.body {
            MistResponseBody::Json(value) => ("application/json", value),
            MistResponseBody::Text(value) => ("text/plain; charset=utf-8", value.into()),
            MistResponseBody::Binary(value) => (
                "application/octet-stream",
                serde_json::Value::Array(value.into_iter().map(serde_json::Value::from).collect()),
            ),
            MistResponseBody::Empty => ("application/octet-stream", serde_json::Value::Null),
        };
        let next_cursor = response
            .cursor
            .and_then(|cursor| serde_json::to_vec(&cursor).ok().map(hex::encode));
        Self {
            operation_id: response.operation_id,
            target: target.map(MistTarget::subject),
            status: response.status,
            content_type,
            data,
            next_cursor,
            truncated: false,
        }
    }
}

fn target_for(
    selectors: &[TargetSelector],
    path: &BTreeMap<String, String>,
) -> Result<Option<MistTarget>, MistCallError> {
    match selectors {
        [TargetSelector::None] => Ok(None),
        [TargetSelector::Org] => path
            .get("org_id")
            .ok_or(MistCallError::InvalidTarget)
            .and_then(|id| MistTarget::org(id).map_err(|_| MistCallError::InvalidTarget))
            .map(Some),
        [TargetSelector::Site] => path
            .get("site_id")
            .ok_or(MistCallError::InvalidTarget)
            .and_then(|id| MistTarget::site(id).map_err(|_| MistCallError::InvalidTarget))
            .map(Some),
        selectors if selectors.contains(&TargetSelector::Msp) => Err(MistCallError::MspTarget),
        _ => Err(MistCallError::InvalidTarget),
    }
}

fn authorize_grant(
    caller: Option<&CallerCtx<MistGrant>>,
    operation_id: &str,
    action: MistCapability,
    target: Option<&MistTarget>,
) -> Result<(), MistCallError> {
    let Some(caller) = caller else {
        return if action == MistCapability::OrdinaryRead {
            Ok(())
        } else {
            Err(MistCallError::Grant)
        };
    };
    let Some(grant) = &caller.grant else {
        return if action == MistCapability::OrdinaryRead {
            Ok(())
        } else {
            Err(MistCallError::Grant)
        };
    };
    if !grant.allows_operation(operation_id)
        || !grant.actions.contains(&action)
        || target.is_some_and(|target| !grant.allows_target(target))
    {
        return Err(MistCallError::Grant);
    }
    Ok(())
}

fn validate_page_limit(query: &BTreeMap<String, serde_json::Value>) -> Result<(), MistCallError> {
    let Some(limit) = query.get("limit") else {
        return Ok(());
    };
    if limit
        .as_u64()
        .is_some_and(|limit| (1..=100).contains(&limit))
    {
        Ok(())
    } else {
        Err(MistCallError::InvalidLimit)
    }
}

fn named_maps<T: Serialize>(args: T, path_names: &[&str]) -> Result<NamedMaps, MistCallError> {
    let object = serde_json::to_value(args)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(MistCallError::InvalidTarget)?;
    let mut path = BTreeMap::new();
    let mut query = BTreeMap::new();
    for (name, value) in object {
        if value.is_null() {
            continue;
        }
        if path_names.contains(&name.as_str()) {
            let value = value.as_str().ok_or(MistCallError::InvalidTarget)?;
            path.insert(name, value.to_owned());
        } else {
            query.insert(name, value);
        }
    }
    Ok((path, query))
}

#[derive(Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct GetOrgArgs {
    /// Organization UUID.
    org_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InvokeReadArgs {
    /// Exact catalog operation ID.
    operation_id: String,
    /// Catalogued path parameters.
    #[serde(default)]
    path: Option<BTreeMap<String, String>>,
    /// Catalogued query parameters.
    #[serde(default)]
    query: Option<BTreeMap<String, serde_json::Value>>,
    /// Opaque operation-bound continuation.
    #[serde(default)]
    #[schemars(length(min = 2, max = 262_144))]
    cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SearchCapability {
    OrdinaryRead,
    PrivilegedRead,
}

impl From<SearchCapability> for MistCapability {
    fn from(value: SearchCapability) -> Self {
        match value {
            SearchCapability::OrdinaryRead => Self::OrdinaryRead,
            SearchCapability::PrivilegedRead => Self::PrivilegedRead,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SearchTarget {
    None,
    Org,
    Site,
    Msp,
}

impl From<SearchTarget> for TargetSelector {
    fn from(value: SearchTarget) -> Self {
        match value {
            SearchTarget::None => Self::None,
            SearchTarget::Org => Self::Org,
            SearchTarget::Site => Self::Site,
            SearchTarget::Msp => Self::Msp,
        }
    }
}

/// Whether a stats tool returns records or a count distribution.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum StatsModeArg {
    /// Return matching records.
    #[default]
    Records,
    /// Return a count distribution. The response shape differs from records.
    Count,
}

impl From<StatsModeArg> for wan::StatsMode {
    fn from(value: StatsModeArg) -> Self {
        match value {
            StatsModeArg::Records => Self::Records,
            StatsModeArg::Count => Self::Count,
        }
    }
}

/// Which SLE impact view a caller wants.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SleImpactArg {
    /// Gateways impacted by the metric.
    Gateways,
    /// Applications impacted by the metric.
    Applications,
    /// Aggregate impact summary.
    Summary,
}

impl From<SleImpactArg> for wan::SleImpact {
    fn from(value: SleImpactArg) -> Self {
        match value {
            SleImpactArg::Gateways => Self::Gateways,
            SleImpactArg::Applications => Self::Applications,
            SleImpactArg::Summary => Self::Summary,
        }
    }
}

/// Where a caller wants the application list from.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum AppSourceArg {
    /// Applications observed at a site. Requires `site_id`.
    Site,
    /// The constant gateway application catalog. Takes no scope.
    Catalog,
}

impl From<AppSourceArg> for wan::AppSource {
    fn from(value: AppSourceArg) -> Self {
        match value {
            AppSourceArg::Site => Self::Site,
            AppSourceArg::Catalog => Self::Catalog,
        }
    }
}

/// A WAN edge configuration object type.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WanObjectArg {
    /// A LAN segment / network.
    Network,
    /// An application or service definition.
    Service,
    /// A service (SD-WAN steering) policy.
    ServicePolicy,
    /// A gateway template.
    GatewayTemplate,
    /// A device profile. Org scope only.
    DeviceProfile,
}

impl From<WanObjectArg> for wan::WanObject {
    fn from(value: WanObjectArg) -> Self {
        match value {
            WanObjectArg::Network => Self::Network,
            WanObjectArg::Service => Self::Service,
            WanObjectArg::ServicePolicy => Self::ServicePolicy,
            WanObjectArg::GatewayTemplate => Self::GatewayTemplate,
            WanObjectArg::DeviceProfile => Self::DeviceProfile,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchOperationsArgs {
    #[schemars(length(min = 1, max = 128))]
    query: String,
    capability: Option<SearchCapability>,
    target: Option<SearchTarget>,
    #[schemars(range(min = 1, max = 50))]
    limit: Option<u8>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationSchemaArgs {
    operation_id: String,
}

#[derive(Serialize)]
struct OperationSummary<'a> {
    operation_id: &'a str,
    summary: &'a str,
    method: &'a str,
    path: &'a str,
    capability: MistCapability,
    target_selectors: &'a [TargetSelector],
    pagination: rustmistmcp_core::PaginationMode,
}

macro_rules! read_args {
    ($name:ident { $($(#[$meta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Deserialize, JsonSchema, Serialize)]
        #[serde(deny_unknown_fields)]
        struct $name {
            $(
                $(#[$meta])*
                $field: $ty,
            )*
        }
    };
}

/// Which write a change set performs.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WriteVerbArg {
    /// Create a new object.
    Create,
    /// Update an existing object.
    Update,
}

impl From<WriteVerbArg> for wan_write::WriteVerb {
    fn from(value: WriteVerbArg) -> Self {
        match value {
            WriteVerbArg::Create => Self::Create,
            WriteVerbArg::Update => Self::Update,
        }
    }
}

read_args!(PlanChangeArgs {
    /// Which configuration object type to change. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Create or update. Not sent to Mist.
    #[serde(skip_serializing)]
    verb: WriteVerbArg,
    /// Organization UUID.
    org_id: String,
    /// The object's UUID. Required for `update`, omitted for `create`.
    #[serde(skip_serializing)]
    object_id: Option<String>,
    /// Fields to change. Merged onto the object's current state: arrays
    /// replace wholesale, and a null value deletes the field.
    #[serde(skip_serializing)]
    patch: serde_json::Value,
});

read_args!(GetChangeSetArgs {
    /// Change-set identifier (64 hex characters).
    change_set_id: String,
    /// Which configuration object type. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// The object's UUID. Required for update change sets.
    #[serde(skip_serializing)]
    object_id: Option<String>,
});

read_args!(ApproveChangeSetArgs {
    /// Change-set identifier (64 hex characters).
    change_set_id: String,
    /// Which configuration object type. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// The object's UUID. Required for update change sets.
    #[serde(skip_serializing)]
    object_id: Option<String>,
});

read_args!(ApplyChangeSetArgs {
    /// Change-set identifier (64 hex characters).
    change_set_id: String,
    /// Which configuration object type. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// The object's UUID. Required for update change sets.
    #[serde(skip_serializing)]
    object_id: Option<String>,
});

read_args!(OrgPageArgs {
    org_id: String,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    #[schemars(range(min = 1))]
    page: Option<u32>,
});
read_args!(SiteArgs { site_id: String });
read_args!(InventoryArgs {
    org_id: String, #[schemars(range(min = 1, max = 100))] limit: Option<u32>, mac: Option<String>, magic: Option<String>,
    master: Option<String>, model: Option<String>, name: Option<String>,
    search_after: Option<String>, serial: Option<String>, site_id: Option<String>,
    sku: Option<String>, sort: Option<String>, status: Option<String>, text: Option<String>,
    #[serde(rename = "type")] r#type: Option<String>, version: Option<String>,
});
read_args!(SiteDeviceArgs {
    site_id: String,
    device_id: String
});
read_args!(DeviceStatsArgs {
    site_id: String, device_id: String, fields: Option<String>,
});
read_args!(SitePageArgs {
    site_id: String,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    #[schemars(range(min = 1))] page: Option<u32>,
});
read_args!(ClientSearchArgs {
    site_id: String, ap: Option<String>, band: Option<String>, device: Option<String>,
    duration: Option<String>, end: Option<String>, hostname: Option<String>, ip: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>, mac: Option<String>, model: Option<String>, os: Option<String>,
    psk_id: Option<String>, psk_name: Option<String>, search_after: Option<String>,
    sort: Option<String>, ssid: Option<String>, start: Option<String>, text: Option<String>,
    username: Option<String>, vlan: Option<String>,
});
read_args!(EventSearchArgs {
    site_id: String, duration: Option<String>, end: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    search_after: Option<String>, sort: Option<String>, start: Option<String>,
    #[serde(rename = "type")] r#type: Option<String>,
});
read_args!(AlarmSearchArgs {
    site_id: String, ack_admin_name: Option<String>, acked: Option<bool>,
    duration: Option<String>, end: Option<String>, group: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    search_after: Option<String>, severity: Option<String>, sort: Option<String>,
    start: Option<String>, #[serde(rename = "type")] r#type: Option<String>,
});
read_args!(AuditSearchArgs {
    org_id: String, admin_name: Option<String>, duration: Option<String>, end: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>, message: Option<String>,
    #[schemars(range(min = 1))] page: Option<u32>, site_id: Option<String>,
    sort: Option<String>, start: Option<String>,
});
read_args!(SleMetricsArgs {
    site_id: String,
    scope: String,
    scope_id: String,
});
read_args!(SleArgs {
    site_id: String, scope: String, scope_id: String, metric: String,
    duration: Option<String>, end: Option<String>, start: Option<String>,
});
read_args!(SleImpactArgs {
    /// Site UUID.
    site_id: String,
    /// SLE scope, e.g. `site`.
    scope: String,
    /// Identifier for the chosen scope.
    scope_id: String,
    /// SLE metric name.
    metric: String,
    /// Which impact view to return. Not sent to Mist.
    #[serde(skip_serializing)]
    impact: SleImpactArg,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
});
read_args!(InsightArgs {
    site_id: String, metrics: String, duration: Option<String>, end: Option<String>,
    interval: Option<String>, #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    #[schemars(range(min = 1))] page: Option<u32>, start: Option<String>,
});
read_args!(TroubleshootArgs {
    site_id: String, ap: Option<String>, app: Option<String>, duration: Option<String>,
    end: Option<String>, #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    mac: Option<String>, meeting_id: Option<String>,
    #[schemars(range(min = 1))] page: Option<u32>, start: Option<String>, wired: Option<bool>,
});
read_args!(RogueArgs {
    site_id: String, duration: Option<String>, end: Option<String>, interval: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>, start: Option<String>,
    #[serde(rename = "type")] r#type: Option<String>,
});
read_args!(UpgradeArgs { site_id: String, status: Option<String> });

/// The device type this tool is permitted to enumerate.
fn gateway_device_type() -> String {
    "gateway".to_owned()
}

read_args!(WanEdgeListArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    hostname: Option<String>,
    mac: Option<String>,
    model: Option<String>,
    version: Option<String>,
    /// Always `gateway`. Not caller-settable: this tool must not enumerate
    /// APs or switches.
    #[serde(rename = "type", skip_deserializing, default = "gateway_device_type")]
    #[schemars(skip)]
    r#type: String,
});

read_args!(WanEdgeStatsArgs {
    /// Site UUID.
    site_id: String,
    /// Gateway device UUID. When present, returns per-device insight metrics.
    device_id: Option<String>,
    /// Metrics to retrieve. Required when `device_id` is present.
    metrics: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
});

read_args!(TunnelSearchArgs {
    /// Organization UUID.
    org_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(PeerPathSearchArgs {
    /// Organization UUID.
    org_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(BgpPeerSearchArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(ServicePathEventArgs {
    /// Site UUID.
    site_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(ApplicationListArgs {
    /// Where to read applications from. Not sent to Mist.
    #[serde(skip_serializing)]
    source: AppSourceArg,
    /// Site UUID. Required when `source` is `site`.
    site_id: Option<String>,
    /// Records or count distribution. Ignored for the constant catalog.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    distinct: Option<String>,
});

read_args!(WanConfigListArgs {
    /// Which configuration object type to list. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID for the derived listing. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    #[schemars(range(min = 1))]
    page: Option<u32>,
});

read_args!(WanConfigGetArgs {
    /// Which configuration object type to read. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Organization UUID.
    org_id: String,
    /// The object's own UUID. Not sent to Mist under this name.
    #[serde(skip_serializing)]
    object_id: String,
});

#[tool_router(router = mist_tool_router, vis = "pub(crate)")]
impl MistHandler {
    #[tool(name = "get_mist_device", description = "Get one site device.")]
    async fn get_mist_device(
        &self,
        Parameters(args): Parameters<SiteDeviceArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_device",
                "getSiteDevice",
                args,
                &["site_id", "device_id"],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_device_stats",
        description = "Get one site device's statistics."
    )]
    async fn get_mist_device_stats(
        &self,
        Parameters(args): Parameters<DeviceStatsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_device_stats",
                "getSiteDeviceStats",
                args,
                &["site_id", "device_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "get_mist_insight", description = "Get site insight metrics.")]
    async fn get_mist_insight(
        &self,
        Parameters(args): Parameters<InsightArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_insight",
                "getSiteInsightMetrics",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_operation_schema",
        description = "Get locally catalogued Mist operation metadata."
    )]
    async fn get_mist_operation_schema(
        &self,
        Parameters(args): Parameters<OperationSchemaArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_mist_operation_schema",
            "read_local",
            Vec::new(),
        );
        if let Err(error) =
            authorize_call(caller, "get_mist_operation_schema", None, RESTRICTED_TOOLS)
        {
            audit.deny("scope");
            return Ok(tool_result::<&MistOperation, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }
        let operation = self
            .catalog
            .operation(&args.operation_id)
            .filter(|operation| self.operation_visible(caller, operation));
        match operation {
            Some(operation) => Ok(audited_tool_result(
                &mut audit,
                Ok::<_, MistCallError>(operation),
            )),
            None => {
                audit.deny("visibility");
                Ok(tool_result::<&MistOperation, _>(
                    Err(MistCallError::UnknownOperation),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ))
            }
        }
    }
    #[tool(name = "get_mist_org", description = "Get one Mist organization.")]
    async fn get_mist_org(
        &self,
        Parameters(args): Parameters<GetOrgArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "get_mist_org",
                    operation_id: "getOrg".to_owned(),
                    path: BTreeMap::from([("org_id".to_owned(), args.org_id)]),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                },
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_rrm",
        description = "Get current site channel planning."
    )]
    async fn get_mist_rrm(
        &self,
        Parameters(args): Parameters<SiteArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_rrm",
                "getSiteCurrentChannelPlanning",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_self",
        description = "Get the privileged Mist caller profile."
    )]
    async fn get_mist_self(
        &self,
        Parameters(args): Parameters<EmptyArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_self",
                "getSelf",
                args,
                &[],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "get_mist_site", description = "Get one Mist site.")]
    async fn get_mist_site(
        &self,
        Parameters(args): Parameters<SiteArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_site",
                "getSiteInfo",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "get_mist_sle", description = "Get one site SLE summary.")]
    async fn get_mist_sle(
        &self,
        Parameters(args): Parameters<SleArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_sle",
                "getSiteSleSummary",
                args,
                &["site_id", "scope", "scope_id", "metric"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_sle_impact",
        description = "Get gateways, applications, or the summary impacted by one site SLE metric."
    )]
    async fn get_mist_sle_impact(
        &self,
        Parameters(args): Parameters<SleImpactArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::sle_impact(args.impact.into());
        Ok(self
            .dispatch_named(
                "get_mist_sle_impact",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_wan_config",
        description = "Get one WAN edge configuration object by ID."
    )]
    async fn get_mist_wan_config(
        &self,
        Parameters(args): Parameters<WanConfigGetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let object: wan::WanObject = args.object.into();
        let resolved = wan::get_config(object);
        let path = BTreeMap::from([
            ("org_id".to_owned(), args.org_id),
            (wan::object_id_name(object).to_owned(), args.object_id),
        ]);
        // Gateway templates and device profiles are privileged config.
        let capability = match args.object {
            WanObjectArg::GatewayTemplate | WanObjectArg::DeviceProfile => {
                MistCapability::PrivilegedRead
            }
            _ => MistCapability::OrdinaryRead,
        };
        Ok(self
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "get_mist_wan_config",
                    operation_id: resolved.operation_id.to_owned(),
                    path,
                    query: BTreeMap::new(),
                    cursor: None,
                    capability,
                },
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_wan_edge_stats",
        description = "Get WAN edge gateway metrics for a site, or insight metrics for one gateway."
    )]
    async fn get_mist_wan_edge_stats(
        &self,
        Parameters(args): Parameters<WanEdgeStatsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::wan_edge_stats(args.device_id.is_some());
        Ok(self
            .dispatch_named(
                "get_mist_wan_edge_stats",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "invoke_mist_privileged_read",
        description = "Invoke one privileged read selected only by catalog operation ID."
    )]
    async fn invoke_mist_privileged_read(
        &self,
        Parameters(args): Parameters<InvokeReadArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .invoke_dispatcher(
                "invoke_mist_privileged_read",
                args,
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "invoke_mist_read",
        description = "Invoke one ordinary read selected only by catalog operation ID."
    )]
    async fn invoke_mist_read(
        &self,
        Parameters(args): Parameters<InvokeReadArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .invoke_dispatcher(
                "invoke_mist_read",
                args,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_applications",
        description = "List applications seen at a site, count them, or list the gateway application catalog."
    )]
    async fn list_mist_applications(
        &self,
        Parameters(args): Parameters<ApplicationListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if matches!(args.source, AppSourceArg::Site) && args.site_id.is_none() {
            return Ok(tool_result::<ReadEnvelope, _>(
                Err(MistCallError::AmbiguousScope),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }
        let resolved = wan::applications(args.source.into(), args.mode.into());
        Ok(self
            .dispatch_named(
                "list_mist_applications",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_orgs",
        description = "List the bounded local configured organization view."
    )]
    async fn list_mist_orgs(
        &self,
        Parameters(_): Parameters<EmptyArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(caller, "list_mist_orgs", "read_local", Vec::new());
        if let Err(error) = authorize_call(caller, "list_mist_orgs", None, RESTRICTED_TOOLS) {
            audit.deny("scope");
            return Ok(tool_result::<LocalOrgView, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }
        let organizations = self
            .allowed_orgs
            .iter()
            .filter_map(|id| {
                let target = format!("org/{id}");
                caller
                    .is_none_or(|caller| caller.devices.allows(&target))
                    .then(|| LocalOrg {
                        id: id.clone(),
                        target,
                    })
            })
            .collect();
        Ok(audited_tool_result(
            &mut audit,
            Ok::<_, MistCallError>(LocalOrgView {
                source: "local_configured_allowlist",
                organizations,
            }),
        ))
    }
    #[tool(
        name = "list_mist_rogues",
        description = "List site rogue access points."
    )]
    async fn list_mist_rogues(
        &self,
        Parameters(args): Parameters<RogueArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_rogues",
                "listSiteRogueAPs",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_sites",
        description = "List sites in one organization."
    )]
    async fn list_mist_sites(
        &self,
        Parameters(args): Parameters<OrgPageArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_sites",
                "listOrgSites",
                args,
                &["org_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_sle_metrics",
        description = "List SLE metrics for one site scope."
    )]
    async fn list_mist_sle_metrics(
        &self,
        Parameters(args): Parameters<SleMetricsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_sle_metrics",
                "listSiteSlesMetrics",
                args,
                &["site_id", "scope", "scope_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_upgrades",
        description = "List site device upgrades."
    )]
    async fn list_mist_upgrades(
        &self,
        Parameters(args): Parameters<UpgradeArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_upgrades",
                "listSiteDeviceUpgrades",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_wan_config",
        description = "List WAN edge configuration objects: networks, services, service policies, gateway templates, or device profiles."
    )]
    async fn list_mist_wan_config(
        &self,
        Parameters(args): Parameters<WanConfigListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        let object = args.object;
        let resolved = wan::list_config(object.into(), scope);
        // Gateway templates and device profiles are privileged config.
        let capability = match object {
            WanObjectArg::GatewayTemplate | WanObjectArg::DeviceProfile => {
                MistCapability::PrivilegedRead
            }
            _ => MistCapability::OrdinaryRead,
        };
        Ok(self
            .dispatch_named(
                "list_mist_wan_config",
                resolved.operation_id,
                args,
                resolved.path_names,
                capability,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_wan_edges",
        description = "List WAN edge gateways (SRX/SSR) in an organization or site."
    )]
    async fn list_mist_wan_edges(
        &self,
        Parameters(args): Parameters<WanEdgeListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        let resolved = wan::wan_edges(scope);
        Ok(self
            .dispatch_named(
                "list_mist_wan_edges",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_wlans",
        description = "List privileged site WLAN configuration."
    )]
    async fn list_mist_wlans(
        &self,
        Parameters(args): Parameters<SitePageArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_wlans",
                "listSiteWlans",
                args,
                &["site_id"],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "search_mist_alarms", description = "Search site alarms.")]
    async fn search_mist_alarms(
        &self,
        Parameters(args): Parameters<AlarmSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_alarms",
                "searchSiteAlarms",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_audit_logs",
        description = "Search privileged organization audit logs."
    )]
    async fn search_mist_audit_logs(
        &self,
        Parameters(args): Parameters<AuditSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_audit_logs",
                "listOrgAuditLogs",
                args,
                &["org_id"],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_bgp_peers",
        description = "Search WAN edge BGP peer stats in an organization or site, or count them."
    )]
    async fn search_mist_bgp_peers(
        &self,
        Parameters(args): Parameters<BgpPeerSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        let resolved = wan::bgp_peers(scope, args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_bgp_peers",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_clients",
        description = "Search site wireless clients."
    )]
    async fn search_mist_clients(
        &self,
        Parameters(args): Parameters<ClientSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_clients",
                "searchSiteWirelessClients",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_events",
        description = "Search site system events."
    )]
    async fn search_mist_events(
        &self,
        Parameters(args): Parameters<EventSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_events",
                "searchSiteSystemEvents",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_inventory",
        description = "Search organization inventory."
    )]
    async fn search_mist_inventory(
        &self,
        Parameters(args): Parameters<InventoryArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_inventory",
                "searchOrgInventory",
                args,
                &["org_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_operations",
        description = "Search bounded locally catalogued Mist operation metadata."
    )]
    async fn search_mist_operations(
        &self,
        Parameters(args): Parameters<SearchOperationsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(caller, "search_mist_operations", "read_local", Vec::new());
        if let Err(error) = authorize_call(caller, "search_mist_operations", None, RESTRICTED_TOOLS)
        {
            audit.deny("scope");
            return Ok(tool_result::<Vec<OperationSummary<'_>>, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }
        let limit = usize::from(args.limit.unwrap_or(20));
        if args.query.is_empty() || args.query.len() > 128 || !(1..=50).contains(&limit) {
            let error = MistCallError::InvalidSearch;
            audit.fail(&error);
            return Ok(tool_result::<Vec<OperationSummary<'_>>, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }
        let query = args.query.to_ascii_lowercase();
        let capability = args.capability.map(MistCapability::from);
        let target = args.target.map(TargetSelector::from);
        let matches = self
            .catalog
            .operations
            .iter()
            .filter(|operation| self.operation_visible(caller, operation))
            .filter(|operation| capability.is_none_or(|value| operation.capability == value))
            .filter(|operation| {
                target.is_none_or(|value| operation.target_selectors.contains(&value))
            })
            .filter(|operation| {
                operation.operation_id.to_ascii_lowercase().contains(&query)
                    || operation.summary.to_ascii_lowercase().contains(&query)
                    || operation.path.to_ascii_lowercase().contains(&query)
                    || operation
                        .openapi_tags
                        .iter()
                        .any(|tag| tag.to_ascii_lowercase().contains(&query))
            })
            .take(limit)
            .map(|operation| OperationSummary {
                operation_id: &operation.operation_id,
                summary: &operation.summary,
                method: &operation.method,
                path: &operation.path,
                capability: operation.capability,
                target_selectors: &operation.target_selectors,
                pagination: operation.pagination,
            })
            .collect::<Vec<_>>();
        Ok(audited_tool_result(
            &mut audit,
            Ok::<_, MistCallError>(matches),
        ))
    }
    #[tool(
        name = "search_mist_peer_paths",
        description = "Search SD-WAN overlay peer path stats, or count them by a distinct field."
    )]
    async fn search_mist_peer_paths(
        &self,
        Parameters(args): Parameters<PeerPathSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::peer_paths(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_peer_paths",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_service_path_events",
        description = "Search WAN edge service path events for a site, or count them."
    )]
    async fn search_mist_service_path_events(
        &self,
        Parameters(args): Parameters<ServicePathEventArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::service_path_events(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_service_path_events",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_tunnels",
        description = "Search WAN edge IPsec tunnel stats, or count them by a distinct field."
    )]
    async fn search_mist_tunnels(
        &self,
        Parameters(args): Parameters<TunnelSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::tunnels(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_tunnels",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "plan_mist_change",
        description = "Stage a change set for a WAN edge configuration object (network, service, service policy, gateway template, or device profile). Returns a digest-bound plan ready for approval. Arrays replace wholesale; null deletes a field."
    )]
    async fn plan_mist_change(
        &self,
        Parameters(args): Parameters<PlanChangeArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let owner = match caller {
            Some(ctx) => ctx.token_name.clone(),
            None => "stdio".to_owned(),
        };
        let mut audit = audit_scope(
            caller,
            "plan_mist_change",
            "plan",
            vec![args.org_id.clone()],
        );

        // Reject mist_configured BEFORE anything else.
        if let Err(wan_write::PatchError::MistConfigured) =
            wan_write::reject_config_authority(&args.patch)
        {
            audit.fail("patch sets mist_configured");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(
                    "patch sets mist_configured, which controls who may configure the device",
                ),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // Validate org against allowed_orgs before issuing any read or creating a change set.
        if !self
            .allowed_orgs
            .iter()
            .any(|allowed| allowed == &args.org_id)
        {
            audit.deny("org not in allowed_orgs");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "organization {} is not in the server's allowed organizations",
                    args.org_id
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        let object: wan::WanObject = args.object.into();
        let verb: wan_write::WriteVerb = args.verb.into();
        let target = wan_write::write_target(object, verb);

        // For update, read the object; for create, before is null.
        let before = if verb == wan_write::WriteVerb::Update {
            let object_id = match args.object_id.as_deref() {
                Some(id) => id,
                None => {
                    audit.fail("update requires object_id");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("update requires object_id"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };

            let mut path = PathValues::new();
            path.insert(target.id_path_name.to_owned(), object_id.to_owned());
            path.insert("org_id".to_owned(), args.org_id.clone());

            let read = CatalogRead {
                tool: "plan_mist_change",
                operation_id: target.read_operation_id.to_owned(),
                path,
                query: QueryValues::new(),
                cursor: None,
                capability: if target.privileged {
                    MistCapability::PrivilegedRead
                } else {
                    MistCapability::OrdinaryRead
                },
            };

            let result = self.dispatch_catalogued_read(read, &extensions).await;
            if result.is_error == Some(true) {
                audit.fail("read failed");
                return Ok(result);
            }

            let text = match result.content[0].as_text() {
                Some(text_content) => text_content.text.clone(),
                None => {
                    audit.fail("read result was not text");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("read result was not text"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse read response: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!(
                            "failed to parse read response: {error}"
                        )),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            match value.get("data") {
                Some(data) => data.clone(),
                None => {
                    audit.fail("read response missing data field");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("read response missing data field"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            }
        } else {
            serde_json::Value::Null
        };

        let after = wan_write::merge_patch(&before, &args.patch);

        let staged = match change_set::stage_plan(
            &self.coordinator,
            owner.clone(),
            object,
            args.object_id.as_deref(),
            args.org_id.clone(),
            before.clone(),
            after.clone(),
        )
        .await
        {
            Ok(staged) => staged,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };

        // The change was proposed. Emitted here rather than inside the
        // coordinator because this server stages through `insert_change_set`,
        // which mecmcp does not treat as a lifecycle event.
        if let Some(recorder) = &self.evidence {
            recorder.proposal(
                &staged.change_set_id,
                &staged.change_set_id,
                &change_set::object_key(object, args.object_id.as_deref()),
                &owner,
                &staged.plan_digest,
            );
        }

        // Auto-waive if lab mode is enabled
        if self.lab_mode {
            let device = change_set::object_key(object, args.object_id.as_deref());
            if let Err(error) = self
                .coordinator
                .waive_approval(
                    staged.change_set_id.clone(),
                    device,
                    owner.clone(),
                    staged.plan_digest.clone(),
                )
                .await
            {
                audit.fail(format!("lab mode waive failed: {error}"));
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(format!("lab mode waive failed: {error}")),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        }

        let response = if before.is_null() {
            serde_json::json!({
                "change_set_id": staged.change_set_id,
                "plan_digest": staged.plan_digest,
                "preview_digest": staged.preview_digest,
                "before": null,
                "before_state": "absent (create)",
                "after": staged.after,
            })
        } else {
            serde_json::json!({
                "change_set_id": staged.change_set_id,
                "plan_digest": staged.plan_digest,
                "preview_digest": staged.preview_digest,
                "before": staged.before,
                "after": staged.after,
            })
        };

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    #[tool(
        name = "get_mist_change_set",
        description = "Inspect a staged change set, returning its state, owner, before/after, and approval status."
    )]
    async fn get_mist_change_set(
        &self,
        Parameters(args): Parameters<GetChangeSetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_mist_change_set",
            "read",
            vec![args.change_set_id.clone()],
        );

        let object: wan::WanObject = args.object.into();
        let device = change_set::object_key(object, args.object_id.as_deref());

        let record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };

        // Extract before/after from the preview artifact
        let (before, after) = if let Some(preview) = &record.preview {
            let parsed: serde_json::Value = match serde_json::from_str(&preview.artifact) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse preview: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!("failed to parse preview: {error}")),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            let before_value = parsed
                .get("before")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let after_value = parsed
                .get("after")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            (before_value, after_value)
        } else {
            (serde_json::Value::Null, serde_json::Value::Null)
        };

        // `approver: null` alone does not tell an operator whether a second
        // person reviewed this or whether lab mode waived the requirement.
        // mecmcp's packaging standard requires both fields, so surface the
        // waiver reason alongside the (absent) approver.
        let approval_waiver = record
            .approval
            .as_ref()
            .and_then(|approval| approval.waived.as_ref())
            .map(|waiver| waiver.reason.clone());

        let response = serde_json::json!({
            "change_set_id": record.id,
            "state": record.state.as_str(),
            "owner": record.owner,
            "approver": record.approver,
            "approval_waiver": approval_waiver,
            "plan_digest": record.digest,
            "before": before,
            "after": after,
        });

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    /// Record that a write which reached Mist did not succeed.
    ///
    /// Every terminal path *after* the write has to emit one. Mist may already
    /// have created or changed the object by the time the response turns out to
    /// be unusable, so a branch that returns without a receipt leaves the chain
    /// ending at apply intent -- an attempt with no outcome, which says someone
    /// must go and look while saying nothing about what to look for.
    fn failure_receipt(&self, record: &mecmcp_changeset::ChangeSetRecord, reason: &str) {
        if let Some(recorder) = &self.evidence
            && let Err(error) =
                recorder.result_receipt(&record.id, &record.id, &record.device, false, reason)
        {
            tracing::error!(
                %error,
                change_set_id = %record.id,
                "the write was answered but its failure receipt could not be persisted"
            );
        }
    }

    #[tool(
        name = "approve_mist_change_set",
        description = "Grant second-principal approval to a planned change set. The approver must be distinct from the owner."
    )]
    async fn approve_mist_change_set(
        &self,
        Parameters(args): Parameters<ApproveChangeSetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let approver = match caller {
            Some(ctx) => ctx.token_name.clone(),
            None => "stdio".to_owned(),
        };
        let mut audit = audit_scope(
            caller,
            "approve_mist_change_set",
            "approve",
            vec![args.change_set_id.clone()],
        );

        let object: wan::WanObject = args.object.into();
        let device = change_set::object_key(object, args.object_id.as_deref());

        let mut record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };

        // CRITICAL: Check self-approval BEFORE any state mutation.
        if record.owner == approver {
            audit.deny("self-approval");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(
                    "the planning principal cannot approve their own change set",
                ),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        if record.state != mecmcp_changeset::ChangeSetState::Planned {
            audit.fail(format!(
                "change set is {}, not planned",
                record.state.as_str()
            ));
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "change set is {}, not planned",
                    record.state.as_str()
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                audit.fail(format!("time error: {error}"));
                rmcp::ErrorData::invalid_params(format!("time error: {error}"), None)
            })?
            .as_secs();

        let approval_digest = mecmcp_changeset::digest::compute_approval_digest(
            &record.id,
            &record.digest,
            &record.owner,
            &approver,
            now,
        );

        record.approval = Some(mecmcp_changeset::ApprovalRecord {
            approver: Some(approver.clone()),
            approved_at_unix: now,
            digest: approval_digest,
            waived: None,
        });
        record.approver = Some(approver.clone());
        record.state = mecmcp_changeset::ChangeSetState::Approved;
        let approved_device = record.device.clone();
        let approved_id = record.id.clone();

        if let Err(error) = self.coordinator.update_change_set(record).await {
            audit.fail(error.to_string());
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(error.to_string()),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // A second person decided. Recorded after the state write, so the trail
        // cannot claim an approval the coordinator failed to persist.
        if let Some(recorder) = &self.evidence {
            let _ = &approved_device;
            recorder.approval(&approved_id, &approved_id, &approver, "approved");
        }

        let response = serde_json::json!({
            "change_set_id": args.change_set_id,
            "state": "approved",
            "expires_in_seconds": self.coordinator.approval_ttl().as_secs(),
        });

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    #[tool(
        name = "apply_mist_change_set",
        description = "Apply an approved change set to Mist. Verifies approval, checks for drift, issues the mutation, and verifies the result."
    )]
    async fn apply_mist_change_set(
        &self,
        Parameters(args): Parameters<ApplyChangeSetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        // Who is applying, which need not be who planned. The apply path does
        // not require caller == owner, so recording `record.owner` here would
        // attribute the execution to the planner -- a false statement in a
        // trail whose whole purpose is saying who did what.
        let applying_principal =
            caller.map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        let mut audit = audit_scope(
            caller,
            "apply_mist_change_set",
            "apply",
            vec![args.change_set_id.clone()],
        );

        let object: wan::WanObject = args.object.into();
        let device = change_set::object_key(object, args.object_id.as_deref());

        // Step 1: Take the device guard for concurrency control.
        let cancellation = tokio_util::sync::CancellationToken::new();
        let _guard = match self.coordinator.device_guard(&device, &cancellation).await {
            Ok(guard) => guard,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };

        // Step 2: Fetch the record and refuse unless state is Approved.
        let mut record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };

        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            audit.fail(format!(
                "change set is {}, not approved",
                record.state.as_str()
            ));
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "change set is {}, not approved",
                    record.state.as_str()
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // Step 3: Check if the approval has expired.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                audit.fail(format!("time error: {error}"));
                rmcp::ErrorData::invalid_params(format!("time error: {error}"), None)
            })?
            .as_secs();

        if now > record.expires_at_unix {
            audit.fail("approval has expired");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "approval expired at unix timestamp {}",
                    record.expires_at_unix
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // Extract before/after/org_id from the preview artifact.
        let (_before, after, org_id) = if let Some(preview) = &record.preview {
            let parsed: serde_json::Value = match serde_json::from_str(&preview.artifact) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse preview: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!("failed to parse preview: {error}")),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            let before_value = parsed
                .get("before")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let after_value = parsed
                .get("after")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let org_id_value = match parsed.get("org_id").and_then(|v| v.as_str()) {
                Some(id) => id.to_owned(),
                None => {
                    audit.fail("preview missing org_id");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(
                            "change set was planned before org-scope fix and must be re-planned",
                        ),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            (before_value, after_value, org_id_value)
        } else {
            audit.fail("change set has no preview");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>("change set has no preview"),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        };

        // Determine the verb from the expected fingerprint.
        let is_create = record.expected_candidate_fingerprint == "create";
        let verb = if is_create {
            wan_write::WriteVerb::Create
        } else {
            wan_write::WriteVerb::Update
        };
        let target = wan_write::write_target(object, verb);

        // Validate and bind object_id for updates.
        let object_id = if !is_create {
            match args.object_id.as_deref() {
                Some(id) => id.to_owned(),
                None => {
                    audit.fail("update requires object_id");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("update requires object_id"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            }
        } else {
            String::new() // Placeholder for creates; will be populated from response
        };

        // Step 4: For updates, re-read the object and compare fingerprints.
        let drift_checked = if !is_create {
            let mut path = PathValues::new();
            path.insert(target.id_path_name.to_owned(), object_id.clone());
            path.insert("org_id".to_owned(), org_id.clone());

            let read = CatalogRead {
                tool: "apply_mist_change_set",
                operation_id: target.read_operation_id.to_owned(),
                path,
                query: QueryValues::new(),
                cursor: None,
                capability: if target.privileged {
                    MistCapability::PrivilegedRead
                } else {
                    MistCapability::OrdinaryRead
                },
            };

            let result = self.dispatch_catalogued_read(read, &extensions).await;
            if result.is_error == Some(true) {
                audit.fail("drift check read failed");
                return Ok(result);
            }

            let text = match result.content[0].as_text() {
                Some(text_content) => text_content.text.clone(),
                None => {
                    audit.fail("drift check result was not text");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("drift check result was not text"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse drift check response: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!(
                            "failed to parse drift check response: {error}"
                        )),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            let current = match value.get("data") {
                Some(data) => data.clone(),
                None => {
                    audit.fail("drift check response missing data field");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("drift check response missing data field"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };

            // Compute fingerprint of current state.
            let canonical = match serde_json::to_vec(&current) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to serialize current state: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!(
                            "failed to serialize current state: {error}"
                        )),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            };
            let mut hasher = sha2::Sha256::new();
            hasher.update(&canonical);
            let current_fingerprint = format!("sha256:{}", hex::encode(hasher.finalize()));

            // Compare with expected fingerprint.
            if current_fingerprint != record.expected_candidate_fingerprint {
                record.state = mecmcp_changeset::ChangeSetState::Failed;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    audit.fail(format!("failed to mark drift failure: {error}"));
                } else {
                    audit.fail("object moved since planning (drift detected)");
                }
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(
                        "object has been modified since planning; fingerprint mismatch",
                    ),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
            true
        } else {
            false
        };

        // Validate org against allowed_orgs before issuing the write.
        if !self.allowed_orgs.iter().any(|allowed| allowed == &org_id) {
            audit.deny("org not in allowed_orgs");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "organization {} is not in the server's allowed organizations",
                    org_id
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // The device is about to be written. Persisted *before* that happens, so
        // a crash during the write still leaves evidence the attempt was made --
        // and refused if it cannot be persisted, because a Mist object changed
        // with no record that anyone tried is the one state this chain exists to
        // rule out.
        //
        // Emitted **before** the `Applying` transition below, not after. After
        // it, a refusal would leave the record in `Applying` while telling the
        // caller it is still approved -- and the retry gate accepts only
        // `Approved`, so the change set would be stranded with no Mist write and
        // no way forward. Refusing here leaves it exactly as it was.
        if let Some(recorder) = &self.evidence
            && let Err(error) =
                recorder.apply_intent(&record.id, &record.id, &record.device, &applying_principal)
        {
            let message = format!(
                "apply refused: the apply-intent evidence record could not be persisted \
                 ({error}); the change set is still approved and can be retried"
            );
            audit.fail(message.clone());
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(message),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // Step 5: Mark Applying and persist before issuing the write.
        record.state = mecmcp_changeset::ChangeSetState::Applying;
        if let Err(error) = self.coordinator.update_change_set(record.clone()).await {
            audit.fail(error.to_string());
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(error.to_string()),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        // Step 6: Issue the write with json: Some(after).
        let mut path = PathValues::new();
        path.insert("org_id".to_owned(), org_id.clone());
        if !is_create {
            path.insert(target.id_path_name.to_owned(), object_id.clone());
        }

        let write_request = MistRequest {
            operation_id: target.write_operation_id.to_owned(),
            path,
            query: QueryValues::new(),
            json: Some(after.clone()),
            cursor: None,
        };

        let write_result = self.client.execute(write_request).await;
        let write_response = match write_result {
            Ok(response) => response,
            Err(error) => {
                audit.fail(format!("write failed: {error}"));
                self.failure_receipt(&record, "write failed");
                record.state = mecmcp_changeset::ChangeSetState::Failed;
                let _ = self.coordinator.update_change_set(record).await;
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(format!("write failed: {error}")),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };

        // Step 7: Re-read and verify against after.
        let final_object_id = if is_create {
            // Extract the ID from the write response.
            match &write_response.body {
                MistResponseBody::Json(json) => match json.get("id") {
                    Some(serde_json::Value::String(id)) => id.clone(),
                    _ => {
                        audit.fail("create response missing id field");
                        self.failure_receipt(&record, "create response missing id field");
                        record.state = mecmcp_changeset::ChangeSetState::Failed;
                        let _ = self.coordinator.update_change_set(record).await;
                        return Ok(tool_result::<serde_json::Value, _>(
                            Err::<serde_json::Value, _>("create response missing id field"),
                            ResultFormat::PrettyJson,
                            RESULT_LIMITS,
                        ));
                    }
                },
                _ => {
                    audit.fail("create response was not JSON");
                    self.failure_receipt(&record, "create response was not JSON");
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = self.coordinator.update_change_set(record).await;
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("create response was not JSON"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                    ));
                }
            }
        } else {
            object_id.clone()
        };

        let mut verify_path = PathValues::new();
        verify_path.insert(target.id_path_name.to_owned(), final_object_id.clone());
        verify_path.insert("org_id".to_owned(), org_id.clone());

        let verify_read = CatalogRead {
            tool: "apply_mist_change_set",
            operation_id: target.read_operation_id.to_owned(),
            path: verify_path,
            query: QueryValues::new(),
            cursor: None,
            capability: if target.privileged {
                MistCapability::PrivilegedRead
            } else {
                MistCapability::OrdinaryRead
            },
        };

        let verify_result = self
            .dispatch_catalogued_read(verify_read, &extensions)
            .await;
        let verified = if verify_result.is_error != Some(true) {
            if let Some(text_content) = verify_result.content[0].as_text() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text_content.text) {
                    if let Some(data) = value.get("data") {
                        data == &after
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Mist answered. Recorded before the local state write, because that
        // write can fail and the receipt describes what the device did, which
        // local persistence cannot retract. A failure is recorded as fully as a
        // success.
        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.result_receipt(
                &record.id,
                &record.id,
                &record.device,
                verified,
                if verified { "" } else { "write not verified" },
            )
        {
            tracing::error!(
                %error,
                change_set_id = %record.id,
                "Mist answered but the result receipt could not be persisted; the \
                 evidence chain ends at apply intent"
            );
        }

        // Step 8: Mark Applied or Failed and persist.
        record.state = if verified {
            mecmcp_changeset::ChangeSetState::Applied
        } else {
            mecmcp_changeset::ChangeSetState::Failed
        };

        if let Err(error) = self.coordinator.update_change_set(record.clone()).await {
            audit.fail(format!("failed to persist final state: {error}"));
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!("failed to persist final state: {error}")),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }

        let response = serde_json::json!({
            "change_set_id": args.change_set_id,
            "state": record.state.as_str(),
            "object_id": final_object_id,
            "drift_checked": drift_checked,
            "verified": verified,
        });

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    #[tool(
        name = "troubleshoot_mist",
        description = "List site troubleshoot calls."
    )]
    async fn troubleshoot_mist(
        &self,
        Parameters(args): Parameters<TroubleshootArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "troubleshoot_mist",
                "listSiteTroubleshootCalls",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
}

/// Wrap a filtered tool list in the result shape a 2026-07-28 client accepts.
///
/// `ListToolsResult::with_all_items` leaves `ttl_ms` and `cache_scope` unset and
/// both are omitted on the wire; a client on that protocol validates the result
/// and rejects it, which surfaces as "tools fetch failed" against a server that
/// is healthy and answering in milliseconds. Servers that do not override
/// `list_tools` get these from rmcp's generated handler — this one filters by
/// scope, so it supplies them itself.
///
/// Gated on the negotiated version exactly as rmcp does: the fields belong to
/// 2026-07-28 and later, and a strict legacy client rejects what it did not
/// negotiate.
///
/// `private` where rmcp's unfiltered list says `public`, because this list is
/// per token: a cache keyed only on the URL must not serve one caller's
/// permitted surface to another.
fn listed_tools(tools: Vec<rmcp::model::Tool>, cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if cache_hints {
        listed
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MistHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rustmistmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Read-only HPE Juniper Mist MCP server. Use named workflows first; \
                 catalog dispatchers accept operation IDs, never methods or URLs.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = mecmcp_server::caller_from_extensions::<rustmistmcp_core::MistGrant>(
            &context.extensions,
        );
        let tools = self.tool_router.list_all();
        let visible = if caller.is_some() {
            filter_tools_for_scope(tools, caller, RESTRICTED_TOOLS)
        } else {
            tools
                .into_iter()
                .filter(|tool| !RESTRICTED_TOOLS.contains(&tool.name.as_ref()))
                .collect()
        };
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(visible, cache_hints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mecmcp_audit::testutil::CapturingWriter;
    use mecmcp_auth::{ActorType, ScopeSet};
    use std::{
        cell::RefCell,
        io::Write,
        sync::{Mutex, OnceLock},
    };

    thread_local! {
        static ACTIVE_AUDIT_CAPTURE: RefCell<Option<CapturingWriter>> = const { RefCell::new(None) };
    }

    static AUDIT_SUBSCRIBER: OnceLock<()> = OnceLock::new();

    struct ThreadLocalAuditWriter(Option<CapturingWriter>);

    impl Write for ThreadLocalAuditWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match &mut self.0 {
                Some(capture) => capture.write(buf),
                None => std::io::sink().write(buf),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            match &mut self.0 {
                Some(capture) => capture.flush(),
                None => std::io::sink().flush(),
            }
        }
    }

    struct ThreadLocalAuditMakeWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadLocalAuditMakeWriter {
        type Writer = ThreadLocalAuditWriter;

        fn make_writer(&'a self) -> Self::Writer {
            ThreadLocalAuditWriter(ACTIVE_AUDIT_CAPTURE.with(|capture| capture.borrow().clone()))
        }
    }

    struct AuditCaptureGuard;

    impl Drop for AuditCaptureGuard {
        fn drop(&mut self) {
            ACTIVE_AUDIT_CAPTURE.with(|capture| {
                capture.borrow_mut().take();
            });
        }
    }

    fn install_audit_capture(capture: CapturingWriter) -> AuditCaptureGuard {
        AUDIT_SUBSCRIBER.get_or_init(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(ThreadLocalAuditMakeWriter)
                .with_ansi(false)
                .with_target(true)
                .with_max_level(tracing::Level::INFO)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("test audit subscriber is installed once");
        });
        ACTIVE_AUDIT_CAPTURE.with(|active| {
            assert!(
                active.borrow().is_none(),
                "nested audit capture on one test thread"
            );
            *active.borrow_mut() = Some(capture);
        });
        AuditCaptureGuard
    }

    #[derive(Default)]
    struct RecordingClient(Mutex<Vec<MistRequest>>);

    struct FixedResponseClient {
        response: rustmistmcp_core::MistResponse,
    }

    #[async_trait]
    impl MistClient for RecordingClient {
        async fn execute(
            &self,
            request: MistRequest,
        ) -> Result<rustmistmcp_core::MistResponse, MistError> {
            self.0.lock().expect("recorder").push(request.clone());
            Ok(rustmistmcp_core::MistResponse {
                operation_id: request.operation_id,
                status: 200,
                body: MistResponseBody::Json(serde_json::json!({"name": "authorized"})),
                cursor: None,
            })
        }
    }

    #[async_trait]
    impl MistClient for FixedResponseClient {
        async fn execute(
            &self,
            _request: MistRequest,
        ) -> Result<rustmistmcp_core::MistResponse, MistError> {
            Ok(self.response.clone())
        }
    }

    fn org_read(operation_id: &str) -> CatalogRead {
        CatalogRead {
            tool: "invoke_mist_read",
            operation_id: operation_id.to_owned(),
            path: BTreeMap::from([(
                "org_id".to_owned(),
                "11111111-1111-1111-1111-111111111111".to_owned(),
            )]),
            query: BTreeMap::new(),
            cursor: None,
            capability: MistCapability::OrdinaryRead,
        }
    }

    fn caller(target: &str) -> CallerCtx<MistGrant> {
        CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "alice".to_owned(),
            devices: ScopeSet::Allowlist(vec![target.to_owned()]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            grant: Some(MistGrant {
                allowed_operations: vec!["getOrg".to_owned()],
                actions: vec![MistCapability::OrdinaryRead],
                subjects: vec![MistTarget::parse(target).expect("target")],
            }),
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        }
    }

    fn extensions(caller: CallerCtx<MistGrant>) -> rmcp::model::Extensions {
        let request = http::Request::new(());
        let (mut parts, _) = request.into_parts();
        parts.extensions.insert(caller);
        let mut extensions = rmcp::model::Extensions::new();
        extensions.insert(parts);
        extensions
    }

    #[tokio::test]
    async fn authenticated_ordinary_read_does_not_require_a_mutation_grant() {
        let target = "org/11111111-1111-1111-1111-111111111111";
        let client = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            client.clone(),
        )
        .expect("handler");
        let mut caller = caller(target);
        caller.grant = None;

        let result = handler
            .dispatch_catalogued_read(org_read("getOrg"), &extensions(caller))
            .await;

        assert_ne!(result.is_error, Some(true), "{result:?}");
        assert_eq!(client.0.lock().expect("recorder").len(), 1);
    }

    #[tokio::test]
    async fn authenticated_privileged_dispatch_requires_an_exact_mist_grant() {
        let client = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            client.clone(),
        )
        .expect("handler");
        let caller = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "privileged-without-grant".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["invoke_mist_privileged_read".to_owned()]),
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };

        let result = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_privileged_read",
                    operation_id: "getSelf".to_owned(),
                    path: BTreeMap::new(),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::PrivilegedRead,
                },
                &extensions(caller),
            )
            .await;

        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert!(
            client.0.lock().expect("recorder").is_empty(),
            "privileged request must be denied before client dispatch"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_dispatch_cursor_emits_a_failed_audit_outcome() {
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
        )
        .expect("handler");
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());
        let result = handler
            .invoke_dispatcher(
                "invoke_mist_read",
                InvokeReadArgs {
                    operation_id: "getOrg".to_owned(),
                    path: None,
                    query: None,
                    cursor: Some("not-hex".to_owned()),
                },
                MistCapability::OrdinaryRead,
                &rmcp::model::Extensions::new(),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        let output = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
        assert!(output.contains("tool=invoke_mist_read"), "{output}");
        assert!(output.contains("result=error"), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cursor_shape_bounds_are_enforced_before_client_dispatch() {
        let recorder = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        for cursor in [
            "0".to_owned(),
            "gg".to_owned(),
            "0".repeat(MAX_ENCODED_CURSOR_BYTES + 1),
        ] {
            let result = handler
                .invoke_dispatcher(
                    "invoke_mist_read",
                    InvokeReadArgs {
                        operation_id: "getOrg".to_owned(),
                        path: None,
                        query: None,
                        cursor: Some(cursor),
                    },
                    MistCapability::OrdinaryRead,
                    &rmcp::model::Extensions::new(),
                )
                .await;
            assert_eq!(result.is_error, Some(true), "{result:?}");
        }
        assert!(recorder.0.lock().expect("recorder").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cursor_context_is_reauthorized_on_every_continuation() {
        let recorder = Arc::new(RecordingClient::default());
        let requested_org = "11111111-1111-1111-1111-111111111111";
        let other_org = "44444444-4444-4444-4444-444444444444";
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![requested_org.to_owned(), other_org.to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let path = BTreeMap::from([("org_id".to_owned(), requested_org.to_owned())]);
        let cursor = rustmistmcp_core::MistCursor::new(
            "listOrgSites".to_owned(),
            &Url::parse("https://api.mist.com/").expect("origin"),
            rustmistmcp_core::PaginationMode::PageLimit,
            "next".to_owned(),
        )
        .expect("cursor")
        .with_request_context(
            path,
            BTreeMap::from([("limit".to_owned(), serde_json::json!(25))]),
            Some(MistTarget::org(requested_org).expect("target")),
        )
        .expect("context");
        let encoded = hex::encode(serde_json::to_vec(&cursor).expect("serialize"));
        let result = handler
            .invoke_dispatcher(
                "invoke_mist_read",
                InvokeReadArgs {
                    operation_id: "listOrgSites".to_owned(),
                    path: None,
                    query: None,
                    cursor: Some(encoded),
                },
                MistCapability::OrdinaryRead,
                &extensions(caller(&format!("org/{other_org}"))),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        assert!(recorder.0.lock().expect("recorder").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_tool_target_and_grant_authority_is_audited_before_client_dispatch() {
        let recorder = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());
        let path = BTreeMap::from([(
            "org_id".to_owned(),
            "11111111-1111-1111-1111-111111111111".to_owned(),
        )]);
        let allowed = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_read",
                    operation_id: "getOrg".to_owned(),
                    path: path.clone(),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                },
                &extensions(caller("org/11111111-1111-1111-1111-111111111111")),
            )
            .await;
        assert_ne!(allowed.is_error, Some(true), "{allowed:?}");
        assert_eq!(recorder.0.lock().expect("recorder").len(), 1);

        let denied = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_read",
                    operation_id: "getOrg".to_owned(),
                    path,
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                },
                &extensions(caller("org/44444444-4444-4444-4444-444444444444")),
            )
            .await;
        assert_eq!(denied.is_error, Some(true));
        assert_eq!(recorder.0.lock().expect("recorder").len(), 1);

        let output = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
        assert!(output.contains("result=ok"), "{output}");
        assert!(output.contains("result=denied"), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_grant_cannot_dispatch_an_undiscovered_site() {
        let recorder = Arc::new(RecordingClient::default());
        let org_id = "11111111-1111-1111-1111-111111111111";
        let site_id = "44444444-4444-4444-4444-444444444444";
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![org_id.to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let target = format!("site/{site_id}");
        let caller = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "alice".to_owned(),
            devices: ScopeSet::Allowlist(vec![target.clone()]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            grant: Some(MistGrant {
                allowed_operations: vec!["getSiteInfo".to_owned()],
                actions: vec![MistCapability::OrdinaryRead],
                subjects: vec![MistTarget::parse(&target).expect("target")],
            }),
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        let result = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_read",
                    operation_id: "getSiteInfo".to_owned(),
                    path: BTreeMap::from([("site_id".to_owned(), site_id.to_owned())]),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                },
                &extensions(caller),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        assert!(recorder.0.lock().expect("recorder").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mismatched_and_non_success_responses_are_failed_audits() {
        let cases = [
            rustmistmcp_core::MistResponse {
                operation_id: "getSiteInfo".to_owned(),
                status: 200,
                body: MistResponseBody::Json(serde_json::json!({"name": "wrong operation"})),
                cursor: None,
            },
            rustmistmcp_core::MistResponse {
                operation_id: "getOrg".to_owned(),
                status: 403,
                body: MistResponseBody::Json(serde_json::json!({"detail": "forbidden"})),
                cursor: None,
            },
            rustmistmcp_core::MistResponse {
                operation_id: "getOrg".to_owned(),
                status: 429,
                body: MistResponseBody::Json(serde_json::json!({"detail": "slow down"})),
                cursor: None,
            },
        ];
        for response in cases {
            let handler = MistHandler::with_client(
                "https://api.mist.com/",
                vec!["11111111-1111-1111-1111-111111111111".to_owned()],
                BTreeMap::new(),
                Arc::new(FixedResponseClient { response }),
            )
            .expect("handler");
            let capture = CapturingWriter::default();
            let _capture_guard = install_audit_capture(capture.clone());
            let result = handler
                .dispatch_catalogued_read(org_read("getOrg"), &rmcp::model::Extensions::new())
                .await;
            assert_eq!(result.is_error, Some(true), "{result:?}");
            let output =
                String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
            assert!(output.contains("result=error"), "{output}");
            assert!(!output.contains("result=ok"), "{output}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_result_refusal_is_a_failed_audit() {
        let sites = (0..32)
            .map(|_| serde_json::json!({"name": "x".repeat(20_000)}))
            .collect();
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            Arc::new(FixedResponseClient {
                response: rustmistmcp_core::MistResponse {
                    operation_id: "listOrgSites".to_owned(),
                    status: 200,
                    body: MistResponseBody::Json(serde_json::Value::Array(sites)),
                    cursor: None,
                },
            }),
        )
        .expect("handler");
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());
        let result = handler
            .dispatch_catalogued_read(org_read("listOrgSites"), &rmcp::model::Extensions::new())
            .await;
        assert_eq!(result.is_error, Some(true), "{result:?}");
        let output = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
        assert!(output.contains("result=error"), "{output}");
        assert!(!output.contains("result=ok"), "{output}");
    }

    #[test]
    fn wildcard_tool_scope_excludes_every_restricted_read() {
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
        )
        .expect("handler");
        let caller = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "wildcard".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        let visible = filter_tools_for_scope(
            handler.tool_router.list_all(),
            Some(&caller),
            RESTRICTED_TOOLS,
        );
        let names = visible
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        for restricted in RESTRICTED_TOOLS {
            assert!(!names.contains(restricted), "{restricted}");
        }
    }

    #[test]
    fn metadata_visibility_requires_an_invocable_configured_target_intersection() {
        let org_id = "11111111-1111-1111-1111-111111111111";
        let site_id = "22222222-2222-2222-2222-222222222222";
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec![org_id.to_owned()],
            BTreeMap::from([(site_id.to_owned(), org_id.to_owned())]),
        )
        .expect("handler");
        let get_org = handler.catalog.operation("getOrg").expect("getOrg");
        let get_site = handler
            .catalog
            .operation("getSiteInfo")
            .expect("getSiteInfo");
        let get_self = handler.catalog.operation("getSelf").expect("getSelf");

        let grantless_org = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "grantless-org".to_owned(),
            devices: ScopeSet::Allowlist(vec![format!("org/{org_id}")]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        assert!(
            handler.operation_visible(Some(&grantless_org), get_org),
            "grantless scoped ordinary read must be discoverable when executable"
        );
        assert!(
            !handler.operation_visible(Some(&grantless_org), get_site),
            "configured inventory still intersects caller target scope"
        );
        let grantless_site = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "grantless-site".to_owned(),
            devices: ScopeSet::Allowlist(vec![format!("site/{site_id}")]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        assert!(handler.operation_visible(Some(&grantless_site), get_site));
        let missing_dispatcher_scope = CallerCtx {
            tools: ScopeSet::Allowlist(vec!["search_mist_operations".to_owned()]),
            ..grantless_org.clone()
        };
        assert!(!handler.operation_visible(Some(&missing_dispatcher_scope), get_org));
        let grantless_privileged = CallerCtx {
            tools: ScopeSet::Allowlist(vec!["invoke_mist_privileged_read".to_owned()]),
            ..grantless_org.clone()
        };
        assert!(
            !handler.operation_visible(Some(&grantless_privileged), get_self),
            "privileged metadata remains hidden without an exact grant"
        );
        let privileged_exact = CallerCtx {
            grant: Some(MistGrant {
                allowed_operations: vec!["getSelf".to_owned()],
                actions: vec![MistCapability::PrivilegedRead],
                subjects: vec![MistTarget::org(org_id).expect("target")],
            }),
            ..grantless_privileged
        };
        assert!(
            handler.operation_visible(Some(&privileged_exact), get_self),
            "privileged metadata is visible only with exact tool and grant authority"
        );

        let ordinary_wildcard = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "ordinary".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: Some(MistGrant {
                allowed_operations: vec!["getOrg".to_owned(), "getSelf".to_owned()],
                actions: vec![MistCapability::OrdinaryRead, MistCapability::PrivilegedRead],
                subjects: vec![MistTarget::org(org_id).expect("target")],
            }),
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        assert!(handler.operation_visible(Some(&ordinary_wildcard), get_org));
        assert!(
            !handler.operation_visible(Some(&ordinary_wildcard), get_self),
            "wildcard tool scope must not expose the restricted dispatcher"
        );

        let out_of_scope = CallerCtx {
            devices: ScopeSet::Allowlist(vec![
                "org/44444444-4444-4444-4444-444444444444".to_owned(),
            ]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            ..ordinary_wildcard
        };
        assert!(
            !handler.operation_visible(Some(&out_of_scope), get_org),
            "grant subjects without caller.devices intersection are not invocable"
        );
    }

    #[test]
    fn handler_reuses_strict_mist_regional_endpoint_validation() {
        for endpoint in [
            "https://evil.example/",
            "https://127.0.0.1/",
            "https://api.mist.com:8443/",
            "https://api.mist.com/api/v1/",
        ] {
            assert!(
                MistHandler::blocked(
                    endpoint,
                    vec!["11111111-1111-1111-1111-111111111111".to_owned()],
                    BTreeMap::new(),
                )
                .is_err(),
                "{endpoint}"
            );
        }
        assert!(
            MistHandler::blocked(
                "https://api.eu.mist.com/",
                vec!["11111111-1111-1111-1111-111111111111".to_owned()],
                BTreeMap::new(),
            )
            .is_ok()
        );
    }
}

#[cfg(test)]
mod tools_list_cache_tests {
    use super::listed_tools;

    /// A 2026-07-28 client rejects a tools/list without these, and the failure
    /// reads as an unreachable server rather than a malformed reply.
    #[test]
    fn a_modern_client_gets_a_private_cache_descriptor() {
        let listed = listed_tools(Vec::new(), true);
        assert_eq!(
            listed.ttl_ms,
            Some(0),
            "a 2026-07-28 client rejects a tools/list without ttlMs"
        );
        assert_eq!(
            listed.cache_scope,
            Some(rmcp::model::CacheScope::Private),
            "the list is filtered per token, so it must not be shared"
        );
    }

    /// The fields are not part of the older result shape, and a strict legacy
    /// client rejects what it did not negotiate.
    #[test]
    fn a_legacy_client_gets_no_cache_descriptor() {
        let listed = listed_tools(Vec::new(), false);
        assert_eq!(listed.ttl_ms, None);
        assert_eq!(listed.cache_scope, None);
    }
}
