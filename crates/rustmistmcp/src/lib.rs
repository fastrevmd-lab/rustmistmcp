//! Mist MCP server composition.

mod http_transport;
mod server;

pub use http_transport::{
    LIVE_MIST_BLOCKER, MistScopePreflight, build_http_router, install_token_reload_handler,
    serve_http, validate_runtime_serve,
};
pub use server::{KNOWN_TOOLS, MistHandler, MistServerError, RESTRICTED_TOOLS};

/// The pinned shared token CLI can manage only grantless token documents.
///
/// HTTP intentionally loads `TokenStoreFile<MistGrant>`, but grant-generic
/// add/list/revoke/rotate support remains tracked by `mecmcp#160`.
pub const GRANT_TOKEN_LIFECYCLE_BLOCKER: &str = "mecmcp#160: shared token commands support \
grantless stores only; grant-bearing Mist token add/list/revoke/rotate is unavailable";
