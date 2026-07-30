//! Mist MCP server composition.

mod http_transport;
mod server;

pub use http_transport::{
    LIVE_MIST_BLOCKER, MistScopePreflight, build_http_router, install_token_reload_handler,
    serve_http, validate_runtime_serve,
};
pub use server::{KNOWN_TOOLS, MistHandler, MistServerError, RESTRICTED_TOOLS};

/// The pinned coherent shared-server revision can manage only grantless tokens.
///
/// `mecmcp#160` has merged the grant-generic command API onto `mecmcp` main,
/// but that revision does not contain the shared server crate this process
/// requires alongside the rest of the shared foundation. Keep one revision and
/// fail closed until upstream publishes the complete foundation together.
pub const GRANT_TOKEN_LIFECYCLE_BLOCKER: &str = "mecmcp#160 is merged, but the pinned coherent \
mecmcp server revision predates it; grant-bearing Mist token add/list/revoke/rotate is unavailable";
