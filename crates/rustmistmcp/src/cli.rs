//! Command-line arguments for the Mist MCP server.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Re-export from mecmcp-runtime for compatibility
pub use mecmcp_runtime::cli::Transport;
pub use mecmcp_runtime::cli::WebApproverArgs;

#[derive(Debug, Parser)]
#[command(name = "rustmistmcp", version, about = "HPE Juniper Mist MCP server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// JSON file with Mist profile configuration.
    #[arg(
        short = 'f',
        long,
        default_value = "mist-profile.json",
        global = true,
        alias = "device-mapping"
    )]
    pub device_mapping: PathBuf,

    /// Transport.
    #[arg(short = 't', long, default_value = "stdio", value_enum)]
    pub transport: Transport,

    /// Bind host (streamable-http only).
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port (streamable-http only).
    #[arg(short = 'p', long, default_value_t = 30030)]
    pub port: u16,

    /// Bearer-token file. Required for streamable-http unless --allow-no-auth.
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// PEM-encoded TLS cert (streamable-http only). Pair with --tls-key.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS key (streamable-http only). Pair with --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Disable bearer-token auth. Refuses to bind off-loopback.
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured.
    #[arg(long)]
    pub allow_insecure_bind: bool,

    /// Additional Host authorities to accept on the streamable-http endpoint.
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Accepted browser Origin URL. Repeat for multiple values.
    #[arg(long)]
    pub allowed_origin: Vec<String>,

    /// Audit/log output format for stderr: text or json.
    #[arg(long, default_value = "text")]
    pub audit_format: String,

    /// Optional file to append JSON audit lines to (in addition to stderr).
    #[arg(long)]
    pub audit_log_file: Option<PathBuf>,

    /// Also send structured audit events directly to journald.
    #[arg(long)]
    pub audit_journald: bool,

    /// Per-field audit redaction, e.g. `devices=hmac,host=drop`.
    #[arg(long, default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction.
    #[arg(long)]
    pub audit_hmac_key_file: Option<PathBuf>,

    /// Change-set lifecycle state file for two-person approval workflow.
    #[arg(
        long = "state-file",
        default_value = "/var/lib/rustmistmcp/changeset-state.json"
    )]
    pub state_file: PathBuf,

    /// Change-set approval timeout in seconds.
    #[arg(long = "approval-timeout-secs", default_value_t = 3600)]
    pub approval_timeout_secs: u64,

    /// Run without two-person control: change sets are approved on creation.
    ///
    /// For single-operator environments — a lab with one engineer — where
    /// requiring a second principal makes change sets unusable rather than
    /// safer.
    ///
    /// No approver is invented. A waived change set records `approver: null`
    /// with `approval_waiver: "lab-mode"`, so it stays distinguishable from one
    /// a second person actually reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Web approver settings (--web-enabled-approver).
    #[command(flatten)]
    pub web_approver: WebApproverArgs,
}

/// Top-level management commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the bearer-token store.
    Token {
        /// Token action.
        #[command(subcommand)]
        action: TokenAction,
    },
}

/// Token-store action.
#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated device names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Change an existing token's scopes without touching its secret.
    SetScopes {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List token names + scopes (never the hash or secret).
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Remove a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke + re-add under the same scopes; prints a new secret.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}
