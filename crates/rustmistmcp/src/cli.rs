//! Command-line arguments for the Mist MCP server.

use clap::Parser;
use std::path::PathBuf;

// Re-export from mecmcp-runtime for compatibility
pub use mecmcp_runtime::cli::{Command, Transport, WebApproverArgs};

#[derive(Debug, Parser)]
#[command(name = "rustmistmcp", version, about = "HPE Juniper Mist MCP server")]
pub struct MistCli {
    /// Flatten the shared CLI so every flag behaves identically across the fleet.
    #[command(flatten)]
    pub shared: mecmcp_runtime::cli::Cli,

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
    /// with `waived: { reason: "lab-mode" }`, so it stays distinguishable from one
    /// a second person actually reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Web approver settings (--web-enabled-approver).
    #[command(flatten)]
    pub web_approver: WebApproverArgs,
}
