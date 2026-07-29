//! HPE Juniper Mist MCP server executable.

use anyhow::{Context as _, Result};
use clap::Parser as _;
use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::cli::{Cli, Command, TokenAction, Transport};
use rmcp::ServiceExt as _;
use rustmistmcp::{
    GRANT_TOKEN_LIFECYCLE_BLOCKER, KNOWN_TOOLS, LIVE_MIST_BLOCKER, MistHandler,
    install_token_reload_handler, serve_http, validate_runtime_serve,
};
use rustmistmcp_core::{MistConfig, MistGrant};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let validated = validate_runtime_serve(&args).map_err(|error| anyhow::anyhow!("{error}"))?;
    init_audit(&args)?;

    if let Some(Command::Token { action }) = args.command {
        // Management is deliberately local: it validates against the fixed
        // tool registry and neither loads Mist profile/credential data nor
        // contacts the Mist service.
        mecmcp_runtime::cli_validate::require_absolute(token_store_path(&action), "--tokens-file")
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        return mecmcp_runtime::token_cmd::run(action, &[], KNOWN_TOOLS)
            .map_err(|error| anyhow::anyhow!("{error}; {GRANT_TOKEN_LIFECYCLE_BLOCKER}"));
    }

    // The shared CLI retains the historic `device_mapping` spelling. Here it
    // selects the singleton Mist profile until mecmcp#91 lands.
    let config = MistConfig::from_path(&args.device_mapping)
        .with_context(|| format!("loading {}", args.device_mapping.display()))?;
    tracing::warn!("{LIVE_MIST_BLOCKER}; serving the blocked client seam");
    let handler = MistHandler::blocked(&config.endpoint, config.allowed_orgs, BTreeMap::new())
        .context("constructing blocked Mist handler")?;

    match args.transport {
        Transport::Stdio => serve_stdio(handler).await,
        Transport::StreamableHttp => {
            let token_store = load_http_token_store(&args)?;
            if let Some(store) = token_store.clone() {
                install_token_reload_handler(store)
                    .context("installing token snapshot reload handler")?;
            }
            let tls = load_listener_tls(&args)?;
            let address = SocketAddr::new(validated.host, args.port);
            serve_http(
                handler,
                address,
                token_store,
                args.allowed_host,
                args.allowed_origin,
                mecmcp_transport::LimitsConfig::default(),
                false,
                tls,
            )
            .await
        }
    }
}

fn token_store_path(action: &TokenAction) -> &std::path::Path {
    match action {
        TokenAction::Add { tokens_file, .. }
        | TokenAction::List { tokens_file }
        | TokenAction::Revoke { tokens_file, .. }
        | TokenAction::Rotate { tokens_file, .. } => tokens_file,
    }
}

fn init_audit(args: &Cli) -> Result<()> {
    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("rustmistmcp_tool_duration_seconds");
    Ok(())
}

async fn serve_stdio(handler: MistHandler) -> Result<()> {
    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("starting MCP stdio service")?;
    service
        .waiting()
        .await
        .map(|_| ())
        .context("MCP stdio service exited with error")
}

fn load_http_token_store(args: &Cli) -> Result<Option<Arc<TokenStoreFile<MistGrant>>>> {
    match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), false) => {
            let store = Arc::new(
                TokenStoreFile::<MistGrant>::load(path)
                    .with_context(|| format!("loading {}", path.display()))?,
            );
            tracing::info!(tokens = store.store().len(), "token store loaded");
            Ok(Some(store))
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts ordinary read/local metadata requests \
                 without authentication on loopback; restricted reads and mutations remain denied"
            );
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn load_listener_tls(args: &Cli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };
    let provider = rustls::crypto::ring::default_provider();
    provider
        .clone()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring crypto provider"))?;
    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
        .context("loading listener TLS")
        .map(Some)
}
