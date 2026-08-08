//! HPE Juniper Mist MCP server executable.

use anyhow::{Context as _, Result};
use clap::Parser as _;
use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::cli::{Cli, Command, Transport};
use rmcp::ServiceExt as _;
use rustmistmcp::{
    KNOWN_TOOLS, MistHandler, install_token_reload_handler, serve_http, validate_runtime_serve,
};
use rustmistmcp_core::{MistConfig, MistGrant};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    validate_runtime_serve(&args).map_err(|error| anyhow::anyhow!("{error}"))?;
    init_audit(&args)?;

    if let Some(Command::Token { action }) = args.command {
        // Management is deliberately local: it validates against the fixed
        // tool registry and neither loads Mist profile/credential data nor
        // contacts the Mist service.
        return mecmcp_runtime::token_cmd::run_with_grant::<MistGrant>(
            action,
            &[], // No known devices - Mist uses org/site targets
            KNOWN_TOOLS,
            None, // No grant for basic token operations
        )
        .map_err(|error| anyhow::anyhow!("{error}"));
    }

    // mecmcp decision D4: the consumer installs the process-global rustls crypto
    // provider, and it must be installed before ANYTHING builds a TLS-capable
    // client. This used to live inside `load_listener_tls`, which only runs when
    // --tls-cert/--tls-key are set — fine while the only TLS consumer was the
    // listener, wrong the moment the outbound Mist client became real. Without
    // it the server died at startup with "failed to construct HTTP client",
    // which the OCI smoke test caught and no unit test could.
    //
    // `install_default` errors if a provider is already set; that is a benign
    // race with anything else in-process, so it is deliberately ignored.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // The shared CLI retains the historic `device_mapping` spelling. Here it
    // selects the singleton Mist profile until mecmcp#91 lands.
    let config = MistConfig::from_path(&args.device_mapping)
        .with_context(|| format!("loading {}", args.device_mapping.display()))?;

    // Construct real HTTP client when credential is available
    let handler = MistHandler::from_config(&config, BTreeMap::new())
        .context("constructing Mist handler with HTTP client")?;
    tracing::info!(
        "Mist handler constructed with HttpMistClient for endpoint {}",
        config.endpoint
    );

    match args.transport {
        Transport::Stdio => serve_stdio(handler).await,
        Transport::StreamableHttp => {
            let token_store = load_http_token_store(&args)?;
            if let Some(store) = token_store.clone() {
                install_token_reload_handler(store)
                    .context("installing token snapshot reload handler")?;
            }
            let tls = load_listener_tls(&args)?;
            let host = args
                .host
                .parse::<std::net::IpAddr>()
                .context("invalid --host IP address")?;
            let address = SocketAddr::new(host, args.port);
            let shutdown = tokio_util::sync::CancellationToken::new();

            // Install signal handlers
            let signal_shutdown = shutdown.clone();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
                let mut sigint =
                    signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
                tokio::spawn(async move {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            tracing::info!("SIGTERM received");
                        }
                        _ = sigint.recv() => {
                            tracing::info!("SIGINT received");
                        }
                    }
                    signal_shutdown.cancel();
                });
            }
            #[cfg(not(unix))]
            {
                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("Ctrl+C received");
                    signal_shutdown.cancel();
                });
            }

            let shutdown_timeout = std::time::Duration::from_secs(10);
            serve_http(
                handler,
                address,
                token_store,
                args.allowed_host,
                args.allowed_origin,
                mecmcp_transport::LimitsConfig::default(),
                false,
                tls,
                shutdown,
                shutdown_timeout,
            )
            .await
            .map_err(anyhow::Error::from)
        }
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
    // The process-global provider is installed in `main`; do not install again —
    // `install_default` returns Err when one is already set, and treating that
    // as fatal would break every TLS start.
    let provider = rustls::crypto::ring::default_provider();
    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
        .context("loading listener TLS")
        .map(Some)
}
