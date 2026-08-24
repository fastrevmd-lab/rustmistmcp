//! HPE Juniper Mist MCP server executable.

mod cli;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use cli::{Command, MistCli, Transport};
use mecmcp_auth::TokenStoreFile;
use rmcp::ServiceExt as _;
use rustmistmcp::{AuthConfig, KNOWN_TOOLS, MistHandler, install_token_reload_handler, serve_http};
use rustmistmcp_core::{MistConfig, MistGrant};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let args = MistCli::parse();

    // Validate the flattened shared CLI
    mecmcp_runtime::cli_validate::validate(&args.shared)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    init_audit(&args)?;

    if let Some(Command::Token { action }) = args.shared.command {
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

    // Lab mode removes two-person control, so say so where an operator will
    // actually see it. Reading it off flags typed weeks ago is not visibility.
    if args.lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets are approved on creation with no second \
             principal. Records carry approval_waiver=lab-mode. Do not run this against \
             production devices."
        );
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
    let config = MistConfig::from_path(&args.shared.device_mapping)
        .with_context(|| format!("loading {}", args.shared.device_mapping.display()))?;

    // Construct real HTTP client when credential is available
    // Built before the handler because its coordinator takes the recorder, and
    // started eagerly so a misconfiguration stops the server here rather than
    // at the first change.
    let evidence = match args.shared.evidence.into_config() {
        Ok(Some(evidence_config)) => {
            tracing::info!(
                server_id = %evidence_config.server_id,
                run_id = %evidence_config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let transport = std::sync::Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.shared.evidence.ca_file(),
                    provider,
                )
                .map_err(|error| {
                    anyhow::anyhow!("building the SSDF evidence transport: {error}")
                })?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(evidence_config, transport)
                    .map_err(|error| {
                        anyhow::anyhow!("starting the SSDF evidence pipeline: {error}")
                    })?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };

    let handler = MistHandler::from_config_with_lab_mode(
        &config,
        BTreeMap::new(),
        args.lab_mode,
        evidence
            .as_ref()
            .map(mecmcp_audit::EvidenceService::recorder),
    )
    .context("constructing Mist handler with HTTP client")?;
    tracing::info!(
        "Mist handler constructed with HttpMistClient for endpoint {}",
        config.endpoint
    );

    let served = match args.shared.transport {
        Transport::Stdio => serve_stdio(handler).await,
        Transport::StreamableHttp => {
            let auth_config = load_http_token_store(&args)?;
            if let AuthConfig::Authenticated(store) = &auth_config {
                install_token_reload_handler(store.clone())
                    .context("installing token snapshot reload handler")?;
            }
            let tls = load_listener_tls(&args)?;
            let host = args
                .shared
                .host
                .parse::<std::net::IpAddr>()
                .context("invalid --host IP address")?;
            let address = SocketAddr::new(host, args.shared.port);
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
                auth_config,
                args.shared.allowed_host,
                args.shared.allowed_origin,
                mecmcp_transport::LimitsConfig::default(),
                false,
                tls,
                args.shared.allow_insecure_bind,
                shutdown,
                shutdown_timeout,
            )
            .await
            .map_err(anyhow::Error::from)
        }
    };

    // Deliver what is still spooled before leaving, whichever way serving
    // ended. Bound rather than returned directly so the flush runs even when
    // the transport returned an error -- that is exactly when the trail matters.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

fn init_audit(args: &MistCli) -> Result<()> {
    let redaction = if args.shared.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.shared.audit_redact,
                args.shared.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.shared.audit_format),
        audit_log_file: args.shared.audit_log_file.clone(),
        redaction,
        journald: args.shared.audit_journald,
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

fn load_http_token_store(args: &MistCli) -> Result<AuthConfig> {
    match (&args.shared.tokens_file, args.shared.allow_no_auth) {
        (Some(path), _) => {
            // Issue #42: resolve between primary (/var/lib) and fallback (/etc)
            // paths to support upgrades without locking out existing clients.
            // The primary path is always /var/lib/rustmistmcp/tokens.json per
            // mecmcp/docs/FILESYSTEM-LAYOUT.md; the CLI path acts as fallback.
            let primary = std::path::PathBuf::from("/var/lib/rustmistmcp/tokens.json");
            let resolved = mecmcp_auth::resolve_token_path(&primary, path).with_context(|| {
                format!(
                    "resolving token path (primary: {}, fallback: {})",
                    primary.display(),
                    path.display()
                )
            })?;

            if resolved.used_fallback {
                tracing::warn!(
                    primary = %primary.display(),
                    fallback = %path.display(),
                    "tokens.json: primary path not found, using fallback from --tokens-file. \
                     Upgraded servers should migrate tokens to /var/lib/rustmistmcp/tokens.json \
                     and update the systemd override."
                );
            }

            let store = Arc::new(
                TokenStoreFile::<MistGrant>::load(&resolved.path)
                    .with_context(|| format!("loading {}", resolved.path.display()))?,
            );
            tracing::info!(
                path = %resolved.path.display(),
                tokens = store.store().len(),
                "token store loaded"
            );

            // Issue #43: warn about stale secrets alongside the live token file
            warn_about_stale_secrets(&resolved.path)?;

            Ok(AuthConfig::Authenticated(store))
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts ordinary read/local metadata requests \
                 without authentication on loopback; restricted reads and mutations remain denied"
            );
            Ok(AuthConfig::ExplicitlyUnauthenticated)
        }
        (None, false) => {
            anyhow::bail!(
                "HTTP transport requires either --tokens-file or --allow-no-auth; \
                 refusing to serve unauthenticated without explicit acknowledgement"
            )
        }
    }
}

/// Detect and warn about superseded token files alongside the live one.
///
/// Issue #43: root-owned superseded token files bypass permission checks and
/// accumulate revoked credentials. Warn only — deletion is a production
/// change-window task.
fn warn_about_stale_secrets(live_path: &std::path::Path) -> Result<()> {
    let parent = live_path
        .parent()
        .context("token file must have a parent directory")?;

    let live_file_name = live_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("token file must have a valid filename")?;

    let stale = mecmcp_auth::find_stale_secrets(parent, &[live_file_name]);
    if !stale.is_empty() {
        tracing::warn!(
            count = stale.len(),
            directory = %parent.display(),
            "found stale secret files — these may contain revoked credentials and \
             should be deleted after confirming the live file carries all active tokens"
        );
        for item in &stale {
            tracing::warn!(
                path = %item.path.display(),
                reason = ?item.reason,
                "stale secret detected"
            );
        }
    }
    Ok(())
}

fn load_listener_tls(args: &MistCli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let (Some(cert), Some(key)) = (&args.shared.tls_cert, &args.shared.tls_key) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_runtime::cli::Transport;
    use std::path::PathBuf;

    /// Verify that the (None, false) case — neither --tokens-file nor
    /// --allow-no-auth — is refused at startup rather than silently serving
    /// unauthenticated.
    #[test]
    fn none_false_refuses_to_serve_unauthenticated() {
        let args = MistCli {
            shared: mecmcp_runtime::cli::Cli {
                evidence: mecmcp_runtime::cli::EvidenceArgs::default(),
                transport: Transport::StreamableHttp,
                host: "127.0.0.1".to_owned(),
                port: 8080,
                tokens_file: None,
                allow_no_auth: false,
                allowed_host: vec![],
                allowed_origin: vec![],
                allow_insecure_bind: false,
                tls_cert: None,
                tls_key: None,
                device_mapping: PathBuf::from("/dev/null"),
                audit_format: String::new(),
                audit_redact: String::new(),
                audit_log_file: None,
                audit_hmac_key_file: None,
                audit_journald: false,
                command: None,
            },
            state_file: PathBuf::from("/dev/null/changeset-state.json"),
            approval_timeout_secs: 3600,
            lab_mode: false,
            web_approver: Default::default(),
        };

        let result = load_http_token_store(&args);
        assert!(
            result.is_err(),
            "load_http_token_store must refuse (None, false) with an error"
        );
        let error = result
            .expect_err("(None, false) must be refused")
            .to_string();
        assert!(
            error.contains("requires either --tokens-file or --allow-no-auth"),
            "error message should explain the requirement, got: {error}"
        );
    }

    /// Verify that --allow-no-auth explicitly permits unauthenticated serving.
    #[test]
    fn explicit_no_auth_is_permitted() {
        let args = MistCli {
            shared: mecmcp_runtime::cli::Cli {
                evidence: mecmcp_runtime::cli::EvidenceArgs::default(),
                transport: Transport::StreamableHttp,
                host: "127.0.0.1".to_owned(),
                port: 8080,
                tokens_file: None,
                allow_no_auth: true,
                allowed_host: vec![],
                allowed_origin: vec![],
                allow_insecure_bind: false,
                tls_cert: None,
                tls_key: None,
                device_mapping: PathBuf::from("/dev/null"),
                audit_format: String::new(),
                audit_redact: String::new(),
                audit_log_file: None,
                audit_hmac_key_file: None,
                audit_journald: false,
                command: None,
            },
            state_file: PathBuf::from("/dev/null/changeset-state.json"),
            approval_timeout_secs: 3600,
            lab_mode: false,
            web_approver: Default::default(),
        };

        let result = load_http_token_store(&args);
        assert!(
            result.is_ok(),
            "load_http_token_store must permit explicit --allow-no-auth"
        );
        assert!(
            matches!(
                result.expect("--allow-no-auth must yield an explicit acknowledgement"),
                AuthConfig::ExplicitlyUnauthenticated
            ),
            "result should be ExplicitlyUnauthenticated"
        );
    }
}
