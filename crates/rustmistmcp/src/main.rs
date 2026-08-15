//! HPE Juniper Mist MCP server executable.

mod cli;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use cli::{Cli, Command, Transport};
use mecmcp_auth::TokenStoreFile;
use rmcp::ServiceExt as _;
use rustmistmcp::{AuthConfig, KNOWN_TOOLS, MistHandler, install_token_reload_handler, serve_http};
use rustmistmcp_core::{MistConfig, MistGrant};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Convert to shared CLI for validation
    let shared_cli = mecmcp_runtime::cli::Cli {
        command: None, // Not checked by validate
        device_mapping: args.device_mapping.clone(),
        transport: args.transport,
        host: args.host.clone(),
        port: args.port,
        tokens_file: args.tokens_file.clone(),
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        allow_no_auth: args.allow_no_auth,
        allow_insecure_bind: args.allow_insecure_bind,
        allowed_host: args.allowed_host.clone(),
        allowed_origin: args.allowed_origin.clone(),
        audit_format: args.audit_format.clone(),
        audit_log_file: args.audit_log_file.clone(),
        audit_journald: args.audit_journald,
        audit_redact: args.audit_redact.clone(),
        audit_hmac_key_file: args.audit_hmac_key_file.clone(),
    };
    mecmcp_runtime::cli_validate::validate(&shared_cli)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    init_audit(&args)?;

    if let Some(Command::Token { action }) = args.command {
        // Management is deliberately local: it validates against the fixed
        // tool registry and neither loads Mist profile/credential data nor
        // contacts the Mist service.
        //
        // Convert our CLI's TokenAction to the runtime's version for the handler.
        let runtime_action = match action {
            cli::TokenAction::Add {
                tokens_file,
                name,
                devices,
                tools,
                provider,
                provider_tier,
                on_behalf_of,
                actor_type,
                server_pid,
            } => mecmcp_runtime::cli::TokenAction::Add {
                tokens_file,
                name,
                devices,
                tools,
                provider,
                provider_tier,
                on_behalf_of,
                actor_type,
                server_pid,
            },
            cli::TokenAction::SetScopes {
                tokens_file,
                name,
                devices,
                tools,
                yes,
                server_pid,
            } => mecmcp_runtime::cli::TokenAction::SetScopes {
                tokens_file,
                name,
                devices,
                tools,
                yes,
                server_pid,
            },
            cli::TokenAction::List { tokens_file } => {
                mecmcp_runtime::cli::TokenAction::List { tokens_file }
            }
            cli::TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            } => mecmcp_runtime::cli::TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            },
            cli::TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            } => mecmcp_runtime::cli::TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            },
        };
        return mecmcp_runtime::token_cmd::run_with_grant::<MistGrant>(
            runtime_action,
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
    let config = MistConfig::from_path(&args.device_mapping)
        .with_context(|| format!("loading {}", args.device_mapping.display()))?;

    // Construct real HTTP client when credential is available
    let handler = MistHandler::from_config_with_lab_mode(&config, BTreeMap::new(), args.lab_mode)
        .context("constructing Mist handler with HTTP client")?;
    tracing::info!(
        "Mist handler constructed with HttpMistClient for endpoint {}",
        config.endpoint
    );

    match args.transport {
        Transport::Stdio => serve_stdio(handler).await,
        Transport::StreamableHttp => {
            let auth_config = load_http_token_store(&args)?;
            if let AuthConfig::Authenticated(store) = &auth_config {
                install_token_reload_handler(store.clone())
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
                auth_config,
                args.allowed_host,
                args.allowed_origin,
                mecmcp_transport::LimitsConfig::default(),
                false,
                tls,
                args.allow_insecure_bind,
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

fn load_http_token_store(args: &Cli) -> Result<AuthConfig> {
    match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), _) => {
            let store = Arc::new(
                TokenStoreFile::<MistGrant>::load(path)
                    .with_context(|| format!("loading {}", path.display()))?,
            );
            tracing::info!(tokens = store.store().len(), "token store loaded");
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
        let args = Cli {
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
        let args = Cli {
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
