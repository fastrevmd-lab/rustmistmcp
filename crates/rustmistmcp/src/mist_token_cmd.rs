//! Temporary Mist-typed token lifecycle adapter.
//!
//! Delete this module when one coherent mecmcp revision contains both the
//! required mecmcp-server surface and token_cmd::run_with_grant.

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_runtime::{
    cli::TokenAction,
    token_cmd::{TokenCommandError, parse_provenance},
};
use rustmistmcp_core::MistGrant;
use std::{io::Write as _, path::Path};

pub(crate) fn run(action: TokenAction, known_tools: &[&str]) -> Result<(), TokenCommandError> {
    let known = KnownNames {
        devices: None,
        tools: known_tools,
    };

    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => {
            let devices = parse_scope(devices, "devices")?;
            let tools = parse_scope(tools, "tools")?;
            let provenance = parse_provenance(provider, provider_tier, on_behalf_of, actor_type)?;
            let secret = TokenStoreFile::<MistGrant>::add_with_options(
                &tokens_file,
                &name,
                devices,
                tools,
                None,
                None,
                provenance.provider,
                provenance.provider_tier,
                provenance.on_behalf_of,
                provenance.actor_type,
                &known,
            )?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)
        }
        TokenAction::List { tokens_file } => list(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::<MistGrant>::revoke(&tokens_file, &name, &known)?;
            if removed {
                eprintln!("revoked '{name}'");
            } else {
                eprintln!("no such token '{name}' (no-op)");
            }
            signal_reload(server_pid)
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let secret = TokenStoreFile::<MistGrant>::rotate(&tokens_file, &name, &known)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)
        }
    }
}

fn parse_scope(values: Vec<String>, field: &'static str) -> Result<ScopeSet, TokenCommandError> {
    if values.is_empty() {
        return Err(TokenCommandError::Scope {
            field,
            message: "at least one exact name or '*' is required".to_owned(),
        });
    }
    if values.iter().any(|value| value == "*") {
        if values.len() == 1 {
            return Ok(ScopeSet::Wildcard);
        }
        return Err(TokenCommandError::Scope {
            field,
            message: "'*' cannot be mixed with exact names".to_owned(),
        });
    }
    Ok(ScopeSet::Allowlist(values))
}

fn list(path: &Path) -> Result<(), TokenCommandError> {
    let store_file = TokenStoreFile::<MistGrant>::load(path)?;
    let store = store_file.store();
    if store.is_empty() {
        eprintln!("(no tokens)");
        return Ok(());
    }

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<32} {:<24} {:<24} CREATED_AT",
        "NAME", "DEVICES", "TOOLS"
    )?;
    for entry in store.entries() {
        let devices = match &entry.devices {
            ScopeSet::Wildcard => "*".to_owned(),
            ScopeSet::Allowlist(values) => values.join(","),
        };
        let tools = match &entry.tools {
            ScopeSet::Wildcard => "*".to_owned(),
            ScopeSet::Allowlist(values) => values.join(","),
        };
        writeln!(
            out,
            "{:<32} {:<24} {:<24} {}",
            entry.name,
            devices,
            tools,
            entry.created_at.to_rfc3339()
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    let Some(raw) = pid else {
        return Ok(());
    };
    let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server PID must be positive",
        )
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP)
        .map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    if pid.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SIGHUP reload is available only on Unix",
        )
        .into());
    }
    Ok(())
}
