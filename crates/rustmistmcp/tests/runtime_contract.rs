//! Runtime composition contracts for the Mist MCP binary.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use clap::Parser as _;
use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_runtime::{
    cli::{Cli, Transport},
    cli_validate::CliRefusal,
};
use mecmcp_transport::{CallerScopes, LimitsConfig, ScopePreflight as _};
use rustmistmcp::{
    KNOWN_TOOLS, LIVE_MIST_BLOCKER, MistHandler, MistScopePreflight, RESTRICTED_TOOLS,
    build_http_router, install_token_reload_handler, validate_runtime_serve,
};
use rustmistmcp_core::{MistConfig, MistGrant};
use std::{collections::BTreeMap, fs, process::Command, sync::Arc, time::Duration};
use tower::ServiceExt as _;

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const OTHER_ORG_ID: &str = "99999999-9999-9999-9999-999999999999";

fn parse_cli(args: &[&str]) -> Cli {
    Cli::parse_from(std::iter::once("rustmistmcp").chain(args.iter().copied()))
}

fn handler() -> MistHandler {
    MistHandler::blocked(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
    )
    .expect("valid blocked handler")
}

#[test]
fn remote_listener_requires_explicit_host_and_origin_policies() {
    let missing_host = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
    ]);
    assert_eq!(
        validate_runtime_serve(&missing_host),
        Err(CliRefusal::AllowedHostRequired)
    );

    let missing_origin = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
        "--allowed-host",
        "mist.example.test",
    ]);
    assert_eq!(
        validate_runtime_serve(&missing_origin),
        Err(CliRefusal::AllowedOriginRequired)
    );

    let strict_remote = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
        "--allowed-host",
        "mist.example.test",
        "--allowed-origin",
        "https://client.example.test",
    ]);
    let validated = validate_runtime_serve(&strict_remote).expect("strict remote listener");
    assert_eq!(validated.host.to_string(), "0.0.0.0");
    assert!(!validated.tls);
}

#[test]
fn listener_validation_preserves_shared_tls_and_absolute_path_refusals() {
    let relative_tokens = parse_cli(&[
        "--transport",
        "streamable-http",
        "--tokens-file",
        "tokens.json",
    ]);
    assert_eq!(
        validate_runtime_serve(&relative_tokens),
        Err(CliRefusal::AbsolutePathRequired {
            flag: "--tokens-file"
        })
    );

    let incomplete_tls = parse_cli(&[
        "--transport",
        "streamable-http",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--tls-cert",
        "/etc/rustmistmcp/tls/cert.pem",
    ]);
    assert!(matches!(
        validate_runtime_serve(&incomplete_tls),
        Err(CliRefusal::TlsPairIncomplete { .. })
    ));
}

#[test]
fn mist_preflight_translates_org_and_site_arguments_to_canonical_targets() {
    let preflight = MistScopePreflight::new(RESTRICTED_TOOLS);
    let target = format!("org/{ORG_ID}");
    let devices = ScopeSet::Allowlist(vec![target]);
    let tools = ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]);
    let caller = CallerScopes {
        token_name: "operator",
        devices: &devices,
        tools: &tools,
    };
    let permitted = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_mist_org",
            "arguments": {"org_id": ORG_ID}
        }
    });
    preflight
        .check(&serde_json::to_vec(&permitted).expect("request"), caller)
        .expect("canonical org scope permits raw org argument");

    let denied = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "get_mist_org",
            "arguments": {"org_id": OTHER_ORG_ID}
        }
    });
    assert_eq!(
        preflight.check(&serde_json::to_vec(&denied).expect("request"), caller),
        Err("insufficient_scope".to_owned())
    );

    let dispatcher_tools = ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]);
    let dispatcher_caller = CallerScopes {
        token_name: "dispatcher",
        devices: &devices,
        tools: &dispatcher_tools,
    };
    let nested_path_denied = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "invoke_mist_read",
            "arguments": {
                "operation_id": "getOrg",
                "path": {"org_id": OTHER_ORG_ID},
                "query": {}
            }
        }
    });
    assert_eq!(
        preflight.check(
            &serde_json::to_vec(&nested_path_denied).expect("request"),
            dispatcher_caller
        ),
        Err("insufficient_scope".to_owned())
    );
}

#[test]
fn wildcard_tool_scope_excludes_restricted_reads_at_preflight() {
    let preflight = MistScopePreflight::new(RESTRICTED_TOOLS);
    let devices = ScopeSet::Wildcard;
    let tools = ScopeSet::Wildcard;
    let caller = CallerScopes {
        token_name: "readonly-wildcard",
        devices: &devices,
        tools: &tools,
    };
    let restricted = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get_mist_self", "arguments": {}}
    });
    assert_eq!(
        preflight.check(&serde_json::to_vec(&restricted).expect("request"), caller),
        Err("insufficient_scope".to_owned())
    );
}

#[tokio::test]
async fn authenticated_router_uses_strict_bearer_syntax_and_scope_preflight() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("tokens.json");
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::<MistGrant>::add(
        &path,
        "operator",
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("token");
    let store = Arc::new(TokenStoreFile::<MistGrant>::load(&path).expect("token store"));
    let router = build_http_router(
        handler(),
        Some(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
    )
    .expect("HTTP router");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_mist_org",
            "arguments": {"org_id": OTHER_ORG_ID}
        }
    })
    .to_string();

    let missing = router
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::HOST, "localhost")
                .body(Body::from(body.clone()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let malformed = router
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::HOST, "localhost")
                .header(
                    header::AUTHORIZATION,
                    format!(" Bearer {}", secret.expose_secret()),
                )
                .body(Body::from(body.clone()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);

    let out_of_scope = router
        .oneshot(
            Request::post("/mcp")
                .header(header::HOST, "localhost")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", secret.expose_secret()),
                )
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(out_of_scope.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        out_of_scope
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("challenge"),
        r#"Bearer realm="rustmistmcp", error="insufficient_scope""#
    );
}

#[tokio::test]
async fn unauthenticated_loopback_router_has_no_bearer_boundary() {
    let router = build_http_router(
        handler(),
        None,
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
    )
    .expect("HTTP router");
    let response = router
        .oneshot(
            Request::post("/mcp")
                .header(header::HOST, "localhost")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn token_add_is_local_and_its_file_loads_as_a_mist_grant_store() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let missing_config = dir.path().join("must-not-be-read.json");
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "--device-mapping",
            missing_config.to_str().expect("UTF-8 path"),
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "local-operator",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty(), "one-time secret is printed");
    assert!(!missing_config.exists(), "Mist config was not contacted");

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("Mist grant token store");
    assert_eq!(store.store().len(), 1);
    assert_eq!(
        store.store().entries()[0].devices,
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")])
    );
}

#[test]
fn token_management_requires_an_absolute_store_path() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .current_dir(dir.path())
        .args([
            "token",
            "add",
            "--tokens-file",
            "tokens.json",
            "--name",
            "relative-path",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token command");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--tokens-file path must be absolute")
    );
    assert!(!dir.path().join("tokens.json").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_only_a_valid_token_snapshot() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("tokens.json");
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add(
        &path,
        "first",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("first token");
    let store = Arc::new(TokenStoreFile::<MistGrant>::load(&path).expect("token store"));
    install_token_reload_handler(store.clone()).expect("SIGHUP handler");

    TokenStoreFile::<MistGrant>::add(
        &path,
        "second",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("second token");
    send_hup();
    wait_for_store_len(&store, 2).await;

    fs::write(&path, b"{not valid json").expect("corrupt token file");
    send_hup();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        store.store().len(),
        2,
        "failed reload retains the last valid snapshot"
    );
}

#[cfg(unix)]
fn send_hup() {
    let pid = rustix::process::Pid::from_raw(std::process::id() as i32).expect("positive pid");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("send SIGHUP");
}

#[cfg(unix)]
async fn wait_for_store_len(store: &TokenStoreFile<MistGrant>, expected: usize) {
    for _ in 0..50 {
        if store.store().len() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("token snapshot did not reload to {expected} entries");
}

#[test]
fn example_uses_absolute_operator_paths_and_runtime_is_honest_about_blockers() {
    let raw = include_str!("../../../examples/mist.example.json");
    let config: MistConfig = serde_json::from_str(raw).expect("strict example schema");
    assert_eq!(config.version, 1);
    assert!(config.credential_file.is_absolute());
    assert_eq!(
        config.credential_file.to_string_lossy(),
        "/etc/rustmistmcp/mist-api-token"
    );
    assert!(LIVE_MIST_BLOCKER.contains("mecmcp#90"));
    assert!(LIVE_MIST_BLOCKER.contains("/api/v1/self"));
    assert!(
        !KNOWN_TOOLS
            .iter()
            .any(|tool| tool.contains("change") || tool.contains("apply"))
    );
}

#[test]
fn binary_help_preserves_the_shared_runtime_flag_names() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for flag in [
        "--device-mapping",
        "--transport",
        "--tokens-file",
        "--tls-cert",
        "--tls-key",
        "--allowed-host",
        "--allowed-origin",
        "--audit-journald",
    ] {
        assert!(help.contains(flag), "missing shared flag {flag}");
    }
    assert!(help.contains("streamable-http"));
    assert_eq!(parse_cli(&[]).transport, Transport::Stdio);
}
