//! Runtime composition contracts for the Mist MCP binary.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderValue, Request, Response, StatusCode, header},
};
use clap::Parser as _;
use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Transport};
use mecmcp_transport::{CallerScopes, LimitsConfig, ScopePreflight as _};
use rustmistmcp::{
    KNOWN_TOOLS, LIVE_MIST_BLOCKER, MistHandler, MistScopePreflight, RESTRICTED_TOOLS,
    build_http_router, install_token_reload_handler, validate_runtime_serve,
};
use rustmistmcp_core::{MistAction, MistConfig, MistGrant, MistTarget};
use std::{collections::BTreeMap, fs, path::Path, process::Command, sync::Arc, time::Duration};
use tower::ServiceExt as _;

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const OTHER_ORG_ID: &str = "99999999-9999-9999-9999-999999999999";

#[test]
fn upstream_token_commands_now_used() {
    // The mist_token_cmd.rs adapter was deleted per the migration task
    assert!(!Path::new("crates/rustmistmcp/src/mist_token_cmd.rs").exists());
}

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

fn privileged_grant() -> MistGrant {
    MistGrant {
        allowed_operations: vec!["getSelf".to_owned()],
        actions: vec![MistAction::PrivilegedRead],
        subjects: vec![MistTarget::org(ORG_ID).expect("target")],
    }
}

fn add_grant_bearing_token(path: &Path, name: &str, grant: MistGrant) {
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add_with_options(
        path,
        name,
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_self".to_owned()]),
        None,
        Some(grant),
        None,
        None,
        None,
        None,
        &known,
    )
    .expect("grant-bearing token");
}

async fn post_mcp(
    router: &Router,
    session: Option<&HeaderValue>,
    body: serde_json::Value,
) -> Response<Body> {
    let mut request = Request::post("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-06-18");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    router
        .clone()
        .oneshot(
            request
                .body(Body::from(body.to_string()))
                .expect("protocol request"),
        )
        .await
        .expect("protocol response")
}

async fn response_json(response: Response<Body>) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded response body");
    let text = String::from_utf8(bytes.to_vec()).expect("UTF-8 response");
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .find(|value: &serde_json::Value| value.get("id").is_some())
        .unwrap_or_else(|| panic!("missing JSON-RPC response in {text}"))
}

async fn initialize_no_auth_session(router: &Router) -> HeaderValue {
    let response = post_mcp(
        router,
        None,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "runtime-contract", "version": "1"}
            }
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .clone();
    let initialized = response_json(response).await;
    assert_eq!(initialized["id"], 1);

    let notification = post_mcp(
        router,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    )
    .await;
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    session
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
    ]);
    assert!(
        validate_runtime_serve(&missing_host).is_err(),
        "should reject missing --allowed-host"
    );

    let missing_origin = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allowed-host",
        "mist.example.test",
    ]);
    assert!(
        validate_runtime_serve(&missing_origin).is_err(),
        "should reject missing --allowed-origin"
    );

    let strict_remote = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allowed-host",
        "mist.example.test",
        "--allowed-origin",
        "https://client.example.test",
    ]);
    validate_runtime_serve(&strict_remote).expect("strict remote listener");

    // Loopback listeners bypass the requirement
    let loopback = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
    ]);
    validate_runtime_serve(&loopback).expect("loopback listener");
}

#[test]
fn listener_validation_allows_insecure_bind_bypass() {
    let insecure_bind = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
    ]);
    validate_runtime_serve(&insecure_bind).expect("allow-insecure-bind bypasses Host/Origin check");
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
        .check(
            &serde_json::to_vec(&permitted).expect("request"),
            caller.clone(),
        )
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
        preflight.check(
            &serde_json::to_vec(&denied).expect("request"),
            caller.clone()
        ),
        Err("insufficient_scope".to_owned())
    );

    let site_devices =
        ScopeSet::Allowlist(vec!["site/22222222-2222-2222-2222-222222222222".to_owned()]);
    let site_tools = ScopeSet::Allowlist(vec!["get_mist_site".to_owned()]);
    let site_caller = CallerScopes {
        token_name: "site-operator",
        devices: &site_devices,
        tools: &site_tools,
    };
    let permitted_site = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_mist_site",
            "arguments": {"site_id": "22222222-2222-2222-2222-222222222222"}
        }
    });
    preflight
        .check(
            &serde_json::to_vec(&permitted_site).expect("request"),
            site_caller.clone(),
        )
        .expect("canonical site scope permits raw site argument");
    let denied_site = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_mist_site",
            "arguments": {"site_id": "33333333-3333-3333-3333-333333333333"}
        }
    });
    assert_eq!(
        preflight.check(
            &serde_json::to_vec(&denied_site).expect("request"),
            site_caller.clone()
        ),
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
        "id": 5,
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
        preflight.check(
            &serde_json::to_vec(&restricted).expect("request"),
            caller.clone()
        ),
        Err("insufficient_scope".to_owned())
    );
}

#[test]
fn mist_preflight_denies_every_malformed_org_and_site_shape() {
    let preflight = MistScopePreflight::new(RESTRICTED_TOOLS);
    let devices = ScopeSet::Allowlist(vec!["site/22222222-2222-2222-2222-222222222222".to_owned()]);
    let tools = ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]);
    let caller = CallerScopes {
        token_name: "malformed-targets",
        devices: &devices,
        tools: &tools,
    };
    let malformed_arguments = [
        serde_json::json!([]),
        serde_json::json!({"path": []}),
        serde_json::json!({"query": 7}),
        serde_json::json!({"org_id": 7}),
        serde_json::json!({"org_id": "not-a-uuid"}),
        serde_json::json!({"site_id": false}),
        serde_json::json!({"site_id": "33333333-3333-3333-3333-333333333333"}),
        serde_json::json!({"path": {"site_id": "not-a-uuid"}}),
        serde_json::json!({"query": {"site_id": ["not", "scalar"]}}),
    ];
    for arguments in malformed_arguments {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke_mist_read",
                "arguments": arguments
            }
        });
        assert_eq!(
            preflight.check(
                &serde_json::to_vec(&request).expect("request"),
                caller.clone()
            ),
            Err("insufficient_scope".to_owned()),
            "{request}"
        );
    }
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
    let shutdown = tokio_util::sync::CancellationToken::new();
    let (router, _shutdown_token) = build_http_router(
        handler(),
        Some(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        shutdown,
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
async fn unauthenticated_loopback_http_exposes_only_ordinary_tools_and_denies_restricted_calls() {
    let shutdown = tokio_util::sync::CancellationToken::new();
    let (router, _shutdown_token) = build_http_router(
        handler(),
        None,
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        shutdown,
    )
    .expect("HTTP router");
    let session = initialize_no_auth_session(&router).await;

    let list = response_json(
        post_mcp(
            &router,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        )
        .await,
    )
    .await;
    let names = list["result"]["tools"]
        .as_array()
        .expect("tool list")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"invoke_mist_read"));
    for restricted in RESTRICTED_TOOLS {
        assert!(!names.contains(restricted), "{restricted} must be hidden");
    }

    let ordinary = response_json(
        post_mcp(
            &router,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "search_mist_operations",
                    "arguments": {"query": "org", "limit": 1}
                }
            }),
        )
        .await,
    )
    .await;
    assert_ne!(ordinary["result"]["isError"], true, "{ordinary}");

    let restricted = response_json(
        post_mcp(
            &router,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "get_mist_self", "arguments": {}}
            }),
        )
        .await,
    )
    .await;
    assert_eq!(restricted["result"]["isError"], true, "{restricted}");
    assert!(
        restricted
            .to_string()
            .contains("authenticated caller context"),
        "{restricted}"
    );
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

    let listed = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("list grantless store");
    assert!(
        listed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("local-operator"));
}

#[test]
fn token_management_accepts_relative_paths_per_upstream() {
    // `token_cmd::run_with_grant` accepts relative paths. Path validation is
    // mecmcp's responsibility now, so this asserts the upstream behaviour
    // rather than one upstream version's behaviour.
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
    assert!(
        output.status.success(),
        "token add should succeed with a relative path, per upstream mecmcp"
    );
    assert!(dir.path().join("tokens.json").exists());
}

#[test]
fn grant_bearing_token_lifecycle_preserves_mist_authority() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let grant = privileged_grant();
    add_grant_bearing_token(&tokens, "privileged", grant.clone());
    add_grant_bearing_token(&tokens, "survivor", grant.clone());

    let listed = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run token list");
    assert!(
        listed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("privileged"), "{stdout}");
    assert!(stdout.contains("survivor"), "{stdout}");
    assert!(!stdout.contains("allowed_operations"), "{stdout}");

    let before = TokenStoreFile::<MistGrant>::load(&tokens).expect("token store");
    let before_digest = before
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token")
        .digest
        .clone();

    let rotated = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "rotate",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "privileged",
        ])
        .output()
        .expect("run token rotate");
    assert!(
        rotated.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert!(!rotated.stdout.is_empty(), "rotated secret is printed once");

    let after_rotate = TokenStoreFile::<MistGrant>::load(&tokens).expect("rotated token store");
    let after_rotate_store = after_rotate.store();
    let privileged = after_rotate_store
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token");
    assert_ne!(privileged.digest, before_digest);
    assert_eq!(privileged.grant, Some(grant.clone()));

    let revoked = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "revoke",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "privileged",
        ])
        .output()
        .expect("run token revoke");
    assert!(
        revoked.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );

    let after_revoke = TokenStoreFile::<MistGrant>::load(&tokens).expect("revoked token store");
    assert!(
        after_revoke
            .store()
            .entries()
            .iter()
            .all(|entry| entry.name != "privileged")
    );
    let after_revoke_store = after_revoke.store();
    let survivor = after_revoke_store
        .entries()
        .iter()
        .find(|entry| entry.name == "survivor")
        .expect("surviving token");
    assert_eq!(survivor.grant, Some(grant));
}

#[test]
fn token_add_to_grant_bearing_store_preserves_existing_grant() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let grant = privileged_grant();
    add_grant_bearing_token(&tokens, "privileged", grant.clone());

    let added = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "ordinary-reader",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token add");
    assert!(
        added.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(!added.stdout.is_empty(), "one-time secret is printed");

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("token store");
    let token_store = store.store();
    let privileged = token_store
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token");
    let ordinary = token_store
        .entries()
        .iter()
        .find(|entry| entry.name == "ordinary-reader")
        .expect("ordinary token");
    assert_eq!(privileged.grant, Some(grant));
    assert_eq!(ordinary.grant, None);
}

#[test]
fn unknown_mist_grant_field_is_refused_without_rewrite() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    add_grant_bearing_token(&tokens, "privileged", privileged_grant());

    let raw = fs::read_to_string(&tokens).expect("token document");
    let mut document: serde_json::Value = serde_json::from_str(&raw).expect("token document JSON");
    document["tokens"][0]["grant"]
        .as_object_mut()
        .expect("grant object")
        .insert(
            "future_restriction".to_owned(),
            serde_json::json!({"maximum_targets": 1}),
        );
    let doctored = serde_json::to_string_pretty(&document).expect("doctored JSON");
    fs::write(&tokens, &doctored).expect("write doctored token document");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run token list");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field"), "{stderr}");
    assert!(stderr.contains("future_restriction"), "{stderr}");
    assert_eq!(
        fs::read_to_string(&tokens).expect("unchanged token document"),
        doctored
    );
}

#[cfg(unix)]
#[test]
fn invalid_token_reload_pid_preserves_shared_post_write_behavior() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "written-before-signal",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
            "--server-pid",
            "0",
        ])
        .output()
        .expect("run token add");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("server PID must be positive"));

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("written token store");
    assert!(
        store
            .store()
            .entries()
            .iter()
            .any(|entry| entry.name == "written-before-signal"),
        "the shared contract writes atomically before requesting reload"
    );
}

#[test]
fn token_adapter_preserves_shared_wildcard_scope_refusal() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let mixed = format!("*,org/{ORG_ID}");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "mixed-scope",
            "--devices",
            &mixed,
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token add");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invalid devices scope: '*' cannot be mixed with exact names")
    );
    assert!(!tokens.exists());
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
    // The blocker names the credential, not `mecmcp#90` — that foundation
    // landed, and citing a closed issue would misreport why a call refused.
    assert!(!LIVE_MIST_BLOCKER.contains("mecmcp#90"));
    assert!(LIVE_MIST_BLOCKER.contains("credential"));
    assert!(LIVE_MIST_BLOCKER.contains("/api/v1/self"));
    // Change-set write tools now exist (plan_mist_change and its apply path),
    // even though mecmcp#90 (live outbound Mist client) remains open. The
    // coordinator-gated lifecycle works without a production Mist client.
    assert!(KNOWN_TOOLS.contains(&"plan_mist_change"));
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

#[test]
fn binary_reports_its_own_name_and_version() {
    // The shared `Cli` carries no version of its own, so parsing it directly
    // made `--version` exit 2. `cli::parse_for` supplies the consumer's
    // identity; release verification used to need hashes because of that gap.
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(
        output.status.success(),
        "--version exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let reported = String::from_utf8(output.stdout).expect("UTF-8 version");
    assert!(
        reported.contains("rustmistmcp"),
        "--version must name the binary, got {reported:?}"
    );
    assert!(
        reported.contains(env!("CARGO_PKG_VERSION")),
        "--version must report {}, got {reported:?}",
        env!("CARGO_PKG_VERSION")
    );
}
