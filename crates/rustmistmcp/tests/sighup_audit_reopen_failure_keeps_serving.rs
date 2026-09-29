//! A failed SIGHUP audit reopen must not take down the server.
//!
//! Modeled on `sighup_reopens_audit_log.rs`, but the rotator here leaves the
//! path unusable (a directory in place of the file) instead of renaming it
//! cleanly, so `AuditFileSink::reopen` fails. The server must keep answering
//! requests regardless — a failed audit reopen is a `warn`-logged event, not a
//! reason to stop serving. Unix-only, like the SIGHUP mechanism itself.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use axum::http::StatusCode;
use rustmistmcp::{AuthConfig, MistHandler, build_http_router, install_audit_reopen_handler};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

fn handler() -> MistHandler {
    MistHandler::blocked(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
    )
    .expect("valid blocked handler")
}

fn sighup() {
    let pid = rustix::process::Pid::from_raw(std::process::id() as i32).expect("positive pid");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("send SIGHUP");
}

async fn post_mcp(
    client: &reqwest::Client,
    base_url: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("Mcp-Protocol-Version", "2025-06-18");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    request.json(&body).send().await.expect("protocol request")
}

async fn initialize_no_auth_session(client: &reqwest::Client, base_url: &str) -> String {
    let response = post_mcp(
        client,
        base_url,
        None,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "sighup-audit-reopen-failure", "version": "1"}
            }
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .expect("session str")
        .to_owned();
    let notification = post_mcp(
        client,
        base_url,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    session
}

async fn emit_audit_record(client: &reqwest::Client, base_url: &str, session: &str, id: i64) {
    let response = post_mcp(
        client,
        base_url,
        Some(session),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": "search_mist_operations", "arguments": {"query": "org", "limit": 1}}
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

fn wait_for_nonempty(path: &std::path::Path, deadline: Instant) {
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} never became non-empty",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[tokio::test]
async fn sighup_audit_reopen_failure_keeps_server_alive() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("temporary directory");
    let audit_path = dir.path().join("audit.jsonl");

    let sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::Json,
        audit_log_file: Some(audit_path.clone()),
        redaction: None,
        journald: false,
    })
    .expect("initializing audit tracing")
    .expect("this call installs the subscriber and configured a file sink");
    install_audit_reopen_handler(sink).expect("SIGHUP handler");

    let shutdown = tokio_util::sync::CancellationToken::new();
    let plan = build_http_router(
        handler(),
        AuthConfig::ExplicitlyUnauthenticated,
        Vec::new(),
        Vec::new(),
        mecmcp_transport::LimitsConfig::default(),
        false,
        false,
        shutdown,
    )
    .expect("HTTP router");
    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
    let base_url = format!("http://{}", served.address);
    let client = reqwest::Client::new();
    let session = initialize_no_auth_session(&client, &base_url).await;

    emit_audit_record(&client, &base_url, &session, 2).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    wait_for_nonempty(&audit_path, deadline);

    // Make the reopen fail: replace the path with a directory, so
    // `OpenOptions::create().append()` on it returns EISDIR. The server's
    // existing (now-unlinked) descriptor keeps working regardless.
    std::fs::remove_file(&audit_path).expect("remove audit file");
    std::fs::create_dir(&audit_path).expect("replace audit file with a directory");
    sighup();

    // The server must keep serving requests -- a failed audit reopen must not
    // take down the process or block other traffic.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = post_mcp(
            &client,
            &base_url,
            Some(&session),
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
        )
        .await;
        if response.status() == StatusCode::OK {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "server stopped responding after a failed audit reopen (last status {})",
            response.status()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    std::fs::remove_dir(&audit_path).expect("clean up directory stand-in");
}
