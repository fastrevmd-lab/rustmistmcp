//! SIGHUP audit log reopen.
//!
//! Verifies that sending SIGHUP to a running server with `--audit-log-file`
//! configured reopens the sink in place: a rename-then-signal rotation loses
//! nothing written before the rename and routes everything written after it
//! to the fresh inode at the same path. Unix-only, like the SIGHUP mechanism
//! itself.
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
                "clientInfo": {"name": "sighup-audit-reopen", "version": "1"}
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

/// Call a tool that emits exactly one `target="audit"` transport event.
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

fn wait_for_nonempty(path: &std::path::Path, deadline: Instant) -> String {
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
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
async fn sighup_reopens_audit_log_after_rename() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("temporary directory");
    let audit_path = dir.path().join("audit.jsonl");

    let sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::Json,
        audit_log_file: Some(audit_path.clone()),
        redaction: None,
        journald: false,
        otel: None,
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

    // First record lands in the original inode.
    emit_audit_record(&client, &base_url, &session, 2).await;
    let deadline = Instant::now() + Duration::from_secs(15);
    let before = wait_for_nonempty(&audit_path, deadline);
    assert!(
        before.contains("search_mist_operations"),
        "audit file missing first record: {before}"
    );

    // Rotate the way logrotate's rename-mode fragment does: move the file
    // aside, then signal the process.
    let rotated = dir.path().join("audit.jsonl.1");
    std::fs::rename(&audit_path, &rotated).expect("rotate audit file");
    sighup();

    // Second record must land at the same path, in a fresh inode, once the
    // reopen has completed. Poll rather than sleep a fixed amount: the
    // reopen races the SIGHUP delivery and this keeps the happy path fast.
    // The deadline is generous because the reopen runs on the tokio runtime's
    // signal task, which can be delayed well past typical scheduling latency
    // when the host is under heavy concurrent load (e.g. a full workspace
    // test run), not just by the signal/reopen work itself.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        emit_audit_record(&client, &base_url, &session, 3).await;
        if let Ok(contents) = std::fs::read_to_string(&audit_path)
            && contents.contains("search_mist_operations")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second record never appeared at {} within 15s after SIGHUP",
            audit_path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let rotated_contents = std::fs::read_to_string(&rotated).expect("read rotated file");
    assert_eq!(
        rotated_contents, before,
        "the rotated-away file must keep exactly what was written before the rename, losing nothing"
    );
}
