//! Integration contracts for the collapsed WAN edge tools.
//!
//! These drive the real tool router and assert which catalog operation each
//! selector combination resolved to. A unit test of the resolver alone cannot
//! prove the tool is wired to it.

use async_trait::async_trait;
use rmcp::{ServiceExt, model::CallToolRequestParams};
use rustmistmcp::MistHandler;
use rustmistmcp_core::{MistClient, MistError, MistRequest, MistResponse, MistResponseBody};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_ID: &str = "22222222-2222-2222-2222-222222222222";

fn site_map() -> BTreeMap<String, String> {
    BTreeMap::from([(SITE_ID.to_owned(), ORG_ID.to_owned())])
}

#[derive(Default)]
struct RecordingClient {
    requests: Mutex<Vec<MistRequest>>,
}

#[async_trait]
impl MistClient for RecordingClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.requests
            .lock()
            .expect("request recorder")
            .push(request.clone());
        let body = match request.operation_id.as_str() {
            "searchOrgDevices" | "searchSiteDevices" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            _ => serde_json::json!({"results": []}),
        };
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(body),
            cursor: None,
        })
    }
}

/// Call one tool against a recording client and return the request it issued.
async fn record_call(tool: &str, arguments: serde_json::Value) -> Result<MistRequest, String> {
    let recorder = Arc::new(RecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let result = client
        .call_tool(
            CallToolRequestParams::new(tool.to_owned())
                .with_arguments(serde_json::from_value(arguments).expect("arguments")),
        )
        .await;
    client.cancel().await.expect("client shutdown");
    server_task.abort();

    let result = result.map_err(|error| error.to_string())?;
    if result.is_error == Some(true) {
        return Err("tool returned is_error=true".to_owned());
    }
    let requests = recorder.requests.lock().expect("lock");
    requests
        .first()
        .cloned()
        .ok_or_else(|| "no request issued".to_owned())
}

#[tokio::test]
async fn wan_edges_resolves_scope_and_forces_gateway_type() {
    let org = record_call("list_mist_wan_edges", serde_json::json!({"org_id": ORG_ID}))
        .await
        .expect("org call");
    assert_eq!(org.operation_id, "searchOrgDevices");
    assert_eq!(org.query.get("type"), Some(&serde_json::json!("gateway")));

    let site = record_call(
        "list_mist_wan_edges",
        serde_json::json!({"site_id": SITE_ID}),
    )
    .await
    .expect("site call");
    assert_eq!(site.operation_id, "searchSiteDevices");
    assert_eq!(site.query.get("type"), Some(&serde_json::json!("gateway")));
}

#[tokio::test]
async fn wan_edges_rejects_caller_supplied_type_and_ambiguous_scope() {
    let overridden = record_call(
        "list_mist_wan_edges",
        serde_json::json!({"org_id": ORG_ID, "type": "ap"}),
    )
    .await;
    assert!(overridden.is_err(), "type must not be caller-supplied");

    let both = record_call(
        "list_mist_wan_edges",
        serde_json::json!({"org_id": ORG_ID, "site_id": SITE_ID}),
    )
    .await;
    assert!(both.is_err(), "both scopes must be refused");

    let neither = record_call("list_mist_wan_edges", serde_json::json!({})).await;
    assert!(neither.is_err(), "missing scope must be refused");
}
