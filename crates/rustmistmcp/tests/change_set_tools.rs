//! Lifecycle contracts for the Mist change-set write tools.
//!
//! These drive the real tool router. A test that constructs a prepared write
//! directly cannot see whether `plan_mist_change` actually read the object it
//! claims to have fingerprinted — which is exactly how a sibling server shipped
//! a digest bound to `Value::Null` while its audit record advertised a
//! digest-bound change set that had passed two-person approval.

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
const NETWORK_ID: &str = "33333333-3333-3333-3333-333333333333";

fn site_map() -> BTreeMap<String, String> {
    BTreeMap::from([(SITE_ID.to_owned(), ORG_ID.to_owned())])
}

/// A client that answers reads from a settable object and records every request.
struct ScriptedClient {
    requests: Mutex<Vec<MistRequest>>,
    object: Mutex<serde_json::Value>,
}

impl ScriptedClient {
    fn new(object: serde_json::Value) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            object: Mutex::new(object),
        }
    }
}

#[async_trait]
impl MistClient for ScriptedClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.requests
            .lock()
            .expect("request recorder")
            .push(request.clone());
        let body = self.object.lock().expect("object").clone();
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(body),
            cursor: None,
        })
    }
}

async fn call(
    handler: MistHandler,
    tool: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, String> {
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
        return Err(format!("tool error: {result:?}"));
    }
    let text = result.content[0]
        .as_text()
        .expect("text result")
        .text
        .clone();
    Ok(serde_json::from_str(&text).expect("JSON envelope"))
}

#[tokio::test]
async fn plan_reads_the_object_and_binds_the_digest_to_what_it_read() {
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({
        "id": NETWORK_ID, "name": "branch", "vlan_id": 10
    })));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");

    let planned = call(
        handler,
        "plan_mist_change",
        serde_json::json!({
            "object": "network",
            "verb": "update",
            "org_id": ORG_ID,
            "object_id": NETWORK_ID,
            "patch": {"vlan_id": 20}
        }),
    )
    .await
    .expect("plan");

    // The plan must have issued the corresponding read.
    let requests = recorder.requests.lock().expect("recorder");
    assert_eq!(
        requests.len(),
        1,
        "plan must read the object exactly once, got {requests:?}"
    );
    assert_eq!(requests[0].operation_id, "getOrgNetwork");
    assert_eq!(
        requests[0].path.get("network_id"),
        Some(&NETWORK_ID.to_owned())
    );
    assert!(
        requests[0].json.is_none(),
        "the plan read must not carry a body"
    );

    // The merged result keeps unspecified fields.
    assert_eq!(planned["after"]["name"], "branch");
    assert_eq!(planned["after"]["vlan_id"], 20);
    assert_eq!(planned["before"]["vlan_id"], 10);
    assert!(planned["change_set_id"].as_str().is_some());
    assert!(
        planned["plan_digest"]
            .as_str()
            .expect("plan digest")
            .starts_with("sha256:")
    );
}

#[tokio::test]
async fn plan_digest_changes_when_the_object_changes() {
    async fn digest_for(vlan: u64) -> String {
        let recorder = Arc::new(ScriptedClient::new(serde_json::json!({
            "id": NETWORK_ID, "name": "branch", "vlan_id": vlan
        })));
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![ORG_ID.to_owned()],
            site_map(),
            recorder,
        )
        .expect("handler");
        let planned = call(
            handler,
            "plan_mist_change",
            serde_json::json!({
                "object": "network", "verb": "update", "org_id": ORG_ID,
                "object_id": NETWORK_ID, "patch": {"vlan_id": 100}
            }),
        )
        .await
        .expect("plan");
        planned["plan_digest"].as_str().expect("digest").to_owned()
    }

    assert_ne!(
        digest_for(10).await,
        digest_for(99).await,
        "a digest that does not move with the object it read is bound to nothing"
    );
}

#[tokio::test]
async fn plan_refuses_a_patch_that_sets_config_authority() {
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({"id": NETWORK_ID})));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");

    let refused = call(
        handler,
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "update", "org_id": ORG_ID,
            "object_id": NETWORK_ID, "patch": {"mist_configured": true}
        }),
    )
    .await;

    assert!(refused.is_err(), "mist_configured must be refused");
    assert!(
        recorder.requests.lock().expect("recorder").is_empty(),
        "the refusal must happen before any Mist call"
    );
}

#[tokio::test]
async fn plan_refuses_org_not_in_allowed_orgs() {
    const DISALLOWED_ORG: &str = "99999999-9999-9999-9999-999999999999";
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({"id": NETWORK_ID})));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");

    let refused = call(
        handler,
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "create", "org_id": DISALLOWED_ORG,
            "patch": {"name": "unapproved", "vlan_id": 20}
        }),
    )
    .await;

    assert!(refused.is_err(), "org not in allowed_orgs must be refused");
    assert!(
        recorder.requests.lock().expect("recorder").is_empty(),
        "the refusal must happen before any Mist call"
    );
}

#[tokio::test]
async fn the_planner_cannot_approve_its_own_change_set() {
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({
        "id": NETWORK_ID, "name": "branch", "vlan_id": 10
    })));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");

    let planned = call(
        handler.clone(),
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "update", "org_id": ORG_ID,
            "object_id": NETWORK_ID, "patch": {"vlan_id": 20}
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    // Same principal — the stdio transport has one caller identity — must be refused.
    let refused = call(
        handler.clone(),
        "approve_mist_change_set",
        serde_json::json!({"change_set_id": id, "object": "network", "object_id": NETWORK_ID}),
    )
    .await;
    assert!(
        refused.is_err(),
        "the planning principal must not be able to approve"
    );

    // The change set is still inspectable, and still planned rather than approved.
    let fetched = call(
        handler,
        "get_mist_change_set",
        serde_json::json!({"change_set_id": id, "object": "network", "object_id": NETWORK_ID}),
    )
    .await
    .expect("get");
    assert_eq!(fetched["state"], "planned");
    assert_eq!(fetched["before"]["vlan_id"], 10);
    assert_eq!(fetched["after"]["vlan_id"], 20);
}

#[tokio::test]
async fn get_refuses_a_change_set_belonging_to_another_object() {
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({
        "id": NETWORK_ID, "name": "original"
    })));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder,
    )
    .expect("handler");

    let planned = call(
        handler.clone(),
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "update", "org_id": ORG_ID,
            "object_id": NETWORK_ID, "patch": {"name": "x"}
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    let wrong = call(
        handler,
        "get_mist_change_set",
        serde_json::json!({
            "change_set_id": id, "object": "service", "object_id": NETWORK_ID
        }),
    )
    .await;
    assert!(
        wrong.is_err(),
        "a change set must not be readable under another object key"
    );
}

#[tokio::test]
async fn apply_refuses_when_the_object_moved_after_planning() {
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({
        "id": NETWORK_ID, "name": "branch", "vlan_id": 10
    })));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");

    let planned = call(
        handler.clone(),
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "update", "org_id": ORG_ID,
            "object_id": NETWORK_ID, "patch": {"vlan_id": 20}
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    // Someone else edits the object between plan and apply.
    *recorder.object.lock().expect("object") = serde_json::json!({
        "id": NETWORK_ID, "name": "branch-renamed", "vlan_id": 10
    });

    let refused = call(
        handler,
        "apply_mist_change_set",
        serde_json::json!({"change_set_id": id, "object": "network", "object_id": NETWORK_ID}),
    )
    .await;

    assert!(
        refused.is_err(),
        "apply must refuse when the object moved since planning"
    );
    let requests = recorder.requests.lock().expect("recorder");
    assert!(
        requests.iter().all(|request| request.json.is_none()),
        "no write may be issued once the fingerprint mismatches, got {requests:?}"
    );
}

#[tokio::test]
async fn apply_refuses_an_unapproved_change_set() {
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({
        "id": NETWORK_ID, "name": "branch", "vlan_id": 10
    })));
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");

    let planned = call(
        handler.clone(),
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "update", "org_id": ORG_ID,
            "object_id": NETWORK_ID, "patch": {"vlan_id": 20}
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    let refused = call(
        handler,
        "apply_mist_change_set",
        serde_json::json!({"change_set_id": id, "object": "network", "object_id": NETWORK_ID}),
    )
    .await;

    assert!(refused.is_err(), "an unapproved change set must not apply");
    assert!(
        recorder
            .requests
            .lock()
            .expect("recorder")
            .iter()
            .all(|request| request.json.is_none()),
        "no write may be issued for an unapproved change set"
    );
}
