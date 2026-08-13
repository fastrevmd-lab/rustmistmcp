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
            "getSiteGatewayMetrics" => serde_json::json!({}),
            "getSiteInsightMetricsForGateway" => serde_json::json!({
                "start": 0,
                "end": 0,
                "interval": 60,
                "results": []
            }),
            "searchOrgTunnelsStats" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "countOrgTunnelsStats" => serde_json::json!({
                "distinct": "type",
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "searchOrgPeerPathStats" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "countOrgPeerPathStats" => serde_json::json!({
                "distinct": "type",
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "searchOrgBgpStats" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "countOrgBgpStats" => serde_json::json!({
                "distinct": "type",
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "searchSiteBgpStats" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "countSiteBgpStats" => serde_json::json!({
                "distinct": "type",
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "searchSiteServicePathEvents" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "countSiteServicePathEvents" => serde_json::json!({
                "distinct": "type",
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "listSiteSleImpactedGateways" | "listSiteSleImpactedApplications" => {
                serde_json::json!({
                    "results": []
                })
            }
            "getSiteSleImpactSummary" => serde_json::json!({
                "start": 0,
                "end": 0,
                "metric": "wan-link-health",
                "classifier": "",
                "failure": "",
                "ap": [],
                "wlan": [],
                "device_os": [],
                "device_type": [],
                "band": []
            }),
            "listSiteApps" => serde_json::json!([]),
            "countSiteApps" => serde_json::json!({
                "distinct": "name",
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            "listGatewayApplications" => serde_json::json!([]),
            "listOrgNetworks" => serde_json::json!([]),
            "listOrgServices" => serde_json::json!([]),
            "listOrgServicePolicies" => serde_json::json!([]),
            "listOrgGatewayTemplates" => serde_json::json!([]),
            "listOrgDeviceProfiles" => serde_json::json!([]),
            "listSiteNetworksDerived" => serde_json::json!([]),
            "listSiteServicesDerived" => serde_json::json!([]),
            "listSiteServicePoliciesDerived" => serde_json::json!([]),
            "listSiteGatewayTemplatesDerived" => serde_json::json!([]),
            "listSiteDeviceProfilesDerived" => serde_json::json!([]),
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

#[tokio::test]
async fn wan_edge_stats_selects_site_or_device_variant() {
    let site = record_call(
        "get_mist_wan_edge_stats",
        serde_json::json!({"site_id": SITE_ID}),
    )
    .await
    .expect("site call");
    assert_eq!(site.operation_id, "getSiteGatewayMetrics");

    let device = record_call(
        "get_mist_wan_edge_stats",
        serde_json::json!({
            "site_id": SITE_ID,
            "device_id": "00000000-0000-0000-0000-00000000abcd",
            "metrics": "cpu,memory"
        }),
    )
    .await
    .expect("device call");
    assert_eq!(device.operation_id, "getSiteInsightMetricsForGateway");
    assert!(
        !device.query.contains_key("device_id"),
        "device_id belongs in the path, not the query"
    );
}

#[tokio::test]
async fn tunnels_resolve_mode_and_never_leak_the_selector() {
    let records = record_call("search_mist_tunnels", serde_json::json!({"org_id": ORG_ID}))
        .await
        .expect("records call");
    assert_eq!(records.operation_id, "searchOrgTunnelsStats");
    assert!(
        !records.query.contains_key("mode"),
        "mode is a tool selector and must not reach Mist"
    );

    let counted = record_call(
        "search_mist_tunnels",
        serde_json::json!({"org_id": ORG_ID, "mode": "count"}),
    )
    .await
    .expect("count call");
    assert_eq!(counted.operation_id, "countOrgTunnelsStats");
    assert!(!counted.query.contains_key("mode"));
}

#[tokio::test]
async fn peer_paths_resolve_mode() {
    let records = record_call(
        "search_mist_peer_paths",
        serde_json::json!({"org_id": ORG_ID}),
    )
    .await
    .expect("records call");
    assert_eq!(records.operation_id, "searchOrgPeerPathStats");

    let counted = record_call(
        "search_mist_peer_paths",
        serde_json::json!({"org_id": ORG_ID, "mode": "count"}),
    )
    .await
    .expect("count call");
    assert_eq!(counted.operation_id, "countOrgPeerPathStats");
    assert!(!counted.query.contains_key("mode"));
}

#[tokio::test]
async fn bgp_peers_resolve_scope_and_mode() {
    for (args, expected) in [
        (serde_json::json!({"org_id": ORG_ID}), "searchOrgBgpStats"),
        (
            serde_json::json!({"org_id": ORG_ID, "mode": "count"}),
            "countOrgBgpStats",
        ),
        (
            serde_json::json!({"site_id": SITE_ID}),
            "searchSiteBgpStats",
        ),
        (
            serde_json::json!({"site_id": SITE_ID, "mode": "count"}),
            "countSiteBgpStats",
        ),
    ] {
        let request = record_call("search_mist_bgp_peers", args.clone())
            .await
            .unwrap_or_else(|error| panic!("call {args} failed: {error}"));
        assert_eq!(request.operation_id, expected, "for {args}");
        assert!(
            !request.query.contains_key("mode"),
            "mode is a tool selector and must not reach Mist, for {args}"
        );
    }

    assert!(
        record_call(
            "search_mist_bgp_peers",
            serde_json::json!({"mode": "count"})
        )
        .await
        .is_err(),
        "missing scope must be refused"
    );
}

#[tokio::test]
async fn service_path_events_resolve_mode() {
    let records = record_call(
        "search_mist_service_path_events",
        serde_json::json!({"site_id": SITE_ID}),
    )
    .await
    .expect("records call");
    assert_eq!(records.operation_id, "searchSiteServicePathEvents");
    assert!(
        !records.query.contains_key("mode"),
        "mode is a tool selector and must not reach Mist"
    );

    let counted = record_call(
        "search_mist_service_path_events",
        serde_json::json!({"site_id": SITE_ID, "mode": "count"}),
    )
    .await
    .expect("count call");
    assert_eq!(counted.operation_id, "countSiteServicePathEvents");
    assert!(!counted.query.contains_key("mode"));
}

#[tokio::test]
async fn sle_impact_resolves_selector() {
    let base = serde_json::json!({
        "site_id": SITE_ID,
        "scope": "site",
        "scope_id": SITE_ID,
        "metric": "wan-link-health",
    });
    for (impact, expected) in [
        ("gateways", "listSiteSleImpactedGateways"),
        ("applications", "listSiteSleImpactedApplications"),
        ("summary", "getSiteSleImpactSummary"),
    ] {
        let mut args = base.clone();
        args["impact"] = serde_json::json!(impact);
        let request = record_call("get_mist_sle_impact", args)
            .await
            .unwrap_or_else(|error| panic!("impact {impact} failed: {error}"));
        assert_eq!(request.operation_id, expected);
        assert!(!request.query.contains_key("impact"));
    }
}

#[tokio::test]
async fn applications_resolve_source_and_mode() {
    let site = record_call(
        "list_mist_applications",
        serde_json::json!({"source": "site", "site_id": SITE_ID}),
    )
    .await
    .expect("site call");
    assert_eq!(site.operation_id, "listSiteApps");
    assert!(
        !site.query.contains_key("source"),
        "source is a tool selector and must not reach Mist"
    );
    assert!(
        !site.query.contains_key("mode"),
        "mode is a tool selector and must not reach Mist"
    );

    let counted = record_call(
        "list_mist_applications",
        serde_json::json!({"source": "site", "site_id": SITE_ID, "mode": "count"}),
    )
    .await
    .expect("count call");
    assert_eq!(counted.operation_id, "countSiteApps");
    assert!(!counted.query.contains_key("source"));
    assert!(!counted.query.contains_key("mode"));

    let catalog = record_call(
        "list_mist_applications",
        serde_json::json!({"source": "catalog"}),
    )
    .await
    .expect("catalog call");
    assert_eq!(catalog.operation_id, "listGatewayApplications");
    assert!(!catalog.query.contains_key("source"));
    assert!(!catalog.query.contains_key("mode"));
}

#[tokio::test]
async fn applications_require_site_id_for_the_site_source() {
    assert!(
        record_call(
            "list_mist_applications",
            serde_json::json!({"source": "site"})
        )
        .await
        .is_err(),
        "site source without site_id must be refused"
    );
}

#[tokio::test]
async fn wan_config_listing_resolves_object_and_scope() {
    // Gateway templates and device profiles require privileged read auth, so
    // this test only covers the ordinary-read config types. The unit test in
    // wan.rs proves all 10 operation resolutions work correctly.
    for (object, scope_key, scope_value, expected) in [
        ("network", "org_id", ORG_ID, "listOrgNetworks"),
        ("service", "org_id", ORG_ID, "listOrgServices"),
        ("servicepolicy", "org_id", ORG_ID, "listOrgServicePolicies"),
        ("network", "site_id", SITE_ID, "listSiteNetworksDerived"),
        ("service", "site_id", SITE_ID, "listSiteServicesDerived"),
        (
            "servicepolicy",
            "site_id",
            SITE_ID,
            "listSiteServicePoliciesDerived",
        ),
    ] {
        let args = serde_json::json!({"object": object, scope_key: scope_value});
        let request = record_call("list_mist_wan_config", args.clone())
            .await
            .unwrap_or_else(|error| panic!("{args} failed: {error}"));
        assert_eq!(request.operation_id, expected, "for {args}");
        assert!(!request.query.contains_key("object"));
    }
}
