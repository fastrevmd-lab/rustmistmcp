//! Lab-style acceptance test for MEC-406.
//!
//! Before this change, `main` handed `MistHandler` an empty site map at
//! startup, so every site-scoped tool call was refused in production
//! regardless of credentials (see `tool_contract.rs`'s
//! `site_reads_require_startup_discovery_even_without_remote_auth`, which
//! still guards that refusal for a handler nobody has run discovery
//! against). This test exercises the fix end to end against a mocked Mist
//! API: run startup discovery, install the result, then make a real
//! site-scoped MCP tool call and confirm it succeeds instead of being
//! refused.

use async_trait::async_trait;
use rmcp::{ServiceExt, model::CallToolRequestParams};
use rustmistmcp::{MistHandler, site_discovery};
use rustmistmcp_core::{MistClient, MistError, MistRequest, MistResponse, MistResponseBody};
use std::collections::BTreeMap;
use std::sync::Arc;

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_ID: &str = "22222222-2222-2222-2222-222222222222";

/// A minimal mocked Mist API: one org, one site, discoverable and readable.
#[derive(Default)]
struct DiscoverableClient;

#[async_trait]
impl MistClient for DiscoverableClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        let body = match request.operation_id.as_str() {
            "listOrgSites" => serde_json::json!([{"id": SITE_ID, "name": "Lab Site"}]),
            "getSiteInfo" => serde_json::json!({"name": "Lab Site"}),
            other => panic!("unexpected operation in acceptance test: {other}"),
        };
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(body),
            cursor: None,
            page: None,
        })
    }
}

#[tokio::test]
async fn site_scoped_tool_succeeds_once_startup_discovery_populates_the_map() {
    // Exactly what `main` constructs before running discovery: a real
    // client, but no site-map configuration supplied by hand.
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
        Arc::new(DiscoverableClient),
    )
    .expect("handler");

    let discovered = site_discovery::discover_sites(
        handler.client().as_ref(),
        handler.catalog(),
        handler.origin(),
        handler.allowed_orgs(),
    )
    .await;
    assert_eq!(
        discovered.sites.get(SITE_ID),
        Some(&ORG_ID.to_owned()),
        "discovery should have learned the site from listOrgSites"
    );
    handler
        .replace_sites(discovered.sites)
        .expect("a discovered map naming only the allowlisted org must validate");

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
        .call_tool(CallToolRequestParams::new("get_mist_site").with_arguments(
            serde_json::from_value(serde_json::json!({"site_id": SITE_ID})).expect("arguments"),
        ))
        .await
        .expect("site call");

    assert_ne!(
        result.is_error,
        Some(true),
        "a site-scoped tool call must succeed once startup discovery has populated the site map: \
         {result:?}"
    );

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}
