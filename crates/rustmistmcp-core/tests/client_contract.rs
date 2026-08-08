//! Contract tests for the non-networking, catalog-bound Mist client seam.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::executor::block_on;
use rustmistmcp_core::{
    Catalog, MistClient, MistCursor, MistError, MistRequest, MistResponse, MistResponseBody,
    MistTarget, PaginationMode,
};
use serde_json::json;
use url::Url;

const ORG: &str = "123e4567-e89b-42d3-a456-426614174000";

fn catalog() -> Catalog {
    Catalog::embedded().expect("embedded catalog")
}

fn origin() -> Url {
    Url::parse("https://api.mist.com/").expect("Mist origin")
}

fn request(operation_id: &str) -> MistRequest {
    MistRequest {
        operation_id: operation_id.to_owned(),
        path: BTreeMap::new(),
        query: BTreeMap::new(),
        json: None,
        cursor: None,
    }
}

#[test]
fn request_validation_is_catalog_bound_and_preserves_schema_constraints() {
    let catalog = catalog();
    let origin = origin();

    let valid = MistRequest {
        path: BTreeMap::from([("site_id".to_owned(), ORG.to_owned())]),
        query: BTreeMap::from([
            ("rating".to_owned(), json!(5)),
            ("distinct".to_owned(), json!("mac")),
        ]),
        ..request("countSiteCalls")
    };
    assert_eq!(valid.clone().validate(&catalog, &origin), Ok(valid));

    for invalid in [
        MistRequest {
            query: BTreeMap::from([("rating".to_owned(), json!(0))]),
            path: BTreeMap::from([("site_id".to_owned(), ORG.to_owned())]),
            ..request("countSiteCalls")
        },
        MistRequest {
            query: BTreeMap::from([("distinct".to_owned(), json!("client"))]),
            path: BTreeMap::from([("site_id".to_owned(), ORG.to_owned())]),
            ..request("countSiteCalls")
        },
        MistRequest {
            path: BTreeMap::new(),
            ..request("listOrgSites")
        },
        MistRequest {
            path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
            query: BTreeMap::from([("not_catalogued".to_owned(), json!(true))]),
            ..request("listOrgSites")
        },
    ] {
        assert!(matches!(
            invalid.validate(&catalog, &origin),
            Err(MistError::InvalidRequest { .. })
        ));
    }
    assert_eq!(
        request("notAnOperation").validate(&catalog, &origin),
        Err(MistError::UnknownOperation("notAnOperation".to_owned()))
    );
}

#[test]
fn request_validation_enforces_json_media_and_resolved_body_schema() {
    let catalog = catalog();
    let origin = origin();

    let json_request = MistRequest {
        path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
        json: Some(json!([{"mac": "001122334455"}])),
        ..request("importOrgUserMacs")
    };
    assert!(json_request.validate(&catalog, &origin).is_ok());

    for optional_body in [
        MistRequest {
            path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
            ..request("importOrgUserMacs")
        },
        MistRequest {
            path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
            ..request("importOrgAssets")
        },
    ] {
        assert!(
            optional_body.validate(&catalog, &origin).is_ok(),
            "optional request bodies must remain omittable"
        );
    }
    let required_body = MistRequest {
        path: BTreeMap::from([
            ("id".to_owned(), ORG.to_owned()),
            ("site_id".to_owned(), ORG.to_owned()),
        ]),
        ..request("submitSiteMarvisConfigFeedback")
    };
    assert!(matches!(
        required_body.validate(&catalog, &origin),
        Err(MistError::InvalidRequest { .. })
    ));

    for invalid in [
        MistRequest {
            json: Some(json!({})),
            ..request("getSelf")
        },
        MistRequest {
            path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
            json: Some(json!({"mac": 9})),
            ..request("importOrgUserMacs")
        },
        MistRequest {
            path: BTreeMap::from([
                ("org_id".to_owned(), ORG.to_owned()),
                ("site_name".to_owned(), "site".to_owned()),
            ]),
            json: Some(json!({"file": "not-a-file-part"})),
            ..request("importInstallerMap")
        },
    ] {
        assert!(matches!(
            invalid.validate(&catalog, &origin),
            Err(MistError::InvalidRequest { .. })
        ));
    }
}

#[test]
fn cursors_are_opaque_but_bound_to_origin_operation_and_pagination_mode() {
    let catalog = catalog();
    let origin = origin();
    let cursor = MistCursor::new(
        "listOrgSites".to_owned(),
        &origin,
        PaginationMode::PageLimit,
        "opaque-next-page".to_owned(),
    )
    .expect("valid cursor");
    assert_eq!(cursor.operation_id(), "listOrgSites");
    assert_eq!(cursor.mode(), PaginationMode::PageLimit);

    let accepted = MistRequest {
        path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
        cursor: Some(cursor.clone()),
        ..request("listOrgSites")
    };
    assert!(accepted.validate(&catalog, &origin).is_ok());

    for invalid in [
        MistRequest {
            path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
            cursor: Some(cursor.clone()),
            ..request("listOrgSites")
        }
        .validate(
            &catalog,
            &Url::parse("https://api.eu.mist.com/").expect("other origin"),
        ),
        MistRequest {
            cursor: Some(cursor.clone()),
            ..request("getSelf")
        }
        .validate(&catalog, &origin),
        MistRequest {
            path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
            cursor: Some(
                MistCursor::new(
                    "listOrgSites".to_owned(),
                    &origin,
                    PaginationMode::SearchAfter,
                    "opaque-next-page".to_owned(),
                )
                .expect("cursor syntax is independently valid"),
            ),
            ..request("listOrgSites")
        }
        .validate(&catalog, &origin),
    ] {
        assert!(matches!(invalid, Err(MistError::InvalidCursor(_))));
    }

    assert!(matches!(
        MistCursor::new(
            "getSelf".to_owned(),
            &origin,
            PaginationMode::None,
            "opaque".to_owned(),
        ),
        Err(MistError::InvalidCursor(_))
    ));
}

#[test]
fn continuation_context_round_trips_for_revalidation_and_reauthorization() {
    let path = BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]);
    let query = BTreeMap::from([
        ("limit".to_owned(), json!(25)),
        ("page".to_owned(), json!(2)),
    ]);
    let target = MistTarget::org(ORG).expect("target");
    let cursor = MistCursor::new(
        "listOrgSites".to_owned(),
        &origin(),
        PaginationMode::PageLimit,
        "opaque-next-page".to_owned(),
    )
    .expect("cursor")
    .with_request_context(path.clone(), query.clone(), Some(target.clone()))
    .expect("bounded request context");
    let decoded: MistCursor =
        serde_json::from_slice(&serde_json::to_vec(&cursor).expect("encode")).expect("decode");
    let (decoded_path, decoded_query, decoded_target) =
        decoded.request_context().expect("request context");
    assert_eq!(decoded_path, &path);
    assert_eq!(decoded_query, &query);
    assert_eq!(decoded_target, Some(&target));
}

#[test]
fn serde_contract_rejects_unknown_fields_and_preserves_response_variants() {
    let cursor = MistCursor::new(
        "listOrgSites".to_owned(),
        &origin(),
        PaginationMode::PageLimit,
        "opaque".to_owned(),
    )
    .expect("cursor");
    let request = MistRequest {
        path: BTreeMap::from([("org_id".to_owned(), ORG.to_owned())]),
        cursor: Some(cursor.clone()),
        ..request("listOrgSites")
    };
    assert_eq!(
        serde_json::from_str::<MistRequest>(&serde_json::to_string(&request).expect("serialize"))
            .expect("deserialize"),
        request
    );
    assert!(
        serde_json::from_value::<MistRequest>(json!({
            "operation_id": "getSelf", "unknown": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<MistCursor>(json!({
            "operation_id": "listOrgSites", "origin": "https://api.mist.com/",
            "mode": "page_limit", "value": "opaque", "unknown": true
        }))
        .is_err()
    );

    for body in [
        MistResponseBody::Json(json!({"ok": true})),
        MistResponseBody::Text("ok".to_owned()),
        MistResponseBody::Binary(vec![0, 1, 2]),
    ] {
        let response = MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 200,
            body,
            cursor: None,
        };
        assert_eq!(
            serde_json::from_str::<MistResponse>(
                &serde_json::to_string(&response).expect("serialize")
            )
            .expect("deserialize"),
            response
        );
    }
}

#[test]
fn response_validation_is_catalog_bound_and_bounded() {
    let catalog = catalog();
    let origin = origin();
    let valid_json = MistResponse {
        operation_id: "getSelf".to_owned(),
        status: 200,
        body: MistResponseBody::Json(json!({})),
        cursor: None,
    };
    assert_eq!(
        valid_json.clone().validate(&catalog, &origin),
        Ok(valid_json)
    );
    let valid_empty = MistResponse {
        operation_id: "deleteOrg".to_owned(),
        status: 200,
        body: MistResponseBody::Empty,
        cursor: None,
    };
    assert!(valid_empty.validate(&catalog, &origin).is_ok());
    let valid_binary = MistResponse {
        operation_id: "generateSecretFor2faVerification".to_owned(),
        status: 200,
        body: MistResponseBody::Binary(vec![1, 2, 3]),
        cursor: None,
    };
    assert!(valid_binary.validate(&catalog, &origin).is_ok());

    let cursor = MistCursor::new(
        "listOrgSites".to_owned(),
        &origin,
        PaginationMode::PageLimit,
        "opaque".to_owned(),
    )
    .expect("cursor");
    for invalid in [
        MistResponse {
            operation_id: "notAnOperation".to_owned(),
            status: 200,
            body: MistResponseBody::Json(json!({})),
            cursor: None,
        },
        MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 201,
            body: MistResponseBody::Json(json!({})),
            cursor: None,
        },
        MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 200,
            body: MistResponseBody::Text("not declared as text".to_owned()),
            cursor: None,
        },
        MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 200,
            body: MistResponseBody::Json(json!([])),
            cursor: None,
        },
        MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 200,
            body: MistResponseBody::Empty,
            cursor: None,
        },
        MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 200,
            body: MistResponseBody::Json(json!({})),
            cursor: Some(cursor),
        },
        MistResponse {
            operation_id: "getSelf".to_owned(),
            status: 200,
            body: MistResponseBody::Text("x".repeat(1_048_577)),
            cursor: None,
        },
    ] {
        assert!(matches!(
            invalid.validate(&catalog, &origin),
            Err(MistError::UnknownOperation(_))
                | Err(MistError::InvalidResponse { .. })
                | Err(MistError::InvalidCursor(_))
        ));
    }
}

struct RecordingMock {
    seen: Mutex<Vec<MistRequest>>,
}

#[async_trait]
impl MistClient for RecordingMock {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.seen
            .lock()
            .expect("record request")
            .push(request.clone());
        if request.operation_id == "rateLimited" {
            return Err(MistError::RateLimited {
                retry_after_secs: Some(30),
            });
        }
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(json!({})),
            cursor: None,
        })
    }
}

#[test]
fn injected_async_client_supports_recording_results_and_rate_limit_mapping() {
    let client = RecordingMock {
        seen: Mutex::new(Vec::new()),
    };
    let result = block_on(client.execute(request("getSelf"))).expect("mock response");
    assert_eq!(result.body, MistResponseBody::Json(json!({})));
    assert_eq!(
        block_on(client.execute(request("rateLimited"))),
        Err(MistError::RateLimited {
            retry_after_secs: Some(30),
        })
    );
    assert_eq!(client.seen.lock().expect("read record").len(), 2);
}
