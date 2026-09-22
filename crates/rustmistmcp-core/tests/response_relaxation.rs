//! Tests for response schema relaxations (issue #95).
//!
//! Verifies that `relax_for_responses` widens schemas to tolerate vendor drift:
//! - Fractional epoch seconds where `integer` is declared (searchOrgInventory)
//! - Missing fields that the schema declares `required` (getOrgStats)
//!
//! Also verifies that requests remain strict: the relaxations must not leak into
//! the request validation path.

use rustmistmcp_core::{Catalog, MistRequest, MistResponse, MistResponseBody};
use std::collections::BTreeMap;
use url::Url;

/// Test that responses with fractional epoch seconds validate cleanly.
///
/// Captured from live Mist: `searchOrgInventory` and `searchOrgDevices` return
/// `start` and `end` as fractional epoch seconds (e.g., 1790089263.3111906),
/// despite the schema declaring them as `type: integer`.
#[test]
fn response_accepts_fractional_epoch_seconds() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // Fixture replicating the exact shape from live Mist
    let body = serde_json::json!({
        "end": 1790089263.3111906,
        "start": 1790085663.3111906,
        "limit": 10,
        "results": [],
        "total": 0
    });

    let response = MistResponse {
        operation_id: "searchOrgInventory".to_owned(),
        status: 200,
        body: MistResponseBody::Json(body),
        cursor: None,
    };

    // Should validate cleanly after the fix
    let result = response.validate(&catalog, &origin);
    assert!(
        result.is_ok(),
        "Expected searchOrgInventory response with fractional epoch to validate, got: {:?}",
        result
    );
}

/// Test that responses missing a `required` field validate cleanly.
///
/// Captured from live Mist: `getOrgStats` is declared with a `required` list of
/// 15 properties, but the live response contains only 14. The missing field is
/// `orggroup_ids`, which Mist never sends.
#[test]
fn response_accepts_missing_required_field() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // Fixture replicating stats_org with 14/15 required fields (missing orggroup_ids)
    let body = serde_json::json!({
        "alarmtemplate_id": null,
        "allow_mist": true,
        "created_time": 1609459200,
        "id": "b069b358-4c97-5319-1f8c-7c5ca64d6ab1",
        "modified_time": 1609459200,
        "msp_id": null,
        "name": "Test Org",
        "num_devices": 42,
        "num_inventory": 50,
        "num_sites": 5,
        "session_expiry": 1440,
        "sle_enabled": false,
        "trial_enabled": false,
        "trial_expiry": null
        // orggroup_ids is missing despite being in required[]
    });

    let response = MistResponse {
        operation_id: "getOrgStats".to_owned(),
        status: 200,
        body: MistResponseBody::Json(body),
        cursor: None,
    };

    // Should validate cleanly after the fix
    let result = response.validate(&catalog, &origin);
    assert!(
        result.is_ok(),
        "Expected getOrgStats response missing orggroup_ids to validate, got: {:?}",
        result
    );
}

/// Test that requests with floats where integers are declared are REJECTED.
///
/// Requests must remain strict: the response relaxations must not leak into the
/// request validation path. A request with a float where an integer is declared
/// should fail validation.
#[test]
fn request_rejects_float_for_integer_field() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // Craft a request with a float where integer is expected
    // Using a query parameter that's declared as integer
    let mut query = BTreeMap::new();
    query.insert(
        "limit".to_owned(),
        serde_json::Value::Number(serde_json::Number::from_f64(10.5).expect("valid float")),
    );

    let request = MistRequest {
        operation_id: "listOrgs".to_owned(),
        path: BTreeMap::new(),
        query,
        json: None,
        cursor: None,
    };

    let result = request.validate(&catalog, &origin);
    assert!(
        result.is_err(),
        "Expected request with float limit to be rejected, but it was accepted"
    );
}

/// Test that requests missing a required field are REJECTED.
///
/// Requests must remain strict. A request missing a required field should fail
/// validation even though responses are relaxed to tolerate missing required fields.
#[test]
fn request_rejects_missing_required_field() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // For an operation that requires certain path parameters, omit one
    // Using createOrgWlan which requires org_id in the path
    let request = MistRequest {
        operation_id: "createOrgWlan".to_owned(),
        path: BTreeMap::new(), // Missing required org_id
        query: BTreeMap::new(),
        json: Some(serde_json::json!({
            "ssid": "test-ssid",
            "enabled": true
        })),
        cursor: None,
    };

    let result = request.validate(&catalog, &origin);
    assert!(
        result.is_err(),
        "Expected request missing required path parameter to be rejected, but it was accepted"
    );
}
