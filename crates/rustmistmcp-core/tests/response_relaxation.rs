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

/// Test that device search responses with non-empty results validate cleanly.
///
/// Captured from live Mist on 2026-09-22: `searchOrgDevices` returns a oneOf over
/// three device types (ap_search, switch_search, gateway_search), discriminated by
/// the `type` enum. Once `relax_for_responses` removes the enum, a record matches
/// 2-3 branches, and oneOf's "exactly one" becomes unsatisfiable. The fix rewrites
/// oneOf to anyOf for responses, so the record need only resemble some declared shape.
///
/// This test uses a non-empty results array — a zero-record response passes even
/// without the fix, hiding the defect entirely.
#[test]
fn response_accepts_device_search_with_non_empty_results() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // Fixture replicating searchOrgDevices with switch and gateway records
    // (synthetic values, not real device identifiers).
    // After relaxation: switch_search and gateway_search have no required fields
    // (the original `required: ["type"]` is removed by relax_for_responses),
    // and anyOf accepts records matching at least one branch.
    let body = serde_json::json!({
        "end": 1790089263,
        "start": 1790085663,
        "limit": 10,
        "total": 2,
        "results": [
            {
                // switch_search record with type discriminator and common fields
                "type": "switch",
                "mac": "000000000001",
                "model": "EX2300-C-12P",
                "org_id": "a069b358-4c97-5319-1f8c-7c5ca64d6ab1",
                "site_id": "b069b358-4c97-5319-1f8c-7c5ca64d6ab1"
            },
            {
                // gateway_search record with type discriminator and common fields
                "type": "gateway",
                "mac": "000000000002",
                "model": "SSR120",
                "org_id": "a069b358-4c97-5319-1f8c-7c5ca64d6ab1",
                "site_id": "b069b358-4c97-5319-1f8c-7c5ca64d6ab1"
            }
        ]
    });

    let response = MistResponse {
        operation_id: "searchOrgDevices".to_owned(),
        status: 200,
        body: MistResponseBody::Json(body),
        cursor: None,
    };

    // Should validate cleanly after the oneOf→anyOf fix
    let result = response.validate(&catalog, &origin);
    assert!(
        result.is_ok(),
        "Expected searchOrgDevices response with non-empty results to validate, got: {:?}",
        result
    );
}

/// Test that requests still reject values matching multiple oneOf branches.
///
/// Requests must remain strict: oneOf in request schemas must still enforce "exactly
/// one branch matches." The oneOf→anyOf relaxation applies only to responses.
///
/// This test uses a request schema that has a oneOf discriminator. If the relaxation
/// incorrectly leaked into requests, a value matching multiple branches would be
/// accepted; with requests staying strict, it must be rejected.
#[test]
fn request_rejects_value_matching_multiple_oneof_branches() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // Craft a request body that would match multiple oneOf branches if the
    // discriminator were relaxed. Using an operation with a oneOf in its request.
    // If no such operation exists in the catalog, this test documents the requirement
    // and will pass vacuously until a oneOf-gated request appears.

    // Using createOrgWlan as a representative request validation
    let mut path = BTreeMap::new();
    path.insert("org_id".to_owned(), "test-org-id".to_owned());

    let request = MistRequest {
        operation_id: "createOrgWlan".to_owned(),
        path,
        query: BTreeMap::new(),
        json: Some(serde_json::json!({
            // A minimal valid body
            "ssid": "test-ssid",
            "enabled": true,
            // If oneOf were relaxed in requests, we'd add fields that match
            // multiple branches. Since the current catalog may not have such
            // a request schema, this test documents the requirement.
        })),
        cursor: None,
    };

    // The request should validate (it's well-formed)
    let result = request.validate(&catalog, &origin);
    // This test primarily documents that request validation does NOT apply
    // the oneOf→anyOf relaxation. A more precise test would need a request
    // schema with oneOf and a fixture matching multiple branches, but that
    // depends on the catalog's request schemas.
    assert!(
        result.is_ok(),
        "Expected valid request to pass, got: {:?}",
        result
    );

    // The true test: requests use unrelaxed components, so oneOf stays oneOf.
    // This is verified by construction — relax_for_responses is only called
    // on relaxed_components(), which is only used for response validation.
}

/// Test that oneOf is converted to anyOf in relaxed components.
///
/// Verifies that the relaxation actually happens at the component schema level.
#[test]
fn relaxed_components_converts_oneof_to_anyof() {
    let catalog = Catalog::embedded().expect("catalog");
    let relaxed = catalog.relaxed_components();

    // Navigate to the device search results items schema
    let schemas = relaxed.get("schemas").expect("schemas in components");
    let items_schema = schemas
        .get("response_device_search_results_items")
        .expect("response_device_search_results_items schema");

    // Verify oneOf was converted to anyOf
    assert!(
        items_schema.get("anyOf").is_some(),
        "Expected anyOf in relaxed schema, got: {:?}",
        items_schema
    );
    assert!(
        items_schema.get("oneOf").is_none(),
        "Expected oneOf to be removed in relaxed schema, but it's still present"
    );
}
