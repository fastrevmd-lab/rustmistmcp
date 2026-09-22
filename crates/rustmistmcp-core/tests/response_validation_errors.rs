//! Tests for response validation error messages - verifies field-level details
//! are included when validation fails (issue #95).

use rustmistmcp_core::{Catalog, MistError, MistResponse, MistResponseBody};
use url::Url;

#[test]
fn response_validation_error_includes_field_path() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // Craft a response that violates the schema: use a number instead of an object
    let response = MistResponse {
        operation_id: "getOrg".to_owned(),
        status: 200,
        body: MistResponseBody::Json(serde_json::json!(12345)),
        cursor: None,
    };

    let result = response.validate(&catalog, &origin);
    match result {
        Err(MistError::InvalidResponse {
            operation_id,
            reason,
        }) => {
            assert_eq!(operation_id, "getOrg");
            eprintln!("Error message: {}", reason);
            // The error should mention "field" to indicate it's giving field-level details
            assert!(
                reason.contains("field"),
                "Error should include field-level details, got: {}",
                reason
            );
        }
        other => panic!("Expected InvalidResponse error, got: {:?}", other),
    }
}

#[test]
fn sentinel_value_not_leaked_in_error() {
    // Critical test: validation errors must not embed instance values, which
    // would bypass audit redaction for sensitive fields (device names, hostnames, serials).
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    const SENTINEL: &str = "SENTINEL-DO-NOT-LEAK-b3f1";

    // Craft a response with a distinctive sentinel in a failing field
    let response = MistResponse {
        operation_id: "getOrg".to_owned(),
        status: 200,
        body: MistResponseBody::Json(serde_json::json!({
            "id": SENTINEL,  // Should be UUID, we're giving it a distinctive string
            "msp_id": 12345, // Wrong type - should be string or null
        })),
        cursor: None,
    };

    let result = response.validate(&catalog, &origin);
    match result {
        Err(MistError::InvalidResponse { reason, .. }) => {
            eprintln!("Error (checking for sentinel): {}", reason);
            // MUST contain field path information (diagnosable)
            assert!(
                reason.contains("field") || reason.contains("msp_id"),
                "Error should include field path for diagnosability, got: {}",
                reason
            );
            // MUST NOT contain the sentinel value (no leak)
            assert!(
                !reason.contains(SENTINEL),
                "Error MUST NOT leak instance value '{}', got: {}",
                SENTINEL,
                reason
            );
            // Should mention the type, not the value
            assert!(
                reason.contains("string") || reason.contains("number"),
                "Error should mention JSON types, got: {}",
                reason
            );
        }
        other => panic!("Expected InvalidResponse error, got: {:?}", other),
    }
}

#[test]
fn valid_response_still_passes() {
    let catalog = Catalog::embedded().expect("catalog");
    let origin = Url::parse("https://api.mist.com").expect("origin");

    // A minimally valid response for getOrg (just needs to be an object)
    let response = MistResponse {
        operation_id: "getOrg".to_owned(),
        status: 200,
        body: MistResponseBody::Json(serde_json::json!({
            "id": "test-org-id",
            "name": "Test Org"
        })),
        cursor: None,
    };

    let result = response.validate(&catalog, &origin);
    assert!(result.is_ok(), "Valid response should pass: {:?}", result);
}
