#![allow(clippy::unwrap_used)]
//! Responses captured from a real Mist tenant must validate.
//!
//! Both fixtures here are real bodies from `api.ac2.mist.com` (org `M_Lab`),
//! reduced to the shape that failed and scrubbed of anything identifying. Both
//! were rejected by v0.1.0 with `JSON body violates declared response schema`,
//! and in both cases the response was correct and the pinned spec was narrower
//! than the API it describes.
//!
//! These are regression fixtures, not synthetic cases: they are the exact
//! reason the relaxation exists, and if the relaxation is removed they fail.

use rustmistmcp_core::{Catalog, MistResponse, MistResponseBody};
use url::Url;

fn origin() -> Url {
    Url::parse("https://api.ac2.mist.com/").unwrap()
}

fn response(operation_id: &str, body: &str) -> MistResponse {
    MistResponse {
        operation_id: operation_id.to_owned(),
        status: 200,
        body: MistResponseBody::Json(serde_json::from_str(body).unwrap()),
        cursor: None,
    }
}

/// `getSelf` returns a privilege view outside the spec's closed enum.
///
/// `admin_privilege_view` lists eight members and the live tenant returns
/// `org_admin`, which is not among them. `admin_privilege` also sets
/// `additionalProperties: false`, so nothing about the response could pass.
#[test]
fn a_privilege_view_outside_the_declared_enum_is_accepted() {
    let catalog = Catalog::embedded().expect("embedded catalog");
    let body = include_str!("fixtures/live_get_self.json");
    assert!(
        body.contains("org_admin"),
        "fixture must still carry the out-of-enum value it exists to test"
    );
    response("getSelf", body)
        .validate(&catalog, &origin())
        .expect("a live getSelf body must validate");
}

/// `getOrg` returns `msp_id: null` where the spec declares a bare `"string"`.
///
/// An org with no MSP has nothing to put there. The same schema declares
/// `alarmtemplate_id` as `["string","null"]`, so the spec is inconsistent about
/// optionality rather than missing the convention entirely.
#[test]
fn a_null_in_a_non_nullable_declared_field_is_accepted() {
    let catalog = Catalog::embedded().expect("embedded catalog");
    let body = include_str!("fixtures/live_get_org.json");
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(
        parsed.get("msp_id").is_some_and(serde_json::Value::is_null),
        "fixture must still carry the null it exists to test"
    );
    response("getOrg", body)
        .validate(&catalog, &origin())
        .expect("a live getOrg body must validate");
}

/// Structure is still judged. Relaxing vocabulary must not mean accepting
/// anything at all — a body of the wrong container shape is still refused.
#[test]
fn a_structurally_wrong_body_is_still_refused() {
    let catalog = Catalog::embedded().expect("embedded catalog");
    let wrong = response("getOrg", r#""a bare string where an object is declared""#);
    assert!(
        wrong.validate(&catalog, &origin()).is_err(),
        "response validation must still refuse a body of the wrong shape; \
         relaxing vocabulary is not the same as accepting anything"
    );
}

/// Requests are **not** relaxed, and this is the guard that says so.
///
/// The relaxation is deliberately one-directional. Rejecting an unknown enum
/// member in a body we are about to *send* is correct: it protects the upstream
/// call and catches our own bugs, and no argument about vendor evolution
/// applies to a value we invented ourselves.
///
/// Without this test, "simplify by relaxing both directions" is a change that
/// nothing objects to.
#[test]
fn an_out_of_enum_value_in_a_request_is_still_refused() {
    use rustmistmcp_core::MistRequest;
    use std::collections::BTreeMap;

    let catalog = Catalog::embedded().expect("embedded catalog");

    // `createInstallerMap` declares these three path parameters; without them
    // validation stops before the body is ever judged, which would make this
    // test pass for the wrong reason.
    let path = || {
        BTreeMap::from([
            (
                "map_id".to_owned(),
                "11111111-1111-1111-1111-111111111111".to_owned(),
            ),
            (
                "org_id".to_owned(),
                "22222222-2222-2222-2222-222222222222".to_owned(),
            ),
            ("site_name".to_owned(), "hq".to_owned()),
        ])
    };

    // `map.type` is a closed enum of ["google", "image"] in the pinned catalog.
    let accepted = MistRequest {
        operation_id: "createInstallerMap".to_owned(),
        path: path(),
        query: BTreeMap::new(),
        json: Some(serde_json::json!({"type": "image"})),
        cursor: None,
    };
    let outcome = accepted.validate(&catalog, &origin());
    assert!(
        outcome.is_ok(),
        "a declared enum member must still be accepted in a request: {:?}",
        outcome.err()
    );

    let refused = MistRequest {
        operation_id: "createInstallerMap".to_owned(),
        path: path(),
        query: BTreeMap::new(),
        json: Some(serde_json::json!({"type": "not_a_declared_map_type"})),
        cursor: None,
    };
    assert!(
        refused.validate(&catalog, &origin()).is_err(),
        "an out-of-enum value must still be refused in a REQUEST; the response \
         relaxation is one-directional and must not leak into the outbound path"
    );
}
