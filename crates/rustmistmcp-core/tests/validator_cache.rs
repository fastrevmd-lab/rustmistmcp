//! Compiled validators are built once per schema, not once per call (#59).
//!
//! The validation root embeds the whole components registry, so building it
//! clones ~2.2 MB and compiling a validator over it costs tens of milliseconds.
//! That was happening on every request and every response and being thrown away
//! at the end of the call.
//!
//! Timing alone would be a flaky assertion, so the guarantee is pinned two
//! ways: a deterministic test that repeated validation stays correct, and a
//! ratio check with enough headroom that only a *reintroduced per-call compile*
//! can fail it — the first call and the hundredth differ by orders of
//! magnitude, not by a few percent.

#![allow(clippy::unwrap_used)]

use rustmistmcp_core::{Catalog, MistRequest, MistResponse, MistResponseBody};
use std::collections::BTreeMap;
use std::time::Instant;
use url::Url;

fn origin() -> Url {
    Url::parse("https://api.mist.com").unwrap()
}

fn request(map_type: &str) -> MistRequest {
    MistRequest {
        operation_id: "createInstallerMap".to_owned(),
        path: BTreeMap::from([
            (
                "map_id".to_owned(),
                "11111111-1111-1111-1111-111111111111".to_owned(),
            ),
            (
                "org_id".to_owned(),
                "22222222-2222-2222-2222-222222222222".to_owned(),
            ),
            ("site_name".to_owned(), "hq".to_owned()),
        ]),
        query: BTreeMap::new(),
        json: Some(serde_json::json!({ "type": map_type })),
        cursor: None,
    }
}

/// Caching must not change the verdict — on either side of it.
///
/// A cache keyed by the wrong thing would be invisible to a timing test and
/// very visible here: it would start accepting what the schema refuses, or
/// refusing what it accepts, once a second schema shared an entry.
#[test]
fn repeated_validation_keeps_returning_the_same_verdict() {
    let catalog = Catalog::embedded().expect("embedded catalog");

    for round in 0..25 {
        assert!(
            request("image").validate(&catalog, &origin()).is_ok(),
            "a declared enum member must be accepted on round {round}"
        );
        assert!(
            request("not_a_declared_map_type")
                .validate(&catalog, &origin())
                .is_err(),
            "an out-of-enum value must be refused on round {round}"
        );
    }
}

/// The first call pays for compilation; the rest must not.
///
/// The threshold is deliberately loose. Compiling the root takes tens of
/// milliseconds against a registry of this size, so a per-call compile makes
/// the steady-state average land within the same order as the first call. A
/// cached validator leaves it orders below, and no plausible machine or CI
/// contention closes that gap.
#[test]
fn the_validator_is_not_recompiled_on_every_call() {
    let catalog = Catalog::embedded().expect("embedded catalog");

    let cold_start = Instant::now();
    request("image").validate(&catalog, &origin()).unwrap();
    let cold = cold_start.elapsed();

    const WARM_CALLS: u32 = 100;
    let warm_start = Instant::now();
    for _ in 0..WARM_CALLS {
        request("image").validate(&catalog, &origin()).unwrap();
    }
    let warm_avg = warm_start.elapsed() / WARM_CALLS;

    assert!(
        warm_avg * 10 < cold,
        "a warm call should be far cheaper than the first: cold {cold:?}, warm \
         average {warm_avg:?} over {WARM_CALLS} calls. If these are close, the \
         validator is being recompiled per call and #59 has regressed."
    );
}

/// A cached validator must not answer for a different status.
///
/// Response schemas are looked up per HTTP status, so the position of a schema
/// within one status's media map restarts at zero for the next. Keying a cache
/// entry on that position alone made status 400's schema and status 404's share
/// one entry, and whichever ran first answered for both — a wrong verdict, not
/// a slow one, and order-dependent so it would surface as a flake.
///
/// `deleteInstallerMap` declares `response_http400` (only `detail`, a string)
/// and `response_http404` (only `id`, a string). Response relaxation strips
/// `additionalProperties: false`, so an unknown key is allowed either way and
/// cannot tell them apart — but a *type* violation still can. `{"detail": 123}`
/// is invalid under 400 and valid under 404, where `detail` is simply unknown.
///
/// The 404 is validated first on purpose: it is the call that would poison the
/// entry.
#[test]
fn a_cached_response_validator_does_not_answer_for_another_status() {
    let catalog = Catalog::embedded().expect("embedded catalog");

    let body = || MistResponseBody::Json(serde_json::json!({ "detail": 123 }));
    let response = |status: u16| MistResponse {
        operation_id: "deleteInstallerMap".to_owned(),
        status,
        body: body(),
        cursor: None,
    };

    assert!(
        response(404).validate(&catalog, &origin()).is_ok(),
        "under 404 `detail` is an unknown key, which relaxation permits"
    );
    assert!(
        response(400).validate(&catalog, &origin()).is_err(),
        "under 400 `detail` is declared a string and 123 is not one. Accepting \
         it means the 404 validator answered for status 400 — the cache key is \
         missing the status."
    );
}
