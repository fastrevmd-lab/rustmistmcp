# WAN Edge Read Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ten scope-collapsed WAN edge (SRX/SSR) read tools so an operator can troubleshoot a WAN edge and read its configuration objects by name rather than by catalog ID.

**Architecture:** Each new tool is a thin `#[tool]` method that resolves selector arguments to exactly one `&'static str` catalog operation ID and its path-parameter names, then calls the existing `dispatch_named`. The collapse lives entirely in the tool signature; authorization, cursors, and bounding are unchanged. Selector fields are `skip_serializing` so they never leak into the Mist query string.

**Tech Stack:** Rust 2024, MSRV 1.88, `rmcp` 3.1 `#[tool]`/`#[tool_router]` macros, `schemars` for tool schemas, `serde` for argument mapping, `mecmcp` v0.8.8 pinned at `850f529`.

## Global Constraints

- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn. Tests may use `expect`, matching existing test style.
- Every new tool must be added in **three** places or the contract test fails: the `#[tool]` method, `KNOWN_TOOLS`, and `EXPECTED` in `crates/rustmistmcp/tests/tool_contract.rs`.
- `KNOWN_TOOLS` is asserted equal to `EXPECTED` **in order** — the list is alphabetically sorted. Insert new names in sorted position.
- All ten tools are `MistCapability::OrdinaryRead`. None are added to `RESTRICTED_TOOLS`.
- Every args struct carries `#[serde(deny_unknown_fields)]` (the `read_args!` macro applies it). The contract test asserts `additionalProperties: false` on every tool schema.
- `limit` is validated 1..=100 by `validate_page_limit`; declare it as `#[schemars(range(min = 1, max = 100))] limit: Option<u32>`.
- Do not add composite tools that issue more than one Mist request. One tool, one request.
- Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` before each commit.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/rustmistmcp/src/server/wan.rs` | **New.** Selector enums, scope resolution, and the operation-resolution functions for all ten tools. Pure logic, no I/O — unit-testable without a client. | Create |
| `crates/rustmistmcp/src/server/mod.rs` | Tool methods, args structs, `KNOWN_TOOLS`, `MistCallError::AmbiguousScope`. | Modify |
| `crates/rustmistmcp/tests/wan_tools.rs` | **New.** Integration tests driving the real tool router with `RecordingClient`, asserting resolved operation IDs and query contents. | Create |
| `crates/rustmistmcp/tests/tool_contract.rs` | `EXPECTED` tool list. | Modify: `:24-47` |
| `README.md` | Tool table. | Modify |

`wan.rs` exists so the resolution logic is testable as pure functions and `mod.rs` — already ~1600 lines — does not absorb another 400. Resolution is the new failure mode, so it gets its own unit tests in-file plus integration tests that prove the wiring.

---

### Task 1: Scope resolution and selector plumbing

**Files:**
- Create: `crates/rustmistmcp/src/server/wan.rs`
- Modify: `crates/rustmistmcp/src/server/mod.rs` (add `mod wan;`, add error variant)
- Test: unit tests inside `crates/rustmistmcp/src/server/wan.rs`

**Interfaces:**
- Produces: `pub(crate) enum WanScope { Org, Site }`; `pub(crate) enum StatsMode { Records, Count }`; `pub(crate) fn resolve_scope(org_id: Option<&str>, site_id: Option<&str>) -> Result<WanScope, ScopeError>`; `pub(crate) struct Resolved { pub operation_id: &'static str, pub path_names: &'static [&'static str] }`
- Consumes: nothing.

- [ ] **Step 1: Write the failing test**

Create `crates/rustmistmcp/src/server/wan.rs` with only this content:

```rust
//! Selector resolution for the collapsed WAN edge tools.
//!
//! These tools accept a selector (scope, mode, object) and resolve it to
//! exactly one catalog operation before dispatch. Resolution is pure so it can
//! be tested without a client; the wiring is proven separately in
//! `tests/wan_tools.rs`.

/// Which scope a collapsed tool was called with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WanScope {
    /// Organization-scoped variant.
    Org,
    /// Site-scoped variant.
    Site,
}

/// Whether a stats tool returns records or a count distribution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum StatsMode {
    /// Return matching records.
    #[default]
    Records,
    /// Return a count distribution.
    Count,
}

/// One resolved dispatch target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Resolved {
    /// Exact catalog operation ID.
    pub operation_id: &'static str,
    /// Names this operation carries in its path rather than its query.
    pub path_names: &'static [&'static str],
}

/// Exactly one of `org_id` or `site_id` is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScopeError;

/// Resolve exactly-one-of `org_id`/`site_id`.
pub(crate) fn resolve_scope(
    org_id: Option<&str>,
    site_id: Option<&str>,
) -> Result<WanScope, ScopeError> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_requires_exactly_one_identifier() {
        assert_eq!(resolve_scope(Some("org"), None), Ok(WanScope::Org));
        assert_eq!(resolve_scope(None, Some("site")), Ok(WanScope::Site));
        assert_eq!(resolve_scope(None, None), Err(ScopeError));
        assert_eq!(resolve_scope(Some("org"), Some("site")), Err(ScopeError));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --lib wan::tests 2>&1 | tail -20`
Expected: FAIL — panics at `unimplemented!()`. (`mod wan;` is added in step 3, so this first run may instead fail to compile with "file not found for module"; that is the same signal.)

- [ ] **Step 3: Write minimal implementation**

In `crates/rustmistmcp/src/server/mod.rs`, add the module declaration next to the other `mod`/`use` items near the top of the file:

```rust
mod wan;
```

Replace the `unimplemented!()` body in `wan.rs`:

```rust
pub(crate) fn resolve_scope(
    org_id: Option<&str>,
    site_id: Option<&str>,
) -> Result<WanScope, ScopeError> {
    match (org_id, site_id) {
        (Some(_), None) => Ok(WanScope::Org),
        (None, Some(_)) => Ok(WanScope::Site),
        _ => Err(ScopeError),
    }
}
```

In `mod.rs`, add a variant to `enum MistCallError` (around line 649), after `InvalidSearch`:

```rust
    #[error("exactly one of org_id or site_id is required")]
    AmbiguousScope,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p rustmistmcp --lib wan::tests 2>&1 | tail -10`
Expected: PASS — `test result: ok. 1 passed`

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/rustmistmcp/src/server/wan.rs crates/rustmistmcp/src/server/mod.rs
git commit -m "feat(wan): add scope and mode selectors for collapsed WAN tools"
```

---

### Task 2: `list_mist_wan_edges`

Collapses `searchOrgDevices` / `searchSiteDevices`, forcing `type=gateway`.

**Files:**
- Modify: `crates/rustmistmcp/src/server/wan.rs`
- Modify: `crates/rustmistmcp/src/server/mod.rs`
- Modify: `crates/rustmistmcp/tests/tool_contract.rs:24-47`
- Test: `crates/rustmistmcp/tests/wan_tools.rs` (create)

**Interfaces:**
- Consumes: `WanScope`, `Resolved`, `resolve_scope`, `MistCallError::AmbiguousScope` from Task 1.
- Produces: `pub(crate) fn wan_edges(scope: WanScope) -> Resolved`.

- [ ] **Step 1: Write the failing test**

Append to `wan.rs` inside `mod tests`:

```rust
    #[test]
    fn wan_edges_resolves_per_scope() {
        assert_eq!(
            wan_edges(WanScope::Org),
            Resolved { operation_id: "searchOrgDevices", path_names: &["org_id"] }
        );
        assert_eq!(
            wan_edges(WanScope::Site),
            Resolved { operation_id: "searchSiteDevices", path_names: &["site_id"] }
        );
    }
```

Create `crates/rustmistmcp/tests/wan_tools.rs`:

```rust
//! Integration contracts for the collapsed WAN edge tools.
//!
//! These drive the real tool router and assert which catalog operation each
//! selector combination resolved to. A unit test of the resolver alone cannot
//! prove the tool is wired to it.

use async_trait::async_trait;
use rmcp::{ServiceExt, model::CallToolRequestParams};
use rustmistmcp::MistHandler;
use rustmistmcp_core::{
    MistClient, MistError, MistRequest, MistResponse, MistResponseBody,
};
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
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(serde_json::json!({"results": []})),
            cursor: None,
        })
    }
}

/// Call one tool against a recording client and return the request it issued.
///
/// A tool that fails validation returns `Ok` with `is_error == Some(true)`
/// rather than `Err`, so both are mapped to `Err` here — otherwise the
/// rejection tests would pass for the wrong reason.
async fn record_call(
    tool: &str,
    arguments: serde_json::Value,
) -> Result<MistRequest, String> {
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
        return Err(format!("tool returned an error result: {result:?}"));
    }
    let requests = recorder.requests.lock().expect("request recorder");
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

    let site = record_call("list_mist_wan_edges", serde_json::json!({"site_id": SITE_ID}))
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools 2>&1 | tail -20`
Expected: FAIL to compile — `wan_edges` not found, `list_mist_wan_edges` is not a registered tool.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve the gateway inventory search for a scope.
pub(crate) fn wan_edges(scope: WanScope) -> Resolved {
    match scope {
        WanScope::Org => Resolved {
            operation_id: "searchOrgDevices",
            path_names: &["org_id"],
        },
        WanScope::Site => Resolved {
            operation_id: "searchSiteDevices",
            path_names: &["site_id"],
        },
    }
}
```

In `mod.rs`, next to the other `read_args!` invocations:

```rust
/// The device type this tool is permitted to enumerate.
fn gateway_device_type() -> String {
    "gateway".to_owned()
}

read_args!(WanEdgeListArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    hostname: Option<String>,
    mac: Option<String>,
    model: Option<String>,
    version: Option<String>,
    /// Always `gateway`. Not caller-settable: this tool must not enumerate
    /// APs or switches.
    #[serde(rename = "type", skip_deserializing, default = "gateway_device_type")]
    #[schemars(skip)]
    r#type: String,
});
```

Add the tool method inside the `#[tool_router]` impl block, in alphabetical position among the existing tools:

```rust
    #[tool(
        name = "list_mist_wan_edges",
        description = "List WAN edge gateways (SRX/SSR) in an organization or site."
    )]
    async fn list_mist_wan_edges(
        &self,
        Parameters(args): Parameters<WanEdgeListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        let resolved = wan::wan_edges(scope);
        Ok(self
            .dispatch_named(
                "list_mist_wan_edges",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"list_mist_wan_edges"` to `KNOWN_TOOLS` in sorted position (after `list_mist_upgrades`, before `list_mist_wlans`), and the same string in the same position in `EXPECTED` in `crates/rustmistmcp/tests/tool_contract.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp --lib wan::tests && cargo test -p rustmistmcp --test wan_tools && cargo test -p rustmistmcp --test tool_contract`
Expected: PASS on all three.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/wan.rs crates/rustmistmcp/src/server/mod.rs crates/rustmistmcp/tests/wan_tools.rs crates/rustmistmcp/tests/tool_contract.rs
git commit -m "feat(wan): add list_mist_wan_edges with forced gateway type"
```

---

### Task 3: `get_mist_wan_edge_stats`

Collapses `getSiteGatewayMetrics` (site-wide) and `getSiteInsightMetricsForGateway` (per-device). Presence of `device_id` selects the per-device variant.

**Files:**
- Modify: `crates/rustmistmcp/src/server/wan.rs`, `crates/rustmistmcp/src/server/mod.rs`, `crates/rustmistmcp/tests/tool_contract.rs`
- Test: `crates/rustmistmcp/tests/wan_tools.rs`

**Interfaces:**
- Consumes: `Resolved` from Task 1.
- Produces: `pub(crate) fn wan_edge_stats(per_device: bool) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn wan_edge_stats_selects_on_device_presence() {
        assert_eq!(
            wan_edge_stats(false),
            Resolved { operation_id: "getSiteGatewayMetrics", path_names: &["site_id"] }
        );
        assert_eq!(
            wan_edge_stats(true),
            Resolved {
                operation_id: "getSiteInsightMetricsForGateway",
                path_names: &["site_id", "device_id"],
            }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
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
        serde_json::json!({"site_id": SITE_ID, "device_id": "00000000-0000-0000-0000-00000000abcd"}),
    )
    .await
    .expect("device call");
    assert_eq!(device.operation_id, "getSiteInsightMetricsForGateway");
    assert!(
        !device.query.contains_key("device_id"),
        "device_id belongs in the path, not the query"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools wan_edge_stats 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve gateway stats to the site-wide or per-device operation.
pub(crate) fn wan_edge_stats(per_device: bool) -> Resolved {
    if per_device {
        Resolved {
            operation_id: "getSiteInsightMetricsForGateway",
            path_names: &["site_id", "device_id"],
        }
    } else {
        Resolved {
            operation_id: "getSiteGatewayMetrics",
            path_names: &["site_id"],
        }
    }
}
```

In `mod.rs`:

```rust
read_args!(WanEdgeStatsArgs {
    /// Site UUID.
    site_id: String,
    /// Gateway device UUID. When present, returns per-device insight metrics.
    device_id: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
});
```

```rust
    #[tool(
        name = "get_mist_wan_edge_stats",
        description = "Get WAN edge gateway metrics for a site, or insight metrics for one gateway."
    )]
    async fn get_mist_wan_edge_stats(
        &self,
        Parameters(args): Parameters<WanEdgeStatsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::wan_edge_stats(args.device_id.is_some());
        Ok(self
            .dispatch_named(
                "get_mist_wan_edge_stats",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"get_mist_wan_edge_stats"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `get_mist_sle`, before `invoke_mist_privileged_read`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp 2>&1 | grep -E "^test result"`
Expected: all suites PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat(wan): add get_mist_wan_edge_stats"
```

---

### Task 4: `search_mist_tunnels`

Collapses `searchOrgTunnelsStats` / `countOrgTunnelsStats` on `mode`.

**Files:**
- Modify: `crates/rustmistmcp/src/server/wan.rs`, `crates/rustmistmcp/src/server/mod.rs`, `crates/rustmistmcp/tests/tool_contract.rs`
- Test: `crates/rustmistmcp/tests/wan_tools.rs`

**Interfaces:**
- Consumes: `StatsMode`, `Resolved`.
- Produces: `pub(crate) fn tunnels(mode: StatsMode) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn tunnels_resolve_per_mode() {
        assert_eq!(
            tunnels(StatsMode::Records),
            Resolved { operation_id: "searchOrgTunnelsStats", path_names: &["org_id"] }
        );
        assert_eq!(
            tunnels(StatsMode::Count),
            Resolved { operation_id: "countOrgTunnelsStats", path_names: &["org_id"] }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools tunnels 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve WAN IPsec tunnel stats for a mode.
pub(crate) fn tunnels(mode: StatsMode) -> Resolved {
    match mode {
        StatsMode::Records => Resolved {
            operation_id: "searchOrgTunnelsStats",
            path_names: &["org_id"],
        },
        StatsMode::Count => Resolved {
            operation_id: "countOrgTunnelsStats",
            path_names: &["org_id"],
        },
    }
}
```

In `mod.rs`, add the wire enum next to the other selector enums. It must derive `Deserialize`/`JsonSchema` for the tool schema and convert into the pure `wan::StatsMode`:

```rust
/// Whether a stats tool returns records or a count distribution.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum StatsModeArg {
    /// Return matching records.
    #[default]
    Records,
    /// Return a count distribution. The response shape differs from records.
    Count,
}

impl From<StatsModeArg> for wan::StatsMode {
    fn from(value: StatsModeArg) -> Self {
        match value {
            StatsModeArg::Records => Self::Records,
            StatsModeArg::Count => Self::Count,
        }
    }
}
```

```rust
read_args!(TunnelSearchArgs {
    /// Organization UUID.
    org_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});
```

```rust
    #[tool(
        name = "search_mist_tunnels",
        description = "Search WAN edge IPsec tunnel stats, or count them by a distinct field."
    )]
    async fn search_mist_tunnels(
        &self,
        Parameters(args): Parameters<TunnelSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::tunnels(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_tunnels",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"search_mist_tunnels"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `search_mist_service_path_events` once Task 7 lands; for now after `search_mist_operations`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat(wan): add search_mist_tunnels"
```

---

### Task 5: `search_mist_peer_paths`

Collapses `searchOrgPeerPathStats` / `countOrgPeerPathStats` on `mode`. Same shape as Task 4.

**Files:** same set as Task 4.

**Interfaces:**
- Consumes: `StatsMode`, `Resolved`, `StatsModeArg`.
- Produces: `pub(crate) fn peer_paths(mode: StatsMode) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn peer_paths_resolve_per_mode() {
        assert_eq!(
            peer_paths(StatsMode::Records),
            Resolved { operation_id: "searchOrgPeerPathStats", path_names: &["org_id"] }
        );
        assert_eq!(
            peer_paths(StatsMode::Count),
            Resolved { operation_id: "countOrgPeerPathStats", path_names: &["org_id"] }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
#[tokio::test]
async fn peer_paths_resolve_mode() {
    let records = record_call("search_mist_peer_paths", serde_json::json!({"org_id": ORG_ID}))
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools peer_paths 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve SD-WAN overlay peer path stats for a mode.
pub(crate) fn peer_paths(mode: StatsMode) -> Resolved {
    match mode {
        StatsMode::Records => Resolved {
            operation_id: "searchOrgPeerPathStats",
            path_names: &["org_id"],
        },
        StatsMode::Count => Resolved {
            operation_id: "countOrgPeerPathStats",
            path_names: &["org_id"],
        },
    }
}
```

In `mod.rs`:

```rust
read_args!(PeerPathSearchArgs {
    /// Organization UUID.
    org_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});
```

```rust
    #[tool(
        name = "search_mist_peer_paths",
        description = "Search SD-WAN overlay peer path stats, or count them by a distinct field."
    )]
    async fn search_mist_peer_paths(
        &self,
        Parameters(args): Parameters<PeerPathSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::peer_paths(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_peer_paths",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"search_mist_peer_paths"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat(wan): add search_mist_peer_paths"
```

---

### Task 6: `search_mist_bgp_peers`

The widest collapse: four operations across scope × mode.

**Files:** same set as Task 4.

**Interfaces:**
- Consumes: `WanScope`, `StatsMode`, `Resolved`, `resolve_scope`, `StatsModeArg`.
- Produces: `pub(crate) fn bgp_peers(scope: WanScope, mode: StatsMode) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn bgp_peers_resolve_all_four_combinations() {
        assert_eq!(
            bgp_peers(WanScope::Org, StatsMode::Records),
            Resolved { operation_id: "searchOrgBgpStats", path_names: &["org_id"] }
        );
        assert_eq!(
            bgp_peers(WanScope::Org, StatsMode::Count),
            Resolved { operation_id: "countOrgBgpStats", path_names: &["org_id"] }
        );
        assert_eq!(
            bgp_peers(WanScope::Site, StatsMode::Records),
            Resolved { operation_id: "searchSiteBgpStats", path_names: &["site_id"] }
        );
        assert_eq!(
            bgp_peers(WanScope::Site, StatsMode::Count),
            Resolved { operation_id: "countSiteBgpStats", path_names: &["site_id"] }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
#[tokio::test]
async fn bgp_peers_resolve_scope_and_mode() {
    for (args, expected) in [
        (serde_json::json!({"org_id": ORG_ID}), "searchOrgBgpStats"),
        (serde_json::json!({"org_id": ORG_ID, "mode": "count"}), "countOrgBgpStats"),
        (serde_json::json!({"site_id": SITE_ID}), "searchSiteBgpStats"),
        (serde_json::json!({"site_id": SITE_ID, "mode": "count"}), "countSiteBgpStats"),
    ] {
        let request = record_call("search_mist_bgp_peers", args.clone())
            .await
            .unwrap_or_else(|error| panic!("call {args} failed: {error}"));
        assert_eq!(request.operation_id, expected, "for {args}");
    }

    assert!(
        record_call("search_mist_bgp_peers", serde_json::json!({"mode": "count"}))
            .await
            .is_err(),
        "missing scope must be refused"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools bgp 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve BGP peer stats for a scope and mode.
pub(crate) fn bgp_peers(scope: WanScope, mode: StatsMode) -> Resolved {
    match (scope, mode) {
        (WanScope::Org, StatsMode::Records) => Resolved {
            operation_id: "searchOrgBgpStats",
            path_names: &["org_id"],
        },
        (WanScope::Org, StatsMode::Count) => Resolved {
            operation_id: "countOrgBgpStats",
            path_names: &["org_id"],
        },
        (WanScope::Site, StatsMode::Records) => Resolved {
            operation_id: "searchSiteBgpStats",
            path_names: &["site_id"],
        },
        (WanScope::Site, StatsMode::Count) => Resolved {
            operation_id: "countSiteBgpStats",
            path_names: &["site_id"],
        },
    }
}
```

In `mod.rs`:

```rust
read_args!(BgpPeerSearchArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});
```

```rust
    #[tool(
        name = "search_mist_bgp_peers",
        description = "Search WAN edge BGP peer stats in an organization or site, or count them."
    )]
    async fn search_mist_bgp_peers(
        &self,
        Parameters(args): Parameters<BgpPeerSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        let resolved = wan::bgp_peers(scope, args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_bgp_peers",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"search_mist_bgp_peers"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `search_mist_audit_logs`, before `search_mist_clients`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat(wan): add search_mist_bgp_peers across scope and mode"
```

---

### Task 7: `search_mist_service_path_events`

Collapses `searchSiteServicePathEvents` / `countSiteServicePathEvents` on `mode`. Completes PR 1.

**Files:** same set as Task 4, plus `README.md`.

**Interfaces:**
- Consumes: `StatsMode`, `Resolved`, `StatsModeArg`.
- Produces: `pub(crate) fn service_path_events(mode: StatsMode) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn service_path_events_resolve_per_mode() {
        assert_eq!(
            service_path_events(StatsMode::Records),
            Resolved { operation_id: "searchSiteServicePathEvents", path_names: &["site_id"] }
        );
        assert_eq!(
            service_path_events(StatsMode::Count),
            Resolved { operation_id: "countSiteServicePathEvents", path_names: &["site_id"] }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
#[tokio::test]
async fn service_path_events_resolve_mode() {
    let records = record_call(
        "search_mist_service_path_events",
        serde_json::json!({"site_id": SITE_ID}),
    )
    .await
    .expect("records call");
    assert_eq!(records.operation_id, "searchSiteServicePathEvents");

    let counted = record_call(
        "search_mist_service_path_events",
        serde_json::json!({"site_id": SITE_ID, "mode": "count"}),
    )
    .await
    .expect("count call");
    assert_eq!(counted.operation_id, "countSiteServicePathEvents");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools service_path 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve service path events for a mode.
pub(crate) fn service_path_events(mode: StatsMode) -> Resolved {
    match mode {
        StatsMode::Records => Resolved {
            operation_id: "searchSiteServicePathEvents",
            path_names: &["site_id"],
        },
        StatsMode::Count => Resolved {
            operation_id: "countSiteServicePathEvents",
            path_names: &["site_id"],
        },
    }
}
```

In `mod.rs`:

```rust
read_args!(ServicePathEventArgs {
    /// Site UUID.
    site_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});
```

```rust
    #[tool(
        name = "search_mist_service_path_events",
        description = "Search WAN edge service path events for a site, or count them."
    )]
    async fn search_mist_service_path_events(
        &self,
        Parameters(args): Parameters<ServicePathEventArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::service_path_events(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_service_path_events",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"search_mist_service_path_events"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `search_mist_operations`, before `search_mist_tunnels`). Verify the whole list is still alphabetically sorted.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Update the README tool table and commit**

In `README.md`, add the six new tools to the tool table with one-line descriptions matching the `#[tool]` `description` strings.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(wan): add search_mist_service_path_events and document the diagnostic tools"
```

**PR 1 boundary.** Open a PR with Tasks 1–7: six diagnostic tools, the collapse pattern, and its tests.

---

### Task 8: `get_mist_sle_impact`

Collapses three SLE impact operations on an `impact` selector.

**Files:** same set as Task 4.

**Interfaces:**
- Consumes: `Resolved`.
- Produces: `pub(crate) enum SleImpact { Gateways, Applications, Summary }`; `pub(crate) fn sle_impact(impact: SleImpact) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn sle_impact_resolves_per_selector() {
        const PATHS: &[&str] = &["site_id", "scope", "scope_id", "metric"];
        assert_eq!(
            sle_impact(SleImpact::Gateways),
            Resolved { operation_id: "listSiteSleImpactedGateways", path_names: PATHS }
        );
        assert_eq!(
            sle_impact(SleImpact::Applications),
            Resolved { operation_id: "listSiteSleImpactedApplications", path_names: PATHS }
        );
        assert_eq!(
            sle_impact(SleImpact::Summary),
            Resolved { operation_id: "getSiteSleImpactSummary", path_names: PATHS }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools sle_impact 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Which SLE impact view to return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SleImpact {
    /// Gateways impacted by the metric.
    Gateways,
    /// Applications impacted by the metric.
    Applications,
    /// Aggregate impact summary.
    Summary,
}

/// Resolve an SLE impact view.
pub(crate) fn sle_impact(impact: SleImpact) -> Resolved {
    const PATHS: &[&str] = &["site_id", "scope", "scope_id", "metric"];
    let operation_id = match impact {
        SleImpact::Gateways => "listSiteSleImpactedGateways",
        SleImpact::Applications => "listSiteSleImpactedApplications",
        SleImpact::Summary => "getSiteSleImpactSummary",
    };
    Resolved { operation_id, path_names: PATHS }
}
```

In `mod.rs`:

```rust
/// Which SLE impact view a caller wants.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SleImpactArg {
    /// Gateways impacted by the metric.
    Gateways,
    /// Applications impacted by the metric.
    Applications,
    /// Aggregate impact summary.
    Summary,
}

impl From<SleImpactArg> for wan::SleImpact {
    fn from(value: SleImpactArg) -> Self {
        match value {
            SleImpactArg::Gateways => Self::Gateways,
            SleImpactArg::Applications => Self::Applications,
            SleImpactArg::Summary => Self::Summary,
        }
    }
}

read_args!(SleImpactArgs {
    /// Site UUID.
    site_id: String,
    /// SLE scope, e.g. `site`.
    scope: String,
    /// Identifier for the chosen scope.
    scope_id: String,
    /// SLE metric name.
    metric: String,
    /// Which impact view to return. Not sent to Mist.
    #[serde(skip_serializing)]
    impact: SleImpactArg,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
});
```

```rust
    #[tool(
        name = "get_mist_sle_impact",
        description = "Get gateways, applications, or the summary impacted by one site SLE metric."
    )]
    async fn get_mist_sle_impact(
        &self,
        Parameters(args): Parameters<SleImpactArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::sle_impact(args.impact.into());
        Ok(self
            .dispatch_named(
                "get_mist_sle_impact",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"get_mist_sle_impact"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `get_mist_sle`, before `get_mist_wan_edge_stats`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat(wan): add get_mist_sle_impact"
```

---

### Task 9: `list_mist_applications`

Collapses `listSiteApps`, `countSiteApps`, and the `listGatewayApplications` constant catalog. Completes PR 2.

**Files:** same set as Task 4, plus `README.md`.

**Interfaces:**
- Consumes: `StatsMode`, `Resolved`, `StatsModeArg`.
- Produces: `pub(crate) enum AppSource { Site, Catalog }`; `pub(crate) fn applications(source: AppSource, mode: StatsMode) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn applications_resolve_source_and_mode() {
        assert_eq!(
            applications(AppSource::Site, StatsMode::Records),
            Resolved { operation_id: "listSiteApps", path_names: &["site_id"] }
        );
        assert_eq!(
            applications(AppSource::Site, StatsMode::Count),
            Resolved { operation_id: "countSiteApps", path_names: &["site_id"] }
        );
        // The constant catalog has no scope and no count variant; mode is ignored.
        assert_eq!(
            applications(AppSource::Catalog, StatsMode::Count),
            Resolved { operation_id: "listGatewayApplications", path_names: &[] }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
#[tokio::test]
async fn applications_resolve_source_and_mode() {
    let site = record_call(
        "list_mist_applications",
        serde_json::json!({"source": "site", "site_id": SITE_ID}),
    )
    .await
    .expect("site call");
    assert_eq!(site.operation_id, "listSiteApps");

    let counted = record_call(
        "list_mist_applications",
        serde_json::json!({"source": "site", "site_id": SITE_ID, "mode": "count"}),
    )
    .await
    .expect("count call");
    assert_eq!(counted.operation_id, "countSiteApps");

    let catalog = record_call("list_mist_applications", serde_json::json!({"source": "catalog"}))
        .await
        .expect("catalog call");
    assert_eq!(catalog.operation_id, "listGatewayApplications");
}

#[tokio::test]
async fn applications_require_site_id_for_the_site_source() {
    assert!(
        record_call("list_mist_applications", serde_json::json!({"source": "site"}))
            .await
            .is_err(),
        "site source without site_id must be refused"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools applications 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Where the application list comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppSource {
    /// Applications observed at a site.
    Site,
    /// The constant gateway application catalog.
    Catalog,
}

/// Resolve an application listing.
///
/// The constant catalog is org- and site-independent and has no count variant,
/// so `mode` is ignored for [`AppSource::Catalog`].
pub(crate) fn applications(source: AppSource, mode: StatsMode) -> Resolved {
    match (source, mode) {
        (AppSource::Site, StatsMode::Records) => Resolved {
            operation_id: "listSiteApps",
            path_names: &["site_id"],
        },
        (AppSource::Site, StatsMode::Count) => Resolved {
            operation_id: "countSiteApps",
            path_names: &["site_id"],
        },
        (AppSource::Catalog, _) => Resolved {
            operation_id: "listGatewayApplications",
            path_names: &[],
        },
    }
}
```

In `mod.rs`:

```rust
/// Where a caller wants the application list from.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum AppSourceArg {
    /// Applications observed at a site. Requires `site_id`.
    Site,
    /// The constant gateway application catalog. Takes no scope.
    Catalog,
}

impl From<AppSourceArg> for wan::AppSource {
    fn from(value: AppSourceArg) -> Self {
        match value {
            AppSourceArg::Site => Self::Site,
            AppSourceArg::Catalog => Self::Catalog,
        }
    }
}

read_args!(ApplicationListArgs {
    /// Where to read applications from. Not sent to Mist.
    #[serde(skip_serializing)]
    source: AppSourceArg,
    /// Site UUID. Required when `source` is `site`.
    site_id: Option<String>,
    /// Records or count distribution. Ignored for the constant catalog.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    distinct: Option<String>,
});
```

```rust
    #[tool(
        name = "list_mist_applications",
        description = "List applications seen at a site, count them, or list the gateway application catalog."
    )]
    async fn list_mist_applications(
        &self,
        Parameters(args): Parameters<ApplicationListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if matches!(args.source, AppSourceArg::Site) && args.site_id.is_none() {
            return Ok(tool_result::<ReadEnvelope, _>(
                Err(MistCallError::AmbiguousScope),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ));
        }
        let resolved = wan::applications(args.source.into(), args.mode.into());
        Ok(self
            .dispatch_named(
                "list_mist_applications",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"list_mist_applications"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (before `list_mist_orgs`).

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Update README and commit**

Add the two new tools to the README tool table.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(wan): add list_mist_applications"
```

**PR 2 boundary.** Open a PR with Tasks 8–9.

---

### Task 10: `list_mist_wan_config`

Lists any of the five WAN edge config object types, org-scoped or site-derived.

**Files:** same set as Task 4.

**Interfaces:**
- Consumes: `WanScope`, `Resolved`, `resolve_scope`.
- Produces: `pub(crate) enum WanObject { Network, Service, ServicePolicy, GatewayTemplate, DeviceProfile }`; `pub(crate) fn list_config(object: WanObject, scope: WanScope) -> Result<Resolved, ScopeError>`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn list_config_resolves_object_and_scope() {
        assert_eq!(
            list_config(WanObject::Network, WanScope::Org),
            Ok(Resolved { operation_id: "listOrgNetworks", path_names: &["org_id"] })
        );
        assert_eq!(
            list_config(WanObject::Network, WanScope::Site),
            Ok(Resolved { operation_id: "listSiteNetworksDerived", path_names: &["site_id"] })
        );
        assert_eq!(
            list_config(WanObject::GatewayTemplate, WanScope::Site),
            Ok(Resolved {
                operation_id: "listSiteGatewayTemplatesDerived",
                path_names: &["site_id"],
            })
        );
        // Device profiles have no site-derived listing.
        assert_eq!(list_config(WanObject::DeviceProfile, WanScope::Site), Err(ScopeError));
    }
```

In `tests/wan_tools.rs`:

```rust
#[tokio::test]
async fn wan_config_listing_resolves_object_and_scope() {
    for (object, scope_key, scope_value, expected) in [
        ("network", "org_id", ORG_ID, "listOrgNetworks"),
        ("service", "org_id", ORG_ID, "listOrgServices"),
        ("servicepolicy", "org_id", ORG_ID, "listOrgServicePolicies"),
        ("gatewaytemplate", "org_id", ORG_ID, "listOrgGatewayTemplates"),
        ("deviceprofile", "org_id", ORG_ID, "listOrgDeviceProfiles"),
        ("network", "site_id", SITE_ID, "listSiteNetworksDerived"),
        ("service", "site_id", SITE_ID, "listSiteServicesDerived"),
        ("servicepolicy", "site_id", SITE_ID, "listSiteServicePoliciesDerived"),
        ("gatewaytemplate", "site_id", SITE_ID, "listSiteGatewayTemplatesDerived"),
    ] {
        let args = serde_json::json!({"object": object, scope_key: scope_value});
        let request = record_call("list_mist_wan_config", args.clone())
            .await
            .unwrap_or_else(|error| panic!("{args} failed: {error}"));
        assert_eq!(request.operation_id, expected, "for {args}");
        assert!(!request.query.contains_key("object"));
    }

    assert!(
        record_call(
            "list_mist_wan_config",
            serde_json::json!({"object": "deviceprofile", "site_id": SITE_ID}),
        )
        .await
        .is_err(),
        "device profiles have no site-derived listing"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools wan_config_listing 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// A WAN edge configuration object type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WanObject {
    /// A LAN segment / network.
    Network,
    /// An application or service definition.
    Service,
    /// A service (SD-WAN steering) policy.
    ServicePolicy,
    /// A gateway template.
    GatewayTemplate,
    /// A device profile.
    DeviceProfile,
}

/// Resolve a configuration listing.
///
/// Device profiles have no site-derived listing, so a site scope is refused
/// rather than silently answered with the org listing.
pub(crate) fn list_config(object: WanObject, scope: WanScope) -> Result<Resolved, ScopeError> {
    let resolved = match (object, scope) {
        (WanObject::Network, WanScope::Org) => Resolved {
            operation_id: "listOrgNetworks",
            path_names: &["org_id"],
        },
        (WanObject::Service, WanScope::Org) => Resolved {
            operation_id: "listOrgServices",
            path_names: &["org_id"],
        },
        (WanObject::ServicePolicy, WanScope::Org) => Resolved {
            operation_id: "listOrgServicePolicies",
            path_names: &["org_id"],
        },
        (WanObject::GatewayTemplate, WanScope::Org) => Resolved {
            operation_id: "listOrgGatewayTemplates",
            path_names: &["org_id"],
        },
        (WanObject::DeviceProfile, WanScope::Org) => Resolved {
            operation_id: "listOrgDeviceProfiles",
            path_names: &["org_id"],
        },
        (WanObject::Network, WanScope::Site) => Resolved {
            operation_id: "listSiteNetworksDerived",
            path_names: &["site_id"],
        },
        (WanObject::Service, WanScope::Site) => Resolved {
            operation_id: "listSiteServicesDerived",
            path_names: &["site_id"],
        },
        (WanObject::ServicePolicy, WanScope::Site) => Resolved {
            operation_id: "listSiteServicePoliciesDerived",
            path_names: &["site_id"],
        },
        (WanObject::GatewayTemplate, WanScope::Site) => Resolved {
            operation_id: "listSiteGatewayTemplatesDerived",
            path_names: &["site_id"],
        },
        (WanObject::DeviceProfile, WanScope::Site) => return Err(ScopeError),
    };
    Ok(resolved)
}
```

In `mod.rs`:

```rust
/// A WAN edge configuration object type.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WanObjectArg {
    /// A LAN segment / network.
    Network,
    /// An application or service definition.
    Service,
    /// A service (SD-WAN steering) policy.
    ServicePolicy,
    /// A gateway template.
    GatewayTemplate,
    /// A device profile. Org scope only.
    DeviceProfile,
}

impl From<WanObjectArg> for wan::WanObject {
    fn from(value: WanObjectArg) -> Self {
        match value {
            WanObjectArg::Network => Self::Network,
            WanObjectArg::Service => Self::Service,
            WanObjectArg::ServicePolicy => Self::ServicePolicy,
            WanObjectArg::GatewayTemplate => Self::GatewayTemplate,
            WanObjectArg::DeviceProfile => Self::DeviceProfile,
        }
    }
}

read_args!(WanConfigListArgs {
    /// Which configuration object type to list. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID for the derived listing. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    #[schemars(range(min = 1))]
    page: Option<u32>,
});
```

Note: `#[serde(rename_all = "lowercase")]` makes the wire values `network`, `service`, `servicepolicy`, `gatewaytemplate`, `deviceprofile`, matching the tests.

```rust
    #[tool(
        name = "list_mist_wan_config",
        description = "List WAN edge configuration objects: networks, services, service policies, gateway templates, or device profiles."
    )]
    async fn list_mist_wan_config(
        &self,
        Parameters(args): Parameters<WanConfigListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        let resolved = match wan::list_config(args.object.into(), scope) {
            Ok(resolved) => resolved,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                ));
            }
        };
        Ok(self
            .dispatch_named(
                "list_mist_wan_config",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
```

Add `"list_mist_wan_config"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `list_mist_upgrades`, before `list_mist_wan_edges`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat(wan): add list_mist_wan_config across five object types"
```

---

### Task 11: `get_mist_wan_config`

Gets one config object by ID. This is the write→read mapping `plan_mist_change` will reuse for `before`, so the operation IDs here must be exact.

**Files:** same set as Task 4, plus `README.md` and `docs/OPERATIONS.md`.

**Interfaces:**
- Consumes: `WanObject`, `Resolved`.
- Produces: `pub(crate) fn get_config(object: WanObject) -> Resolved`.

- [ ] **Step 1: Write the failing test**

In `wan.rs` `mod tests`:

```rust
    #[test]
    fn get_config_resolves_each_object() {
        assert_eq!(
            get_config(WanObject::Network),
            Resolved { operation_id: "getOrgNetwork", path_names: &["org_id", "network_id"] }
        );
        assert_eq!(
            get_config(WanObject::Service),
            Resolved { operation_id: "getOrgService", path_names: &["org_id", "service_id"] }
        );
        assert_eq!(
            get_config(WanObject::ServicePolicy),
            Resolved {
                operation_id: "getOrgServicePolicy",
                path_names: &["org_id", "servicepolicy_id"],
            }
        );
        assert_eq!(
            get_config(WanObject::GatewayTemplate),
            Resolved {
                operation_id: "getOrgGatewayTemplate",
                path_names: &["org_id", "gatewaytemplate_id"],
            }
        );
        assert_eq!(
            get_config(WanObject::DeviceProfile),
            Resolved {
                operation_id: "getOrgDeviceProfile",
                path_names: &["org_id", "deviceprofile_id"],
            }
        );
    }
```

In `tests/wan_tools.rs`:

```rust
#[tokio::test]
async fn wan_config_get_resolves_each_object_and_places_the_id_in_the_path() {
    const OBJECT_ID: &str = "33333333-3333-3333-3333-333333333333";
    for (object, expected) in [
        ("network", "getOrgNetwork"),
        ("service", "getOrgService"),
        ("servicepolicy", "getOrgServicePolicy"),
        ("gatewaytemplate", "getOrgGatewayTemplate"),
        ("deviceprofile", "getOrgDeviceProfile"),
    ] {
        let args = serde_json::json!({
            "object": object,
            "org_id": ORG_ID,
            "object_id": OBJECT_ID,
        });
        let request = record_call("get_mist_wan_config", args.clone())
            .await
            .unwrap_or_else(|error| panic!("{args} failed: {error}"));
        assert_eq!(request.operation_id, expected, "for {args}");
        assert!(
            !request.query.contains_key("object_id"),
            "the object id belongs in the path"
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test wan_tools wan_config_get 2>&1 | tail -15`
Expected: FAIL — tool not found.

- [ ] **Step 3: Write minimal implementation**

In `wan.rs`:

```rust
/// Resolve the single-object read for a configuration object type.
///
/// This mapping is what a future `plan_mist_change` uses to fetch the `before`
/// state its digest binds to, so each entry must name the exact catalog read
/// that corresponds to the write on the same object.
pub(crate) fn get_config(object: WanObject) -> Resolved {
    match object {
        WanObject::Network => Resolved {
            operation_id: "getOrgNetwork",
            path_names: &["org_id", "network_id"],
        },
        WanObject::Service => Resolved {
            operation_id: "getOrgService",
            path_names: &["org_id", "service_id"],
        },
        WanObject::ServicePolicy => Resolved {
            operation_id: "getOrgServicePolicy",
            path_names: &["org_id", "servicepolicy_id"],
        },
        WanObject::GatewayTemplate => Resolved {
            operation_id: "getOrgGatewayTemplate",
            path_names: &["org_id", "gatewaytemplate_id"],
        },
        WanObject::DeviceProfile => Resolved {
            operation_id: "getOrgDeviceProfile",
            path_names: &["org_id", "deviceprofile_id"],
        },
    }
}

/// The path parameter name carrying the object's own identifier.
pub(crate) fn object_id_name(object: WanObject) -> &'static str {
    match object {
        WanObject::Network => "network_id",
        WanObject::Service => "service_id",
        WanObject::ServicePolicy => "servicepolicy_id",
        WanObject::GatewayTemplate => "gatewaytemplate_id",
        WanObject::DeviceProfile => "deviceprofile_id",
    }
}
```

In `mod.rs`, the args struct takes a uniform `object_id` and the tool renames it to the per-object path name before dispatch. Because `dispatch_named` derives its maps from the serialized struct, build the maps directly here instead:

```rust
read_args!(WanConfigGetArgs {
    /// Which configuration object type to read. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Organization UUID.
    org_id: String,
    /// The object's own UUID. Not sent to Mist under this name.
    #[serde(skip_serializing)]
    object_id: String,
});
```

This tool cannot use `dispatch_named`, because `named_maps` keys the path map by
the struct's own field names and the object's identifier must be sent under a
different name per object type (`network_id`, `service_id`, and so on). Build
the path map directly and call `dispatch_catalogued_read`, which is what
`dispatch_named` itself calls and which returns `CallToolResult`:

```rust
    #[tool(
        name = "get_mist_wan_config",
        description = "Get one WAN edge configuration object by ID."
    )]
    async fn get_mist_wan_config(
        &self,
        Parameters(args): Parameters<WanConfigGetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let object: wan::WanObject = args.object.into();
        let resolved = wan::get_config(object);
        let path = BTreeMap::from([
            ("org_id".to_owned(), args.org_id),
            (wan::object_id_name(object).to_owned(), args.object_id),
        ]);
        Ok(self
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "get_mist_wan_config",
                    operation_id: resolved.operation_id.to_owned(),
                    path,
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                },
                &extensions,
            )
            .await)
    }
```

Add `"get_mist_wan_config"` to `KNOWN_TOOLS` and `EXPECTED` in sorted position (after `get_mist_sle_impact`, before `get_mist_wan_edge_stats`).

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace 2>&1 | grep -E "^test result"`
Expected: all PASS.

- [ ] **Step 5: Update docs and commit**

Add both config tools to the README tool table. In `docs/OPERATIONS.md`, add one paragraph under the WAN section noting that `get_mist_wan_config`'s object→operation mapping is the same mapping the change-set lifecycle will use to fetch `before`.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh
git add -A
git commit -m "feat(wan): add get_mist_wan_config and record the write-to-read mapping"
```

**PR 3 boundary.** Open a PR with Tasks 10–11. This completes the read surface; the change-set write plan follows in its own document.

---

## Self-Review

**Spec coverage.** Every tool in the spec's troubleshoot table maps to a task: `list_mist_wan_edges` (2), `get_mist_wan_edge_stats` (3), `search_mist_tunnels` (4), `search_mist_peer_paths` (5), `search_mist_bgp_peers` (6), `search_mist_service_path_events` (7), `get_mist_sle_impact` (8), `list_mist_applications` (9). Config reads: `list_mist_wan_config` (10), `get_mist_wan_config` (11). The spec's four change-set tools are deliberately **out of scope** for this plan and get their own document, as the spec's delivery sequencing requires.

Spec testing requirements covered: collapse correctness (every task), `type=gateway` forcing (Task 2), selector non-leakage (Tasks 4, 8, 10, 11). **Cursor binding across the collapse is not covered by a task here** — it is a property of `MistCursor`, already tested in `tool_contract.rs`, and adding a duplicate assertion per tool would be noise. If a reviewer wants it, add one assertion to Task 6 where the four-way collapse makes it most meaningful.

**Placeholder scan.** No TBD/TODO. One prose-only step exists — Task 11 Step 5's OPERATIONS.md paragraph — which is documentation, not code.

**Type consistency.** `Resolved`, `WanScope`, `StatsMode`, `ScopeError`, `SleImpact`, `AppSource`, `WanObject` are defined in Task 1, 8, 9, 10 respectively and used consistently thereafter. Wire enums (`StatsModeArg`, `SleImpactArg`, `AppSourceArg`, `WanObjectArg`) live in `mod.rs` with `From` impls into the pure `wan` types; the split exists because `schemars`/`serde` derives belong on the wire type and the resolver stays dependency-free. `list_config` returns `Result<Resolved, ScopeError>` while the other resolvers return `Resolved` — deliberate, because device profiles have no site-derived listing.
