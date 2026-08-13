# WAN Edge Change-Set Writes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four change-set tools that let an operator create and update WAN edge configuration objects through a plan → approve → apply → verify lifecycle, never as a direct write.

**Architecture:** `plan_mist_change` reads the target object's current state, merges the caller's patch onto it, and stages a `ChangeSetRecord` in `mecmcp-changeset`'s `ChangesetCoordinator`. `approve_mist_change_set` requires a second principal. `apply_mist_change_set` re-reads, refuses if the object moved, issues the write, then re-reads to verify. Mist-specific parts live in this repo; the state machine, persistence, and digests are upstream.

**Tech Stack:** Rust 2024, MSRV 1.88, `mecmcp-changeset` v0.8.8 (`ChangesetCoordinator`, `ChangeSetRecord`, `ChangeSetState`, digest helpers), `rmcp` 3.1 `#[tool]` macros, `serde_json` for merge-patch.

## Global Constraints

- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn. Tests may use `.expect(...)`.
- Every new tool must be registered in **five** places: the `#[tool]` method, `KNOWN_TOOLS`, `EXPECTED` in `crates/rustmistmcp/tests/tool_contract.rs`, and — because all four are write-capable — `RESTRICTED_TOOLS` and `EXPECTED_RESTRICTED`. `KNOWN_TOOLS`/`EXPECTED` and `RESTRICTED_TOOLS`/`EXPECTED_RESTRICTED` are asserted equal pairwise and must stay alphabetically sorted.
- Selector and control fields must never be serialized into the Mist query string. `named_maps` serializes every non-null arg field into the query map.
- `crates/rustmistmcp/src/server/wan.rs` must remain free of `serde`/`schemars` dependencies.
- Batch 1 covers **create and update only**, for five object types. `delete*`, `assignOrgDeviceProfile`, and `unassignOrgDeviceProfile` are **out of scope** and must not be reachable.
- Any request body containing `mist_configured` must be **refused at plan time**, before a change set exists.
- Documentation must not claim more than is true.
- Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` before each commit. Commit files by explicit path; never `git add -A`.

## Verified upstream API (do not re-derive)

From `mecmcp-changeset` v0.8.8, pinned at rev `850f529`:

```rust
ChangesetCoordinator::load(path: Option<&Path>, limits: OperationLimits, approval_ttl: Duration, lab_mode: bool) -> Result<Self, CoordinatorError>
coordinator.insert_change_set(record: ChangeSetRecord) -> Result<(), CoordinatorError>   // async
coordinator.change_set(id: &str, device: &str) -> Result<ChangeSetRecord, CoordinatorError> // async
coordinator.update_change_set(record: ChangeSetRecord) -> Result<(), CoordinatorError>   // async
coordinator.device_guard(endpoint: &str, cancellation: &CancellationToken) -> Result<OwnedMutexGuard<()>, CoordinatorError> // async

change_set_digest<A: Serialize>(owner: &str, device: &str, fingerprint: &str, actions: &[A]) -> Result<String, DigestError>
preview_digest(artifact: &str) -> String
compute_approval_digest(change_set_id: &str, plan_digest: &str, owner: &str, approver: &str, approved_at_unix: u64) -> String
validate_digest(value: &str, field: &'static str) -> Result<(), DigestError>
```

`ChangeSetRecord` fields: `id`, `owner`, `device`, `expected_candidate_fingerprint`, `actions: Vec<serde_json::Value>`, `digest`, `state: ChangeSetState`, `approver: Option<String>`, `approval: Option<ApprovalRecord>`.

`ChangeSetState`: `Planned` → `Approved` → `Applying` → `Applied` | `Expired` | `Failed` | `Cancelled`.

`ApprovalRecord` fields: `approver: Option<String>`, `approved_at_unix: u64`, `digest: String`.

`OperationLimits` fields: `max_operations`, `max_change_sets`, `max_actions_per_set`, `max_change_set_bytes`, `max_state_bytes`, `max_targets_per_set`.

**`MistRequest` already supports writes**: it has `json: Option<serde_json::Value>`, and `validate_json_body` enforces it against the catalog's `request_body_required`. No core change is needed to send a body.

## The mapping decision that shapes everything

`ChangeSetRecord.device` is also the key `device_guard` locks on, so it is the **concurrency unit**. Mist has no devices. **`device` is the object being changed**, formatted `"<object>/<uuid>"` — e.g. `network/2b0f…`. Consequences:

- Two operators editing different networks in the same org proceed in parallel.
- Two edits to the same network serialize.
- Changes to *different* objects that reference each other (a service policy and the service it steers) are **not** serialized against each other. That is a known, accepted limitation of this granularity; do not silently widen the key to compensate.

For a **create**, no object UUID exists yet, so `device` is `"<object>/new"` — meaning concurrent creates of the same object type serialize. That is deliberate and cheap.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/rustmistmcp/src/server/wan_write.rs` | **New.** Write-target mapping (write op ↔ its read op ↔ object identity), merge-patch, `mist_configured` refusal. Pure logic, no I/O, no coordinator. | Create |
| `crates/rustmistmcp/src/server/change_set.rs` | **New.** The four tools' bodies: staging, retrieval, approval, apply-and-verify. Holds the coordinator interaction. | Create |
| `crates/rustmistmcp/src/server/mod.rs` | `#[tool]` methods delegating to `change_set.rs`, args structs, `KNOWN_TOOLS`, `RESTRICTED_TOOLS`, coordinator field on `MistHandler`. | Modify |
| `crates/rustmistmcp/tests/change_set_tools.rs` | **New.** Integration tests driving the real router through the full lifecycle against a recording client. | Create |
| `crates/rustmistmcp/tests/tool_contract.rs` | `EXPECTED`, `EXPECTED_RESTRICTED`. | Modify |
| `README.md`, `docs/OPERATIONS.md` | Tool table row(s); operator guidance on the lifecycle and the state file. | Modify |

`wan_write.rs` is separate from `change_set.rs` because the mapping and merge are pure and heavily tested, while the lifecycle is stateful and async. Splitting them keeps the pure half testable without a coordinator.

---

### Task 1: Write-target mapping

**Files:**
- Create: `crates/rustmistmcp/src/server/wan_write.rs`
- Modify: `crates/rustmistmcp/src/server/mod.rs` (add `mod wan_write;`)
- Test: unit tests inside `wan_write.rs`

**Interfaces:**
- Consumes: `wan::WanObject` from `crates/rustmistmcp/src/server/wan.rs`.
- Produces: `pub(crate) enum WriteVerb { Create, Update }`; `pub(crate) struct WriteTarget { pub write_operation_id: &'static str, pub read_operation_id: &'static str, pub id_path_name: &'static str, pub privileged: bool }`; `pub(crate) fn write_target(object: wan::WanObject, verb: WriteVerb) -> WriteTarget`.

- [ ] **Step 1: Write the failing test**

Create `crates/rustmistmcp/src/server/wan_write.rs`:

```rust
//! Write targets for WAN edge configuration objects.
//!
//! Each write operation is paired with the read that produces the `before`
//! state its digest binds to. That pairing is the reason this module exists:
//! a change set whose `before` came from the wrong read binds its digest to
//! the wrong object's state, which is worse than no digest because the audit
//! record still says the change was digest-bound.

use crate::server::wan::WanObject;

/// Which write a change set performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteVerb {
    /// Create a new object. Has no prior state.
    Create,
    /// Update an existing object.
    Update,
}

/// One write operation and the read that produces its `before` state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WriteTarget {
    /// Catalog operation ID for the write.
    pub write_operation_id: &'static str,
    /// Catalog operation ID for the read that produces `before`.
    ///
    /// For a create this is the read that would fetch the object once it
    /// exists; it is not called at plan time, because a create has no prior
    /// state.
    pub read_operation_id: &'static str,
    /// Path parameter name carrying the object's own identifier.
    pub id_path_name: &'static str,
    /// Whether this object's operations are `privileged_read`/privileged write.
    pub privileged: bool,
}

/// Resolve the write target for an object and verb.
pub(crate) fn write_target(object: WanObject, verb: WriteVerb) -> WriteTarget {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_targets_pair_each_write_with_its_own_read() {
        let network = write_target(WanObject::Network, WriteVerb::Update);
        assert_eq!(network.write_operation_id, "updateOrgNetwork");
        assert_eq!(network.read_operation_id, "getOrgNetwork");
        assert_eq!(network.id_path_name, "network_id");
        assert!(!network.privileged);

        let template = write_target(WanObject::GatewayTemplate, WriteVerb::Update);
        assert_eq!(template.write_operation_id, "updateOrgGatewayTemplate");
        assert_eq!(template.read_operation_id, "getOrgGatewayTemplate");
        assert_eq!(template.id_path_name, "gatewaytemplate_id");
        assert!(template.privileged);
    }

    #[test]
    fn create_targets_use_the_collection_endpoint() {
        let service = write_target(WanObject::Service, WriteVerb::Create);
        assert_eq!(service.write_operation_id, "createOrgService");
        assert_eq!(service.read_operation_id, "getOrgService");

        let profile = write_target(WanObject::DeviceProfile, WriteVerb::Create);
        assert_eq!(profile.write_operation_id, "createOrgDeviceProfile");
        assert!(profile.privileged);
    }

    #[test]
    fn every_object_and_verb_resolves() {
        for object in [
            WanObject::Network,
            WanObject::Service,
            WanObject::ServicePolicy,
            WanObject::GatewayTemplate,
            WanObject::DeviceProfile,
        ] {
            for verb in [WriteVerb::Create, WriteVerb::Update] {
                let target = write_target(object, verb);
                assert!(target.write_operation_id.starts_with(match verb {
                    WriteVerb::Create => "create",
                    WriteVerb::Update => "update",
                }));
                assert!(target.read_operation_id.starts_with("get"));
            }
        }
    }
}
```

Add `mod wan_write;` in `mod.rs` beside `mod wan;`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --lib wan_write::tests`
Expected: FAIL — panics at `unimplemented!()`.

- [ ] **Step 3: Write minimal implementation**

Replace the `unimplemented!()` body:

```rust
pub(crate) fn write_target(object: WanObject, verb: WriteVerb) -> WriteTarget {
    match (object, verb) {
        (WanObject::Network, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgNetwork",
            read_operation_id: "getOrgNetwork",
            id_path_name: "network_id",
            privileged: false,
        },
        (WanObject::Network, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgNetwork",
            read_operation_id: "getOrgNetwork",
            id_path_name: "network_id",
            privileged: false,
        },
        (WanObject::Service, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgService",
            read_operation_id: "getOrgService",
            id_path_name: "service_id",
            privileged: false,
        },
        (WanObject::Service, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgService",
            read_operation_id: "getOrgService",
            id_path_name: "service_id",
            privileged: false,
        },
        (WanObject::ServicePolicy, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgServicePolicy",
            read_operation_id: "getOrgServicePolicy",
            id_path_name: "servicepolicy_id",
            privileged: false,
        },
        (WanObject::ServicePolicy, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgServicePolicy",
            read_operation_id: "getOrgServicePolicy",
            id_path_name: "servicepolicy_id",
            privileged: false,
        },
        (WanObject::GatewayTemplate, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgGatewayTemplate",
            read_operation_id: "getOrgGatewayTemplate",
            id_path_name: "gatewaytemplate_id",
            privileged: true,
        },
        (WanObject::GatewayTemplate, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgGatewayTemplate",
            read_operation_id: "getOrgGatewayTemplate",
            id_path_name: "gatewaytemplate_id",
            privileged: true,
        },
        (WanObject::DeviceProfile, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgDeviceProfile",
            read_operation_id: "getOrgDeviceProfile",
            id_path_name: "deviceprofile_id",
            privileged: true,
        },
        (WanObject::DeviceProfile, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgDeviceProfile",
            read_operation_id: "getOrgDeviceProfile",
            id_path_name: "deviceprofile_id",
            privileged: true,
        },
    }
}
```

- [ ] **Step 4: Verify every operation ID exists in the catalog**

Run:

```bash
python3 - <<'EOF'
import json, re
cat = json.load(open('docs/mist-api/catalog.json'))
ops = {o['operation_id']: o for o in cat['operations']}
src = open('crates/rustmistmcp/src/server/wan_write.rs').read()
for oid in sorted(set(re.findall(r'"(createOrg\w+|updateOrg\w+|getOrg\w+)"', src))):
    op = ops.get(oid)
    print(f"{oid:32} {op['capability'] if op else 'MISSING FROM CATALOG'}")
EOF
```

Expected: every ID present. `createOrg*`/`updateOrg*` report `create`/`update`; `getOrg*` report `ordinary_read` or `privileged_read`. Any `MISSING FROM CATALOG` is a stop-and-fix.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p rustmistmcp --lib wan_write::tests` — expect PASS.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/wan_write.rs crates/rustmistmcp/src/server/mod.rs
git commit -m "feat(wan): map each WAN edge write to the read that produces its before state"
```

---

### Task 2: Merge-patch and the `mist_configured` refusal

**Files:**
- Modify: `crates/rustmistmcp/src/server/wan_write.rs`
- Test: unit tests inside `wan_write.rs`

**Interfaces:**
- Consumes: Task 1's module.
- Produces: `pub(crate) enum PatchError { MistConfigured }`; `pub(crate) fn reject_config_authority(patch: &serde_json::Value) -> Result<(), PatchError>`; `pub(crate) fn merge_patch(before: &serde_json::Value, patch: &serde_json::Value) -> serde_json::Value`.

- [ ] **Step 1: Write the failing test**

Append to `wan_write.rs` (inside `mod tests`):

```rust
    use serde_json::json;

    #[test]
    fn merge_preserves_unspecified_fields() {
        let before = json!({"name": "branch", "vlan_id": 10, "subnet": "10.0.0.0/24"});
        let patch = json!({"vlan_id": 20});
        assert_eq!(
            merge_patch(&before, &patch),
            json!({"name": "branch", "vlan_id": 20, "subnet": "10.0.0.0/24"})
        );
    }

    #[test]
    fn merge_replaces_arrays_wholesale() {
        let before = json!({"servers": ["a", "b", "c"]});
        let patch = json!({"servers": ["z"]});
        assert_eq!(merge_patch(&before, &patch), json!({"servers": ["z"]}));
    }

    #[test]
    fn merge_deletes_on_null() {
        let before = json!({"name": "branch", "note": "temporary"});
        let patch = json!({"note": null});
        assert_eq!(merge_patch(&before, &patch), json!({"name": "branch"}));
    }

    #[test]
    fn merge_recurses_into_nested_objects() {
        let before = json!({"dhcpd": {"enabled": true, "lease": 3600}});
        let patch = json!({"dhcpd": {"lease": 7200}});
        assert_eq!(
            merge_patch(&before, &patch),
            json!({"dhcpd": {"enabled": true, "lease": 7200}})
        );
    }

    #[test]
    fn config_authority_is_refused_at_any_depth() {
        assert_eq!(
            reject_config_authority(&json!({"mist_configured": true})),
            Err(PatchError::MistConfigured)
        );
        assert_eq!(
            reject_config_authority(&json!({"switch": {"mist_configured": false}})),
            Err(PatchError::MistConfigured)
        );
        assert_eq!(
            reject_config_authority(&json!({"devices": [{"mist_configured": true}]})),
            Err(PatchError::MistConfigured)
        );
        assert_eq!(reject_config_authority(&json!({"name": "branch"})), Ok(()));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --lib wan_write::tests`
Expected: FAIL to compile — `merge_patch`, `reject_config_authority`, `PatchError` not found.

- [ ] **Step 3: Write minimal implementation**

Append to `wan_write.rs` (outside `mod tests`):

```rust
/// Why a patch was refused before a change set was created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatchError {
    /// The patch tried to set `mist_configured`.
    MistConfigured,
}

/// Refuse any patch that touches `mist_configured`, at any depth.
///
/// That field decides whether Mist owns a device's configuration, so changing
/// it decides who may configure the device at all — a different kind of act
/// from changing what a configuration says, and one with fleet-wide reach. It
/// spans two capabilities (`update` and `create`), so no capability-based gate
/// can contain it; refusing the field is the only control that holds. The
/// refusal happens before a change set exists so approval cannot override it.
pub(crate) fn reject_config_authority(patch: &serde_json::Value) -> Result<(), PatchError> {
    match patch {
        serde_json::Value::Object(map) => {
            if map.contains_key("mist_configured") {
                return Err(PatchError::MistConfigured);
            }
            for value in map.values() {
                reject_config_authority(value)?;
            }
            Ok(())
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_config_authority(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Apply a JSON merge-patch to the object read from Mist.
///
/// All five objects update via `PUT`, which replaces the whole object, so a
/// caller sending only the field it wants changed would silently drop every
/// other field. Merging onto the `before` state removes that hazard. Two
/// behaviours must be documented wherever this is exposed: **arrays replace
/// wholesale** (there is no element-wise edit), and **`null` deletes a field**
/// rather than setting it to null.
pub(crate) fn merge_patch(
    before: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    let serde_json::Value::Object(patch_map) = patch else {
        return patch.clone();
    };
    let mut merged = match before {
        serde_json::Value::Object(before_map) => before_map.clone(),
        _ => serde_json::Map::new(),
    };
    for (key, value) in patch_map {
        if value.is_null() {
            merged.remove(key);
        } else if let Some(existing) = merged.get(key) {
            merged.insert(key.clone(), merge_patch(existing, value));
        } else {
            merged.insert(key.clone(), value.clone());
        }
    }
    serde_json::Value::Object(merged)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp --lib wan_write::tests`
Expected: PASS — 7 tests.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/wan_write.rs
git commit -m "feat(wan): merge-patch onto the read before state, and refuse mist_configured"
```

---

### Task 3: Mount the change-set coordinator on the handler

**Files:**
- Create: `crates/rustmistmcp/src/server/change_set.rs`
- Modify: `crates/rustmistmcp/src/server/mod.rs`
- Test: `crates/rustmistmcp/tests/change_set_tools.rs` (create)

**Interfaces:**
- Consumes: nothing from Tasks 1-2.
- Produces: `pub(crate) fn object_key(object: wan::WanObject, object_id: Option<&str>) -> String`; a `coordinator: Arc<ChangesetCoordinator>` field on `MistHandler`, populated by every constructor.

- [ ] **Step 1: Write the failing test**

Create `crates/rustmistmcp/src/server/change_set.rs`:

```rust
//! The Mist change-set lifecycle: stage, inspect, approve, apply.
//!
//! The state machine, persistence and digests are `mecmcp-changeset`'s. What
//! belongs here is Mist-specific: which read produces the `before` state, how
//! an object is named as a concurrency key, and what verification means.

use crate::server::wan::WanObject;

/// Format an object as a change-set `device` key.
///
/// `ChangeSetRecord.device` is what `device_guard` locks on, so it is the
/// concurrency unit. Mist has no devices, so the object being changed serves:
/// two operators editing different networks proceed in parallel, and two edits
/// to the same network serialize. A create has no UUID yet, so all creates of
/// one object type share a key and serialize — deliberate and cheap.
///
/// Objects that reference each other are deliberately NOT serialized against
/// each other. Widening this key to compensate would trade a real, understood
/// limitation for a coarse lock nobody can reason about.
pub(crate) fn object_key(object: WanObject, object_id: Option<&str>) -> String {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_names_the_object_not_the_org() {
        assert_eq!(
            object_key(WanObject::Network, Some("2b0f0000-0000-0000-0000-000000000001")),
            "network/2b0f0000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            object_key(WanObject::GatewayTemplate, Some("abc")),
            "gatewaytemplate/abc"
        );
    }

    #[test]
    fn creates_share_one_key_per_object_type() {
        assert_eq!(object_key(WanObject::Service, None), "service/new");
        assert_eq!(object_key(WanObject::Network, None), "network/new");
    }
}
```

Add `mod change_set;` in `mod.rs`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --lib change_set::tests`
Expected: FAIL — panics at `unimplemented!()`.

- [ ] **Step 3: Write minimal implementation**

In `change_set.rs`, replace the body:

```rust
pub(crate) fn object_key(object: WanObject, object_id: Option<&str>) -> String {
    let name = match object {
        WanObject::Network => "network",
        WanObject::Service => "service",
        WanObject::ServicePolicy => "servicepolicy",
        WanObject::GatewayTemplate => "gatewaytemplate",
        WanObject::DeviceProfile => "deviceprofile",
    };
    match object_id {
        Some(id) => format!("{name}/{id}"),
        None => format!("{name}/new"),
    }
}
```

In `mod.rs`, add the coordinator to `MistHandler`. Add to the struct definition (beside `client: Arc<dyn MistClient>`):

```rust
    /// Change-set lifecycle state for gated writes.
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
```

Add a helper next to the other constructors:

```rust
/// Default change-set limits for this consumer.
///
/// A Mist change set holds one action over one object, so the per-set ceilings
/// are deliberately small; the store ceiling is what bounds a runaway client.
fn change_set_limits() -> mecmcp_changeset::OperationLimits {
    mecmcp_changeset::OperationLimits {
        max_operations: 64,
        max_change_sets: 64,
        max_actions_per_set: 1,
        max_change_set_bytes: 256 * 1024,
        max_state_bytes: 4 * 1024 * 1024,
        max_targets_per_set: 1,
    }
}

/// Load the coordinator for a handler.
///
/// `None` keeps state in memory, which is what tests want. Production passes
/// `/var/lib/rustmistmcp/changeset-state.json`, the path packaging reserves.
fn load_coordinator(
    path: Option<&std::path::Path>,
) -> Result<Arc<mecmcp_changeset::ChangesetCoordinator>, MistServerError> {
    let coordinator = mecmcp_changeset::ChangesetCoordinator::load(
        path,
        change_set_limits(),
        std::time::Duration::from_secs(3600),
        false,
    )
    .map_err(|error| MistServerError::Config(format!("change-set state: {error}")))?;
    Ok(Arc::new(coordinator))
}
```

Populate `coordinator: load_coordinator(None)?` in `with_client` and `blocked`, and `coordinator: load_coordinator(Some(std::path::Path::new("/var/lib/rustmistmcp/changeset-state.json")))?` in `from_config`.

If `MistServerError` has no `Config` variant, use whichever variant it does have for configuration failures — check the enum before writing this.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp --lib change_set::tests && cargo test --workspace`
Expected: PASS. Existing tests must still pass — every `MistHandler` constructor now populates one more field.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/change_set.rs crates/rustmistmcp/src/server/mod.rs
git commit -m "feat(wan): mount the change-set coordinator on the Mist handler"
```

---

### Task 4: `plan_mist_change`

The task the whole design exists to get right.

**Files:**
- Modify: `crates/rustmistmcp/src/server/change_set.rs`, `crates/rustmistmcp/src/server/mod.rs`, `crates/rustmistmcp/tests/tool_contract.rs`
- Test: `crates/rustmistmcp/tests/change_set_tools.rs`

**Interfaces:**
- Consumes: `write_target`, `WriteVerb`, `WriteTarget`, `merge_patch`, `reject_config_authority`, `PatchError` (Tasks 1-2); `object_key`, the `coordinator` field (Task 3).
- Produces: tool `plan_mist_change`; `pub(crate) struct StagedPlan { pub change_set_id: String, pub plan_digest: String, pub preview_digest: String, pub before: serde_json::Value, pub after: serde_json::Value }`.

- [ ] **Step 1: Write the failing test**

Create `crates/rustmistmcp/tests/change_set_tools.rs`:

```rust
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
    assert_eq!(requests[0].path.get("network_id"), Some(&NETWORK_ID.to_owned()));
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
                "object_id": NETWORK_ID, "patch": {"name": "branch"}
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test change_set_tools`
Expected: FAIL — `plan_mist_change` is not a registered tool.

- [ ] **Step 3: Write minimal implementation**

In `change_set.rs`, add the staging function. It takes an already-fetched `before` so the tool layer owns the read — that keeps this function pure enough to test, while the *tool* test above proves the read really happens:

```rust
/// A staged change set, ready to be recorded.
#[derive(Clone, Debug)]
pub(crate) struct StagedPlan {
    /// Change-set identifier.
    pub change_set_id: String,
    /// Digest binding owner, object, `before` fingerprint and the action.
    pub plan_digest: String,
    /// Digest over the exact body apply will send.
    pub preview_digest: String,
    /// The object as read, or `Value::Null` for a create.
    pub before: serde_json::Value,
    /// The merged body apply will send.
    pub after: serde_json::Value,
}
```

Write the staging logic in the same file, using `mecmcp_changeset::digest::{change_set_digest, preview_digest}` and `sha2` for the fingerprint over `before`. Build a `ChangeSetRecord` with `state: ChangeSetState::Planned`, `device: object_key(object, object_id)`, `actions: vec![the action JSON]`, `expected_candidate_fingerprint: <fingerprint of before>`, then `coordinator.insert_change_set(record).await`.

For a **create**, `before` is `serde_json::Value::Null` and the fingerprint is the empty-state marker `"create"` — the plan digest therefore binds to the preview only, and the tool's response must say `"before": null` with an explicit `"before_state": "absent (create)"` field rather than presenting a hollow digest as if it constrained prior state.

In `mod.rs`, add the args struct and tool:

```rust
/// Which write a change set performs.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WriteVerbArg {
    /// Create a new object.
    Create,
    /// Update an existing object.
    Update,
}

impl From<WriteVerbArg> for wan_write::WriteVerb {
    fn from(value: WriteVerbArg) -> Self {
        match value {
            WriteVerbArg::Create => Self::Create,
            WriteVerbArg::Update => Self::Update,
        }
    }
}

read_args!(PlanChangeArgs {
    /// Which configuration object type to change. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Create or update. Not sent to Mist.
    #[serde(skip_serializing)]
    verb: WriteVerbArg,
    /// Organization UUID.
    org_id: String,
    /// The object's UUID. Required for `update`, omitted for `create`.
    #[serde(skip_serializing)]
    object_id: Option<String>,
    /// Fields to change. Merged onto the object's current state: arrays
    /// replace wholesale, and a null value deletes the field.
    #[serde(skip_serializing)]
    patch: serde_json::Value,
});
```

The tool method must, in order: reject `mist_configured` **before** anything else; resolve the write target; for an update, issue the paired read through the existing dispatch path and keep its JSON body as `before`; merge; compute digests; insert the change-set record; return the envelope.

Register `plan_mist_change` in `KNOWN_TOOLS`, `EXPECTED`, `RESTRICTED_TOOLS`, and `EXPECTED_RESTRICTED`, all alphabetically sorted. All four change-set tools are write-capable and therefore restricted.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp --test change_set_tools && cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/change_set.rs crates/rustmistmcp/src/server/mod.rs crates/rustmistmcp/tests/change_set_tools.rs crates/rustmistmcp/tests/tool_contract.rs
git commit -m "feat(wan): plan_mist_change stages a write bound to the state it read"
```

---

### Task 5: `get_mist_change_set` and `approve_mist_change_set`

**Files:**
- Modify: `crates/rustmistmcp/src/server/change_set.rs`, `crates/rustmistmcp/src/server/mod.rs`, `crates/rustmistmcp/tests/tool_contract.rs`
- Test: `crates/rustmistmcp/tests/change_set_tools.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: tools `get_mist_change_set` and `approve_mist_change_set`.

- [ ] **Step 1: Write the failing test**

Append to `crates/rustmistmcp/tests/change_set_tools.rs`:

```rust
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
    let recorder = Arc::new(ScriptedClient::new(serde_json::json!({"id": NETWORK_ID})));
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
    assert!(wrong.is_err(), "a change set must not be readable under another object key");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test change_set_tools`
Expected: FAIL — the two tools are not registered.

- [ ] **Step 3: Write minimal implementation**

`get_mist_change_set` calls `coordinator.change_set(&id, &object_key(object, object_id)).await` and renders the record: `state.as_str()`, digests, `before`, `after`, owner, approver. The coordinator already refuses a record whose `device` differs, which is what the second test exercises.

`approve_mist_change_set` must:
1. Fetch the record by id and object key.
2. Refuse if `record.owner == caller.token_name` — the planning principal cannot approve. This is the security property of the whole lifecycle; it must be checked before any state change.
3. Refuse if the state is not `Planned`.
4. Compute `compute_approval_digest(&record.id, &record.digest, &record.owner, approver, approved_at_unix)`, set `record.approval`, set `record.state = ChangeSetState::Approved`, and `coordinator.update_change_set(record).await`.

Use `mecmcp_auth::CallerCtx::token_name` for the principal, read from the request extensions exactly as the existing tools read caller context.

Register both tools in `KNOWN_TOOLS`, `EXPECTED`, `RESTRICTED_TOOLS`, and `EXPECTED_RESTRICTED`, alphabetically sorted.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp --test change_set_tools && cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/change_set.rs crates/rustmistmcp/src/server/mod.rs crates/rustmistmcp/tests/change_set_tools.rs crates/rustmistmcp/tests/tool_contract.rs
git commit -m "feat(wan): inspect and approve change sets, refusing self-approval"
```

---

### Task 6: `apply_mist_change_set`

**Files:**
- Modify: `crates/rustmistmcp/src/server/change_set.rs`, `crates/rustmistmcp/src/server/mod.rs`, `crates/rustmistmcp/tests/tool_contract.rs`
- Test: `crates/rustmistmcp/tests/change_set_tools.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: tool `apply_mist_change_set`.

- [ ] **Step 1: Write the failing test**

Append to `crates/rustmistmcp/tests/change_set_tools.rs`:

```rust
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
        "id": NETWORK_ID, "vlan_id": 10
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rustmistmcp --test change_set_tools`
Expected: FAIL — `apply_mist_change_set` is not registered.

- [ ] **Step 3: Write minimal implementation**

`apply_mist_change_set` must, in order:

1. Take `coordinator.device_guard(&object_key(object, object_id), &cancellation).await` so a second apply for the same object waits rather than interleaving.
2. Fetch the record; refuse unless `state == ChangeSetState::Approved`.
3. Refuse if the approval has expired against `coordinator.approval_ttl()`.
4. **Re-read the object** through the paired read operation and compare its fingerprint with `record.expected_candidate_fingerprint`. On mismatch, set state to `Failed`, persist, and refuse **without issuing any write**.
5. Set state to `Applying` and persist, so a crash mid-apply is visible as `Applying` rather than looking never-started.
6. Issue the write: a `MistRequest` for `write_operation_id` carrying `json: Some(after)`.
7. **Re-read and verify**: compare the re-read object against `after`. Record the comparison result in the response; a mismatch is reported, never swallowed.
8. Set state to `Applied` (or `Failed`) and persist.

For a create, step 4 has nothing to compare — the record's fingerprint is the `"create"` marker — so skip the drift check and say so in the response rather than implying a check occurred.

Register `apply_mist_change_set` in all four lists, alphabetically sorted.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rustmistmcp --test change_set_tools && cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/rustmistmcp/src/server/change_set.rs crates/rustmistmcp/src/server/mod.rs crates/rustmistmcp/tests/change_set_tools.rs crates/rustmistmcp/tests/tool_contract.rs
git commit -m "feat(wan): apply change sets bound to plan and preview digests, then verify"
```

---

### Task 7: Documentation and the packaging contract

**Files:**
- Modify: `README.md`, `docs/OPERATIONS.md`, `CLAUDE.md`
- Test: `scripts/verify-packaging.sh`

**Interfaces:**
- Consumes: the four tools from Tasks 4-6.
- Produces: no code.

- [ ] **Step 1: Add the four tools to the README table**

In `README.md`'s `## WAN edge tools` section, add four rows in alphabetical order, with descriptions matching each `#[tool]` `description` string. **Do not broaden the section's subset-scoping sentence** — it deliberately says these are part of a larger registry.

- [ ] **Step 2: Document the lifecycle in `docs/OPERATIONS.md`**

Add a section covering, in the surrounding document's voice:
- Change-set state lives at `/var/lib/rustmistmcp/changeset-state.json`, which packaging already reserves and the OCI runtime mounts read-write. **Preserve it across upgrades** — losing it strands any planned or approved change set.
- The four tools are all in `RESTRICTED_TOOLS`, so a wildcard-tools token cannot reach them.
- Approval requires a second principal; the planning principal is refused.
- Merge-patch semantics: arrays replace wholesale, `null` deletes.
- `mist_configured` is refused at plan time and cannot be approved past.
- Batch 1 is create and update only. Delete and device-profile assign/unassign are not reachable.

- [ ] **Step 3: Update `CLAUDE.md`'s standing claim**

`CLAUDE.md` currently states mutating tools are absent. That becomes false with this work. Update it to say mutations exist for the batch-1 WAN edge objects, are reachable only through the change-set lifecycle, and that delete and config-authority changes remain out of reach. Do not overstate: **no live-tenant apply has happened yet** unless one has actually been recorded.

- [ ] **Step 4: Verify the packaging contract**

Run:

```bash
cargo build --release --workspace
RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh
```

Expected: PASS. That script asserts exact README and CLAUDE.md content, so a malformed edit fails here rather than in review.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo test --workspace
git add README.md docs/OPERATIONS.md CLAUDE.md
git commit -m "docs(wan): document the change-set write lifecycle and its state file"
```

---

## Live acceptance (not a task — requires a human)

Issue #14 decision 3 requires each write batch to complete plan → approve → apply → verify against the lab org before shipping, mutating an object created for the purpose.

Because `create` is in batch 1, the scratch object can be made by the tools themselves: create a network named `mcp-acceptance`, drive it through the full cycle, and the evidence covers create and update in one pass.

Two things make this a human step rather than a task:

- **Approval needs two principals.** The lab deployment has one token (`acceptance`). A second grant-bearing token must be minted for the approver, or apply will refuse — correctly.
- **It mutates a real org.** LXC 952 is `protected`, and the tenant is real even though it is a test tenant.

Do not mark this plan complete on the strength of passing tests. The tests prove the lifecycle is wired; only a live apply proves it works.

## Self-Review

**Spec coverage.** Design's change-set section maps to tasks: real `before` read (Task 4), patch/read-modify-write (Task 2, wired Task 4), two digests (Task 4), approval on principal identity (Task 5), drift refusal and verification re-read (Task 6), `mist_configured` refused at plan time (Task 2, enforced Task 4), creates binding to preview only (Tasks 4 and 6), state file location (Task 3), batch-1 scope of ten operations (Task 1). Delete and assign/unassign are excluded by Task 1's mapping containing no such entries.

**Placeholder scan.** Tasks 4, 5 and 6 describe parts of their implementation in prose rather than complete code — specifically the coordinator interaction and tool bodies. That is a deliberate limit, not an oversight: those bodies depend on how `MistHandler` reads caller context and dispatches, which the implementer must read from the surrounding file. Every *contract* those bodies must satisfy is given as an executable test, and every upstream signature they need is listed verbatim in "Verified upstream API". An implementer who satisfies the tests cannot satisfy them the wrong way.

**Type consistency.** `WriteVerb`/`WriteVerbArg`, `WriteTarget`, `PatchError`, `StagedPlan`, `object_key`, `write_target`, `merge_patch`, `reject_config_authority` are used consistently across tasks. `WanObject` and `WanObjectArg` are reused from the merged read surface rather than redefined.

**Known risk.** Task 3 assumes `MistServerError` has a `Config` variant and tells the implementer to check before writing. Task 5 assumes caller identity is reachable as `CallerCtx::token_name` from request extensions — true of the existing tools, but the implementer must confirm the extension is populated on the stdio path the tests use, since a `None` caller would make self-approval refusal untestable there. If it is not, that test must move to the HTTP path, and the plan should be corrected rather than the test weakened.
