# WAN edge (SRX/SSR) tool surface — design

Date: 2026-08-12
Status: approved, not implemented

## Goal

An operator can **troubleshoot** an SRX WAN edge and **configure** it through
rustmistmcp. The same endpoints serve SSR, so nothing here is SRX-specific in
the API sense; the name reflects the operator's device, not a code path.

## Why this shape

The catalog holds **53 WAN-edge read operations**, of which three already have
named tools (`getSiteDeviceStats`, `getSiteSleSummary`, `getSiteInsightMetrics`).
All fifty remaining are already *reachable* through `invoke_mist_read` — reach
was never the gap. The gaps are **discoverability** for troubleshooting and the
**absence of any write path** for configuration.

One tool per operation would add ~50 tools to the existing 24. The repo's own
constraint rejects that: tool selection degrades badly past a few dozen, and a
grant naming fifty operations is unreviewable. Composite tools that fan out to
several API calls were also rejected — they cannot carry a coherent pagination
cursor, they muddy error semantics when one sub-call fails, and they force a
grant to authorize every underlying operation at once, making the grant less
precise rather than more.

**Chosen: scope-collapsed named tools.** Fourteen tools, surface 24 → 38. Each
tool resolves to exactly one concrete catalog operation ID before dispatch, so
`MistGrant.allowed_operations` binds per-operation exactly as today. The
collapse is in the tool signature, not in the authorization.

## Tool inventory

### Troubleshoot (8 tools, all `ordinary_read`)

| Tool | Operations collapsed | Selector |
|---|---|---|
| `list_mist_wan_edges` | `searchOrgDevices`, `searchSiteDevices` | `org_id` xor `site_id`; `type=gateway` forced |
| `get_mist_wan_edge_stats` | `getSiteGatewayMetrics`, `getSiteInsightMetricsForGateway` | `device_id` present selects the per-device variant |
| `search_mist_tunnels` | `searchOrgTunnelsStats`, `countOrgTunnelsStats` | `mode: records\|count` |
| `search_mist_peer_paths` | `searchOrgPeerPathStats`, `countOrgPeerPathStats` | `mode` |
| `search_mist_bgp_peers` | `searchOrgBgpStats`, `countOrgBgpStats`, `searchSiteBgpStats`, `countSiteBgpStats` | `org_id` xor `site_id`, `mode` |
| `search_mist_service_path_events` | `searchSiteServicePathEvents`, `countSiteServicePathEvents` | `mode` |
| `get_mist_sle_impact` | `listSiteSleImpactedGateways`, `listSiteSleImpactedApplications`, `getSiteSleImpactSummary` | `impact: gateways\|applications\|summary` |
| `list_mist_applications` | `listSiteApps`, `countSiteApps`, `listGatewayApplications` | `source: site\|catalog`, `mode` |

`mxtunnels` and `wxtunnels` are deliberately **excluded**. They read as WAN
tunnels and are not — they are Mist Edge and wireless constructs. SRX/SSR WAN
tunnels live under `stats/tunnels` (IPsec) and `stats/vpn_peers` (overlay peer
paths). A keyword sweep for "tunnel" produces a WAN tool set that is mostly
wireless.

### Configure (6 tools)

| Tool | Covers |
|---|---|
| `list_mist_wan_config` | list and site-derived variants for all five object types |
| `get_mist_wan_config` | get-one for the same five |
| `plan_mist_change` | reads `before`, merges the patch, computes digests, stages the write |
| `get_mist_change_set` | inspect a pending change set and its before→after diff |
| `approve_mist_change_set` | second-principal approval |
| `apply_mist_change_set` | applies, bound to both plan and preview digests, then verifies |

Object selector for both read tools:
`object: network|service|servicepolicy|gatewaytemplate|deviceprofile`.

The four change-set tools cover **all ten** batch-1 write operations, because
the target operation is a parameter constrained by the grant — the precedent
`invoke_mist_read` already sets for reads. This is what stops "configure the
SRX" costing twenty-five named write tools.

### Batch 1 write scope

Create and update for the five objects — ten operations:

```
createOrgNetwork          updateOrgNetwork
createOrgService          updateOrgService
createOrgServicePolicy    updateOrgServicePolicy
createOrgGatewayTemplate  updateOrgGatewayTemplate
createOrgDeviceProfile    updateOrgDeviceProfile
```

**Deferred to batch 2**, with reasons:

- **`delete*` (5 ops).** An update is revertible from its fingerprinted
  `before`; a delete is not. Deleting an object another object references is
  also the classic footgun and deserves its own design pass.
- **`assignOrgDeviceProfile` / `unassignOrgDeviceProfile`.** Classified
  `update`, but they are *binding* operations with fleet-wide reach — they
  change which config a device receives, not what a config says. Structurally
  the same hazard as `mist_configured`.

## Parameters, bounding, error handling

**Selectors are typed enums**, not strings, with `schemars` derives. An invalid
value is rejected by the tool schema before dispatch, rather than surfacing as
a less specific dispatcher error after a round trip.

**Scope is exactly-one.** Tools taking `org_id` xor `site_id` reject both or
neither at schema level. This matters beyond ergonomics: `MistScopePreflight`
translates those two argument names into `org/<uuid>` and `site/<uuid>`
subjects. Keeping the argument names means transport preflight containment
works unchanged, with no new authorization path.

**`type=gateway` is forced server-side** on `list_mist_wan_edges`.
`searchOrgDevices` accepts `type` as a query parameter, so a caller-supplied
value would let a WAN tool enumerate APs and switches.

**Bounding is inherited unchanged**: `limit` validated 1..=100, opaque cursors
with `MAX_ENCODED_CURSOR_BYTES`. `MistCursor` binds to a single `operation_id`
and origin, so a cursor from `searchOrgBgpStats` is rejected if replayed
against `searchSiteBgpStats` through the same tool. The collapse changes the
tool signature, not the cursor's binding.

**`mode: count` returns a different shape.** Mist `/count` endpoints return
distributions rather than record pages, and carry `PaginationMode::None` where
the search variants use `SearchAfter`. The response envelope already reports
the resolved `operation_id`; the tool description must state the shape
difference rather than leaving it to be discovered.

| Failure | Answered by | Result |
|---|---|---|
| Invalid selector, both scopes, or neither | tool schema | rejected before dispatch, no Mist call |
| Operation absent from grant `allowed_operations` | handler authorization | refused, audited `denied` |
| Target org/site outside grant subjects | transport preflight | 403, audited `denied` |

## Change-set flow

**`plan_mist_change` must issue a real read.** rustsdcmcp shipped complete
fingerprint machinery and passed `Value::Null` as `before` at the call site: the
digest bound to nothing while the audit record advertised a digest-bound change
set that had cleared two-person approval. Here, `plan_mist_change` resolves the
target operation, derives its corresponding GET from the catalog, executes it,
and binds the digest to that response. No `before`, no plan — a hard error.

**The tool takes a patch; the server performs read-modify-write.** All five
objects update via `PUT`, which replaces the whole object, so a caller sending
`{"name": "x"}` would silently drop every other field. The `before` read is
mandatory for the digest anyway, so merging costs nothing and removes the
omission hazard. Two sharp edges must be documented in the tool description:
**arrays replace wholesale** (no element-wise edit) and **`null` deletes a
field** rather than setting it null.

**`apply` binds to two digests**: the plan digest (what was read and staged)
and the preview digest (the exact merged body apply will send). If the object
moved in Mist between plan and apply, the plan digest mismatches and apply
refuses.

**Approval is refused on principal identity** using `CallerCtx.token_name`: the
principal that planned cannot approve. Change sets carry a TTL and expire.

**Verification is a re-read.** `VerificationPolicy` already exists in the
catalog. After apply, re-read the object and compare against the merged body;
a mismatch is reported, not swallowed.

**`mist_configured` is refused at plan time.** Any patch containing that field
is rejected before a change set exists, so the refusal cannot be overridden by
approval.

**Creates have no `before`.** A digest over `null` would be the
meaningless-digest problem in a new costume. Creates therefore bind the digest
to the *preview* only, and the audit record states `before: absent (create)`
explicitly rather than carrying a hollow value — the same reasoning that made
`execute` operations approval-gated but not drift-bound.

State lives in `/var/lib/rustmistmcp/changeset-state.json`, which packaging
already reserves and the OCI runtime already mounts read-write. The lifecycle
is `mecmcp-changeset`; this repo supplies only the Mist-specific parts — which
GET corresponds to which write, the merge, and the verification comparison.
`rustsdcmcp-core/src/license_write.rs` is the closest template.

## Testing

**Collapse correctness is the new failure mode.** Table-driven tests per
collapsed tool assert `(selector combination) → exact operation ID`, including
negatives: both scopes, neither scope, invalid enum.

**The `before` guard must drive the real plan path.** rustsdcmcp's first fix was
correct in the transaction module and still passed with `before` reverted to
`Null`, because the tests constructed the prepared write directly. The test here
calls `plan_mist_change` end to end against a fixture client and asserts the
digest changes when the fixture's GET response changes. A test that builds the
prepared write itself passes against the bug and is worth nothing.

**Merge semantics**: unspecified fields preserved, arrays replaced wholesale,
`null` deletes.

**Non-overridable refusals**: `mist_configured` in a patch rejected at plan
time; planning principal cannot approve; moved `before` fails the digest check.

**Forcing test**: a caller passing `type=ap` to `list_mist_wan_edges` still gets
`type=gateway`.

**Cursor binding across the collapse**: a cursor from `searchOrgBgpStats`
replayed against the site variant through the same tool is rejected.

## Live acceptance

Per issue #14 decision 3, each write batch completes plan → digest → approve →
apply → verify against the lab org before shipping, mutating an object created
for the purpose.

Because `create` is in batch 1, **the scratch object can be created by the tools
themselves**: create a network named `mcp-acceptance`, drive it through the full
cycle, and the evidence covers create and update in one pass. No portal
prerequisite, unlike the superseded WLAN batch.

## Delivery sequencing

Fourteen tools plus a change-set lifecycle is too much for one commit to be
reviewed, or gated, in one sitting. Four PRs, each independently useful:

1. **Diagnostic reads (6 tools)** — `list_mist_wan_edges`,
   `get_mist_wan_edge_stats`, `search_mist_tunnels`, `search_mist_peer_paths`,
   `search_mist_bgp_peers`, `search_mist_service_path_events`. Establishes the
   scope-collapse pattern and its tests. No new authorization surface.
2. **Analysis reads (2 tools)** — `get_mist_sle_impact`,
   `list_mist_applications`. Same pattern, different selectors.
3. **Config reads (2 tools)** — `list_mist_wan_config`, `get_mist_wan_config`.
   Introduces the object selector and the GET-per-write-target mapping the
   change set will reuse for `before`.
4. **Change-set writes (4 tools)** — the lifecycle, batch-1 write scope, and
   live acceptance.

PR 3 deliberately precedes PR 4: the mapping from a write operation to its
corresponding read is the thing `plan_mist_change` depends on for a real
`before`, and it is easier to get right — and to test — when it ships as a read
tool first.

## Decisions superseded

Issue #14 decision 1 chose WLAN updates (`updateSiteWlan`, `updateOrgWlan`) as
the first write batch. **WAN edge config replaces it.** WLAN is wireless and
does not advance configuring an SRX. WLAN updates move to a later batch and
inherit the machinery proven here.

## Out of scope

- WAN edge config **delete** and device-profile assign/unassign (batch 2).
- SSR-specific operations (versions, upgrades, registration commands) — no
  named tools; reachable via `invoke_mist_read`.
- The remaining WAN config read operations not listed above (`getOrgNetwork`
  and peers are covered by the two config read tools; anything else stays on
  `invoke_mist_read`).
- `mecmcp#269` request-id correlation, which is upstream and open.
