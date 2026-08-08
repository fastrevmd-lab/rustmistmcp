# rustmistmcp v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a production Rust Mist MCP server with full functional parity
to the frozen reference surface, plus customer-selectable OCI and LXC packages.

**Architecture:** A Mist-only core crate consumes generic security/runtime
foundations from one immutable `mecmcp` revision. A thin server crate exposes
curated workflows and safe catalog dispatchers. Generated artifacts are
internal catalog/parity data, never 1,050 registered MCP tools.

**Tech Stack:** Rust 1.88, edition 2024, Tokio, reqwest/rustls, rmcp 2, serde,
schemars, JSON Schema validation, pinned `mecmcp-*` Git dependencies, Debian 13,
distroless OCI.

## Global Constraints

- Modify only `rustmistmcp`; never modify `mecmcp`, `rustsdcmcp`, or another
  repository.
- Never modify or replace VMID 612 (`foundry`).
- Generic MCP/cloud behavior comes from `mecmcp`; search existing issues before
  filing a missing cross-server capability and never create a duplicate issue.
- All `mecmcp-*` dependencies use one immutable revision.
- Rust edition 2024, MSRV 1.88, MIT, `unsafe_code = "forbid"`.
- Mutations require authenticated caller context, exact tool/target/grant
  authorization, digest-bound approval, and apply through `mecmcp-changeset`.
- One Mist profile per process; outbound authentication is API-token only.
- Tests precede production behavior and are observed failing before
  implementation.

---

### Task 1: Workspace and dependency gate

**Files:**
- Create: `Cargo.toml`, `deny.toml`
- Create: `crates/rustmistmcp-core/Cargo.toml`
- Create: `crates/rustmistmcp/Cargo.toml`
- Test: `crates/rustmistmcp-core/tests/workspace_contract.rs`

**Interfaces:**
- Produces workspace dependency and lint contracts used by every later task.
- Pins one `mecmcp` revision that contains the required shared crates.

- [ ] Write a compile-time contract test for package metadata, unsafe-code
  policy, and shared revision equality; run it and observe failure because the
  workspace is absent.
- [ ] Add the two-crate workspace, exact lint policy, release profile, and
  dependency set; run the contract test and `cargo metadata`.
- [ ] Record #90/#91 status. Do not implement their missing generic APIs.
- [ ] Commit as `feat: establish rustmistmcp workspace`.

### Task 2: Vendored API and deterministic catalog

**Files:**
- Create: `docs/mist-api/README.md`, `docs/mist-api/mist-openapi.json`
- Create: `scripts/generate-mist-catalog.py`
- Create: `crates/rustmistmcp-core/src/catalog.rs`
- Test: `crates/rustmistmcp-core/tests/catalog_contract.rs`

**Interfaces:**
- Produces `MistOperation`, `MistCapability`, `MistAction`,
  `PaginationMode`, `VerificationPolicy`, and `Catalog`.
- Produces checked-in `docs/mist-api/catalog.json` and `parity.json`.

- [ ] Write failing catalog tests for unique operation IDs, safe templates,
  classifications, target selectors, request media, and full frozen-reference
  accounting.
- [ ] Vendor the official spec and provenance; build a deterministic generator
  that emits only catalog/parity data.
- [ ] Generate Rust-consumable data and make the contract tests pass.
- [ ] Verify a second generation produces no diff.
- [ ] Commit as `feat: add audited Mist operation catalog`.

### Task 3: Mist configuration, target model, and grant

**Files:**
- Create: `crates/rustmistmcp-core/src/config.rs`
- Create: `crates/rustmistmcp-core/src/grant.rs`
- Create: `crates/rustmistmcp-core/src/target.rs`
- Test: `crates/rustmistmcp-core/tests/config_grant_contract.rs`

**Interfaces:**
- Produces `MistConfig::from_path`, `MistGrant: mecmcp_auth::Grant`,
  `MistAction`, and canonical `MistTarget`.

- [ ] Write failing tests for versioned strict config, HTTPS root endpoints,
  safe credential paths, non-empty org allowlist, canonical org/site targets,
  exact operation grants, and invalid combinations.
- [ ] Implement the minimal validated types using shared target-neutral APIs
  when #91 lands; retain no competing generic vocabulary.
- [ ] Make focused and workspace tests pass.
- [ ] Commit as `feat: add Mist profile and authorization model`.

### Task 4: Bounded Mist request adapter

**Files:**
- Create: `crates/rustmistmcp-core/src/request.rs`
- Create: `crates/rustmistmcp-core/src/pagination.rs`
- Create: `crates/rustmistmcp-core/src/client.rs`
- Test: `crates/rustmistmcp-core/tests/client_contract.rs`

**Interfaces:**
- Produces `MistClient`, `MistRequest`, `MistResponse`, `MistCursor`, and
  `MistError`.
- Consumes the shared secret/HTTP/path foundations delivered by #90.

- [ ] Write failing mock-server tests for token header, path encoding,
  parameter/schema rejection, JSON/multipart requests, streamed limits,
  JSON/text/binary responses, cancellation, 429/`Retry-After`, all pagination
  forms, cursor origin/operation binding, and mutation non-retry.
- [ ] If #90 remains unresolved, stop this task at the tested interface seam;
  do not add generic HTTP or secret-loading code locally.
- [ ] Once available, implement the Mist-specific adapter over the shared
  foundation and make all tests pass.
- [ ] Commit as `feat: add bounded Mist API adapter`.

### Task 5: Curated reads and parity dispatch

**Files:**
- Create: `crates/rustmistmcp/src/server/`
- Create: `crates/rustmistmcp/src/lib.rs`
- Test: `crates/rustmistmcp/tests/tool_contract.rs`

**Interfaces:**
- Produces `MistHandler`, `KNOWN_TOOLS`, `RESTRICTED_TOOLS`, and the approved
  named/read-dispatch tool schemas.
- Consumes `mecmcp-server` result, audit, caller, authorization, and filtering
  adapters.

- [ ] Write failing handler tests for the exact named registry, operation
  search/schema, ordinary vs privileged dispatch, target authorization,
  catalog-only method/path selection, bounded results, scope-filtered listing,
  and audit outcomes.
- [ ] Implement named tools and dispatchers through one catalog/client path.
- [ ] Run handler, core, and workspace tests.
- [ ] Commit as `feat: expose curated Mist read tools`.

### Task 6: Changeset-backed mutation parity

**Upstream sequencing update (2026-07-30):** `mecmcp#90` now places the
multi-target preview extension in phase 5, after shared secret, HTTP, response
limit, job, and OpenAPI helpers. Keep this task blocked until phase 5 is
published; do not add a second Mist-local change envelope.

**Files:**
- Create: `crates/rustmistmcp-core/src/change.rs`
- Create: `crates/rustmistmcp/src/server/changes.rs`
- Test: `crates/rustmistmcp-core/tests/change_contract.rs`
- Test: `crates/rustmistmcp/tests/change_tool_contract.rs`

**Interfaces:**
- Produces `MistPreparedChange`, `MistChangeManager`, prepare/approve/apply/get
  tools, and durable recovery behavior.
- Consumes shared prepared-change and `mecmcp-changeset` APIs.

- [ ] Write failing tests for grant denial, canonical persisted request,
  redacted review, digest tamper detection, separate-principal approval,
  expiry, owner/apply revalidation, drift, verification policy, API-acknowledged
  fallback, cancellation, indeterminate persistence, restart, and non-retry.
- [ ] If #90 remains unresolved, stop at the tested Mist transaction seam; do
  not create a local generic prepared-change framework.
- [ ] Implement over `mecmcp-changeset`, make focused and workspace tests pass.
- [ ] Commit as `feat: add controlled Mist changes`.

### Task 7: Runtime and transports

**Upstream sequencing update (2026-07-30):** consume `mecmcp#90` phases 1,
2a, 2b, 3, and 4 in order for the live client and startup identity probe.
Merged `mecmcp#160` is consumed temporarily through the private Mist-typed
adapter and compatibility ledger approved on 2026-07-30. Delete that adapter
when a coherent revision contains the required shared server surface and
`run_with_grant`.

**Files:**
- Create: `crates/rustmistmcp/src/main.rs`
- Create: `crates/rustmistmcp/src/http_transport.rs`
- Create: `examples/mist.example.json`
- Test: `crates/rustmistmcp/tests/runtime_contract.rs`

**Interfaces:**
- Produces the `rustmistmcp` binary with stdio and Streamable HTTP.
- Consumes shared CLI, validation, audit, TLS, signals, token commands, and
  HTTP router construction.

- [ ] Write failing tests for startup profile verification, token minting
  without Mist contact, read-only stdio/no-auth, HTTP bearer preflight,
  targets, TLS/listener validation, SIGHUP reload, shared flag names, and
  durable state paths.
- [ ] Implement the thin runtime composition using only `mecmcp` primitives.
- [ ] Run all runtime and workspace tests.
- [ ] Commit as `feat: compose rustmistmcp runtime`.

### Task 8: Packaging, release evidence, and lab deployment

**Files:**
- Create: `Dockerfile`, `packaging/container/compose.example.yaml`
- Create: `packaging/lxc/`
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- Modify: `README.md`, `CLAUDE.md`

**Interfaces:**
- Produces OCI image, LXC archive/installer, systemd service, sysusers/tmpfiles,
  journald/audit configuration, SBOM/checksums/provenance, and operator docs.

- [ ] Add static packaging contract tests before packaging files: digest pins,
  UID/GID 65532, distroless Debian 13, read-only compose, exact paths/modes,
  unprivileged Debian 13 `nesting=1`, idempotent/no-clobber installer, shared
  CLI flags, and no runtime process spawns.
- [ ] Implement Docker and LXC packages and CI/release jobs until contracts pass.
- [ ] Refresh the reference/spec once at RC, regenerate, review the delta, and
  require zero parity gaps.
- [ ] Verify archive install/upgrade and OCI startup/health/read-only mounts.
- [ ] Reconfirm VMID 613 and an address are unused, snapshot no unrelated
  guest, provision a new LXC only, install, configure secrets at 0600, enable
  audit forwarding, and test against the writable Mist tenant.
- [ ] Run formatting, clippy `-D warnings`, tests, dependency/license checks,
  SBOM/provenance, glibc-floor, packaging, and end-to-end gates.
- [ ] Commit as `release: prepare rustmistmcp v1`.
