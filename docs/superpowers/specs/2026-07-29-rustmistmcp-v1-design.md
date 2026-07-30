# rustmistmcp v1 Design

## Goal

Build a production Rust MCP server with full functional parity to the Mist
portion of `nowireless4u/hpe-networking-mcp`, without registering its generated
one-tool-per-operation surface.

Release parity means every frozen reference operation is reachable through
either a curated workflow tool or a catalog-backed dispatcher. It does not mean
matching the Python tool names or schemas.

## Ownership Boundary

`rustmistmcp` owns only Mist-specific behavior:

- the Mist OpenAPI snapshot, catalog, and parity manifest;
- Mist API-token header semantics and regional endpoint validation;
- Mist request/response and pagination behavior;
- org/site target extraction;
- Mist operation classification and `MistGrant`;
- curated Mist workflows and the Mist changeset adapter.

`mecmcp` owns authentication, target/tool scopes, caller attribution, audit,
bounded result conversion, inbound Streamable HTTP, TLS, runtime CLI and
signals, secure outbound cloud primitives, and change-set lifecycle. This
project must not edit `mecmcp` or duplicate a missing shared feature. Existing
issues `mecmcp#90` and `mecmcp#91` are prerequisites.

`rustsdcmcp`, VMID 612 (`foundry`), and all unrelated repositories and guests
remain untouched.

One narrow exception was approved on 2026-07-30: the private Mist-typed token
lifecycle adapter specified in
`2026-07-30-temporary-mist-token-lifecycle-compat-design.md`. Its upstream
ledger and objective deletion condition are mandatory; it does not change the
ownership of any `mecmcp#90` foundation.

## Architecture

The Cargo workspace has two crates:

- `rustmistmcp-core`: Mist configuration, operation catalog, grants, request
  validation, pagination, client adapter, typed workflow models, and changes.
- `rustmistmcp`: `rmcp` handler, tool registry, curated tools, parity
  dispatchers, shared runtime composition, and HTTP transport wiring.

All `mecmcp-*` crates use one immutable Git revision so request-extension type
identities cannot diverge.

One process loads one Mist profile: one HTTPS regional endpoint and one API
token from a secure file. Startup calls `/api/v1/self`, verifies the configured
organization allowlist, and discovers the profile's org/site view.

## Operation Catalog and Parity

The official Mist OpenAPI document is vendored with its upstream blob SHA,
version, source URL, and MIT attribution. A deterministic generator emits an
internal manifest, never Rust tool wrappers.

Each catalog entry contains:

- operation ID, method, tags, and summary;
- path template and typed path/query parameters;
- supported request media and schema reference;
- `OrdinaryRead`, `PrivilegedRead`, `Create`, `Update`, `Delete`, or `Execute`;
- org/site target selectors;
- response media and pagination mode;
- verification policy.

A separate parity manifest maps the example's actually registered Mist tools to
operation IDs. The initial example commit is
`2b91700b9049c2c27ce6a811a272f2ddfa8091e5`; release candidate refreshes the
example and official spec once, closes the delta, then freezes both revisions.

## Public MCP Surface

Named workflows:

- `get_mist_self`, `list_mist_orgs`, `get_mist_org`;
- `list_mist_sites`, `get_mist_site`;
- `search_mist_inventory`, `get_mist_device`, `get_mist_device_stats`;
- `list_mist_wlans`, `search_mist_clients`;
- `search_mist_events`, `search_mist_alarms`, `search_mist_audit_logs`;
- `list_mist_sle_metrics`, `get_mist_sle`, `get_mist_insight`;
- `troubleshoot_mist`, `list_mist_rogues`, `get_mist_rrm`;
- `list_mist_upgrades`.

Parity tools:

- `search_mist_operations`, `get_mist_operation_schema`;
- `invoke_mist_read`, `invoke_mist_privileged_read`;
- `prepare_mist_change`, `approve_mist_change_set`,
  `apply_mist_change_set`, `get_mist_change_set`.

Dispatchers accept only an operation ID plus structured path/query/body/file
values. They never accept an arbitrary method or URL. Ordinary wildcard tool
scope excludes privileged reads and every change tool.

Canonical authorization targets are `org/<uuid>` and `site/<uuid>`.
`MistGrant` contains exact operation IDs and permitted `MistAction` values.

## Request and Change Behavior

Path values are substituted as whole encoded segments. Query values are
validated against the catalog. JSON and bounded multipart bodies are supported.
Responses are streamed under a configured byte limit and decoded as JSON,
UTF-8 text, or bounded binary content.

Mist page/limit headers, `X-Next-Page`, response-body `next`, and
`search_after` are normalized to an operation-bound opaque cursor. Cursor
follow-up must remain on the configured origin and the original operation.

Mist HTTP 429 preserves `Retry-After`. Mutations are never automatically
retried.

Change preparation validates `MistGrant`, canonicalizes the exact request,
redacts its review artifact, and persists it through `mecmcp-changeset`.
Approval requires a separate principal. Apply revalidates owner, target, grant,
policy, and digests, then sends the persisted request. A catalogued follow-up
read verifies state where available; otherwise the result is explicitly
API-acknowledged rather than state-verified.

## Delivery

The release provides both:

- a digest-pinned OCI image using
  `gcr.io/distroless/cc-debian13:nonroot`, UID/GID 65532, read-only root, and
  explicit read-only secret/config plus writable state mounts;
- an LXC archive and idempotent Debian 13 installer for an unprivileged
  `nesting=1` container with persistent journald, remote forwarding, JSON audit,
  HMAC redaction, and mode-0600 credentials.

Configuration lives under `/etc/rustmistmcp`; durable state lives under
`/var/lib/rustmistmcp`. Shared flags retain the exact names `--lab-mode`,
`--state-file`, and `--approval-timeout-secs`.

The lab deployment uses a new dedicated LXC at VMID 613 if it is still free,
otherwise the nearest free VMID. Its address is proven unused immediately
before assignment. VMID 612 is never modified.

## Verification

The generator must account for every frozen example and spec operation without
duplicates, unsafe paths, unresolved schemas, missing capability/target
classification, or mutation verification policy.

Unit and mock-server tests cover configuration, credentials, paths, schemas,
grants, targets, pagination, cursors, rate limiting, response bounds,
cancellation, mutation non-retry, approval, persistence, tampering, restart,
and indeterminate outcomes.

The writable Mist test tenant validates all named workflows and a reversible
GET/POST/PUT/DELETE matrix. Unsafe account/destructive operations remain
contract-tested and are named in release evidence.

Release gates include formatting, clippy with warnings denied, workspace tests,
dependency/license checks, SBOM, checksums and provenance, measured glibc
floor, clean catalog generation, zero parity gaps, tested Docker deployment,
tested fresh LXC install/upgrade, and live-tenant evidence.
