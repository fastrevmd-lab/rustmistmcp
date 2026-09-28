# Threat model

Status: pre-release baseline, 2026-09-28, validated against `main` @ `f8575f5`.

This document defines the security boundaries, assets, and required controls
for `rustmistmcp`. It exists to answer the question a procurement or security
review asks before deployment: **what can a compromised token or a compromised
MCP-client agent do against a real Mist org, and what stops it?**

For token issuance guidance, see [`TOKEN_ROLE_GUIDANCE.md`](TOKEN_ROLE_GUIDANCE.md).
For the checklist a human runs before treating a build as shippable, see
[`PACKAGING_ACCEPTANCE.md`](PACKAGING_ACCEPTANCE.md).

## Scope

The server accepts MCP requests over stdio or bearer-protected Streamable HTTP
and translates authorized tool calls into HPE Juniper Mist cloud REST API
calls (`/api/v1`, region-specific host). Mist is a **multi-tenant cloud
control plane**: a single org-scoped credential can reach every site, AP,
switch, and gateway the org owns. That is the defining difference from the
device-plane servers in this family (`rustjunosmcp`, `rustpanosmcp`), and it
sets the blast radius described below.

In scope: API-token authentication to Mist, the curated read/search tool
surface, and the batch-1 WAN edge write lifecycle (`plan_mist_change` →
`approve_mist_change_set` → `apply_mist_change_set`) for networks, services,
service policies, gateway templates, and device profiles.

Out of scope for this document: Mist OAuth 2.0 (not implemented — see
README), delete operations and `mist_configured` device-profile
assignment/unassignment (not implemented — `plan_mist_change` refuses any
patch containing `mist_configured`), and any tool not present in
`crates/rustmistmcp/src/server/mod.rs`'s `KNOWN_TOOLS`/tool router.

## Assets

- The outbound **Mist API token** (`mist-api-token`) — inherits the
  privileges of whatever account created it in the Mist portal.
- **MCP bearer credentials** and their tool/device scopes (`mecmcp-auth`
  token store, `tokens.json`).
- **`MistGrant`** authorization data: `allowed_operations`, `actions`,
  and `subjects` (canonical org/site targets) bound to a token.
- Mist org, site, WLAN, device, and WAN edge configuration reachable through
  that org's API token.
- Operational and telemetry data returned by read tools: device stats,
  clients, events, alarms, audit logs, SLE, inventory.
- Change-set state (`changeset-state.json`) — staged and approved mutations
  awaiting apply.
- Audit records that attribute a call to a token, tool, and target.
- Integrity of the binary, dependency graph, and release/packaging pipeline.

## Trust boundaries

```text
MCP client (human operator, agent, or LLM tool loop)
   │  untrusted request fields; bearer credential on HTTP
   ▼
MCP transport boundary (mecmcp-transport)
   │  bearer authentication, Host/Origin checks, size/rate/concurrency limits
   ▼
rustmistmcp process
   │  scope preflight (MistScopePreflight), MistGrant check, catalog/operation
   │  validation, RESTRICTED_TOOLS gate, bounded response handling
   ▼
Mist cloud REST API (api.mist.com / api.eu.mist.com / api.gc1.mist.com / ...)
   │  Authorization: Token <mist-api-token>, org-scoped
   ▼
The customer's real Mist organization: every site, AP, switch, gateway,
WLAN, and WAN edge device that org owns

Local operator ── mist.json / mist-api-token / tokens.json / audit-hmac.key ──► rustmistmcp process
Supply chain  ── source / crates.io / CI / OCI base images ─────────────────► deployed binary
```

Crossing a boundary does not make data trusted. A successful MCP bearer check
does not make tool arguments, catalog operation IDs, or Mist response bodies
safe; the process still validates them independently.

## Security principals

- **Local operator**: controls `mist.json`, `mist-api-token`,
  `audit-hmac.key`, and the token store. Trusted to administer the deployment,
  but a scoping mistake here (an over-privileged Mist API token, a wildcard
  bearer grant) is the single largest risk this document tracks.
- **MCP bearer-token holder**: may call only the tools and Mist
  org/site subjects its `MistGrant` and shared `devices`/`tools` scope
  name. Different token names are different principals; approval of a
  change set requires two distinct ones (see below).
- **Mist API administrator identity behind the outbound token**: the
  *actual* ceiling on everything this server can do to the org, independent
  of MCP-side scoping. See `TOKEN_ROLE_GUIDANCE.md`.
- **Remote attacker**: can reach the MCP listener or influence an MCP
  client but holds no valid bearer token.
- **Malicious or compromised MCP client / agent**: holds a valid but
  limited bearer token and attempts scope escalation, resource exhaustion, or
  policy bypass — including via an LLM tool-loop that was itself prompt-
  injected by data returned from a Mist read call.
- **Compromised or spoofed Mist endpoint**: returns hostile or oversized
  response bodies, or attempts to stall the client indefinitely.

## Compromised token / compromised agent: what it can do

This is the scenario an enterprise security review cares most about, so it is
stated explicitly rather than left to the table below.

**A stolen bearer token that is correctly scoped** can do exactly what its
`devices`/`tools` scope and `MistGrant` allow: call the named tools against
the named org/site subjects, nothing else. `RESTRICTED_TOOLS` — which
includes every change-set tool plus the privileged read tools
(`get_mist_change_set`, `get_mist_self`, `get_mist_device`,
`list_mist_wlans`, `get_mist_wan_config`,
`list_mist_wan_config`, `invoke_mist_privileged_read`,
`search_mist_audit_logs`) — is never reachable through a wildcard `--tools
'*'` grant; each must be explicitly named. A stolen read-only, narrowly
scoped token can read whatever data its scope covers and nothing more; it
cannot stage or apply a change set.

**A stolen bearer token scoped to write tools** can stage
(`plan_mist_change`) and, if it also holds approval reach as a *second*
distinct token name, apply mutations to batch-1 WAN edge objects (networks,
services, service policies, gateway templates, device profiles) within its
`MistGrant` subjects. It cannot delete objects or touch `mist_configured`
device-profile assignment (both refused at the tool level, not just by
scope). Applying a change still requires the plan → digest → approve → apply
lifecycle to complete, which bounds a single stolen token to *proposing*
changes, not silently applying them — unless `--lab-mode` is enabled, which
waives the second-principal requirement (see README's `--lab-mode` section)
and must never run against production.

**The Mist org-scoped API token itself compromised** (not the MCP bearer
layer, but the outbound credential in `/etc/rustmistmcp/mist-api-token`) is
the worst case: it inherits whatever role was granted to it in the Mist
portal, and MCP-side scoping does nothing to constrain calls made outside
this server. This is why `TOKEN_ROLE_GUIDANCE.md` exists — the MCP
authorization layer described above is only as narrow as the *underlying*
Mist API token's role, and a super-admin or account-level token defeats
every MCP-side control in this document.

**A compromised agent on the stdio transport** is a different case, because
stdio has no bearer layer at all. Every stdio caller is the single principal
`stdio`. Restricted tools are left out of `tools/list`, but a client that
names them directly can still call them: `plan_mist_change` stages a change
set with no bearer check, gated only by the server's `allowed_orgs`. Two
things still hold. Approval cannot happen on stdio, because the approver is
also `stdio` and self-approval is refused, so a stdio agent can propose
changes but cannot apply them. And with `--lab-mode`, the plan is waived on
creation, so **one stdio agent can plan and apply a WAN edge mutation
against the real org with no second human**. In that configuration layer 2
does not exist, layer 3 is waived, and only the Mist API token's role
(layer 1) bounds the damage. Never combine stdio, `--lab-mode`, and a token
that can reach a production org.

**Blast radius against a real Mist org** is therefore bounded by three
independent layers, weakest link wins:
1. The Mist API token's role/privilege in the Mist portal (operator-controlled,
   outside this server's code — see token-role guidance).
2. The MCP bearer token's `devices`/`tools`/`MistGrant` scope (server-enforced,
   deny-by-default, `RESTRICTED_TOOLS` cannot be reached by wildcard).
3. The plan → approve → apply lifecycle for mutations (server-enforced,
   requires a second distinct principal unless `--lab-mode`).

A weakness in any one layer does not compromise the others, but a weak Mist
API token role (layer 1) is not mitigated at all by layers 2 and 3 for calls
this server is scoped to make — it only bounds *which* organization data a
narrowly-scoped MCP token can reach within whatever the API token can already
do.

## Non-negotiable invariants

1. Remote MCP requests are authenticated before tool execution.
2. Authentication and authorization failures never reveal whether another
   token, org, site, or secret exists beyond what the caller may already know.
3. On the HTTP transport, a token's scope and `MistGrant` are checked for
   both the tool and every target subject before any Mist network I/O
   begins. On stdio there is no token; only the server's `allowed_orgs` and
   site map bound the target.
4. Caller input cannot select an arbitrary Mist host. The region/endpoint
   comes only from operator configuration (`mist.json`), never a request field.
5. Mist API tokens and MCP bearer secrets never appear in URLs, logs, errors,
   MCP results, panic output, or `Debug` formatting.
6. On the HTTP transport, `RESTRICTED_TOOLS` (every change-set tool and every
   privileged read tool) is unreachable by a wildcard tool grant; each
   requires an explicit per-token allowlist entry. On stdio there is no
   bearer layer: restricted tools are hidden from `tools/list` but remain
   callable by the local client (see "stdio transport" above).
7. Every untrusted response and request payload has a size bound.
8. A change set is applied only after an explicit plan → digest → approve →
   apply sequence, with the approver a distinct principal from the owner,
   unless `--lab-mode` is enabled — which is off by default, warns loudly at
   startup, and is never to be used against production.
9. `plan_mist_change` refuses any patch touching `mist_configured`; this
   refusal cannot be approved past.
10. Audit records identify the principal, tool, target, outcome, and timing
    without recording Mist secrets or full configuration payloads.

## Threats and required controls

| Threat | Consequence | Required controls | Status |
|---|---|---|---|
| Stolen or guessed MCP bearer token | Unauthorized tool access within scope | Digest-only token store, per-token `devices`/`tools`/`MistGrant` scope, TLS on any non-loopback bind | In place (`mecmcp-auth`) |
| Over-privileged outbound Mist API token (super-admin/account token) | MCP-side scoping cannot constrain what the credential itself is allowed to do | Operator issues a dedicated, least-privilege org token — no code-level control possible | Documented, operator-enforced — see `TOKEN_ROLE_GUIDANCE.md` |
| Wildcard MCP token scope reaching a mutation or privileged-read tool | Unscoped write or privileged-read access | `RESTRICTED_TOOLS` list; wildcard `--tools '*'` resolves to non-restricted tools only | In place |
| DNS rebinding / browser-origin attack against the HTTP listener | A website reaches a loopback MCP server | Loopback default, strict Host/Origin allowlists | In place (`mecmcp-transport`) |
| Plaintext remote transport | Bearer and payload interception | TLS required for any non-loopback bind; insecure bind is explicit | In place |
| Change-set replay after a network failure | Duplicate or unintended mutation | Digest-bound plan, drift check at apply, terminal-state tracking | In place (`mecmcp-changeset`) |
| Single-token self-approval of a mutation | One compromised token both stages and approves a write | Approver must be a distinct token name from the owner | In place, except under `--lab-mode` |
| `--lab-mode` accidentally left enabled against a production org | Two-person control silently waived | Off by default, startup warning, change set recorded with `approver: null` and `waived: { reason: "lab-mode" }` (`approval_waiver=lab-mode` in audit), so it is distinguishable from a real approval; audit records are tamper-evident only when `audit-hmac.key` is configured | In place |
| Delete or `mist_configured` mutation reachable through a crafted patch | Out-of-scope destructive change | `plan_mist_change` refuses `mist_configured`; delete operations are not implemented as tools | In place |
| Prompt-injected LLM agent attempts an unscoped Mist call via this server | Scope bypass driven by hostile data returned from an earlier Mist read | Deterministic server-side scope/grant enforcement — the model's intent is never trusted, only the token's scope | In place (house rule: deterministic code decides, the model explains) |
| Oversized or hostile Mist API response | Memory exhaustion or slow client | Response size caps (`RESULT_LIMITS`, 512 KiB text/JSON) | In place |
| Leaked audit trail correlating transport and handler events | Reduced ability to reconstruct an incident | Transport and handler audit events currently mint different `request_id`s | Known gap — `mecmcp#269`, tracked upstream |
| Compromised release artifact (supply chain) | Malicious binary/image deployed | Locked `Cargo.lock`, `cargo audit`/`cargo deny` in CI, deterministic release build, digest-pinned OCI base images | In place for build reproducibility; **image signing not yet implemented** |
| Unsigned OCI image pulled by tag instead of digest | Image substitution between build and pull | Sigstore cosign signing, SBOM and build provenance attestation, CI pinned to exact digests | **Planned** — follow-on to `rustsdcmcp#182` / MEC-349, not yet implemented here (see below) |
| Weak local file permissions on secrets | Local credential theft | Documented ownership/mode for `mist.json`, `mist-api-token`, `tokens.json`, `audit-hmac.key` (see `docs/OPERATIONS.md`) | In place, operator-verified |
| Systemd egress-filter declared but not enforced (unprivileged LXC) | Silent absence of the egress control it appears to provide | Installer probes actual BPF attachment and reports `ENFORCED`/`NOT ENFORCED`/`NO POLICY`/`UNKNOWN`; `RUSTMISTMCP_REQUIRE_EGRESS_FILTER=1` refuses anything short of `ENFORCED` | In place — see `docs/OPERATIONS.md` |

## Mitigations already in place vs. planned

**In place today:**
- Deny-by-default MCP authorization: `RESTRICTED_TOOLS` gate, per-token
  `devices`/`tools` scope, `MistGrant` subject/action/operation allowlists.
- Two-person change control for every mutation, off only under an explicit,
  loudly-logged `--lab-mode`.
- Digest-bound plan/apply lifecycle with drift detection (`mecmcp-changeset`).
- Bounded, auditable I/O: response size caps, structured audit events,
  redaction via `mecmcp-audit`.
- Loopback-by-default HTTP transport with Host/Origin enforcement and
  TLS-required non-loopback binds.
- Deterministic packaging: digest-pinned distroless OCI runtime, non-root
  UID/GID, no shell/package manager in the image, locked dependency graph,
  `cargo audit`/`cargo deny` in CI.
- Egress-filter enforcement probing for the unprivileged-LXC deployment
  target, where systemd's own `IPAddressDeny` cannot be trusted to work.

**Planned, not yet implemented:**
- **Signed release images.** Tracked as a follow-on to `rustsdcmcp#182`
  (Sigstore cosign signing without long-lived keys, SBOM and build
  provenance attestations, actions pinned to commit SHA) once that lands in `mecmcp`/`rustsdcmcp`. This repository does
  not re-derive a separate signing scheme — see MEC-349.
- **`/api/v1/self` startup identity probe.** The outbound `HttpMistClient`
  can make the call (`get_mist_self` proves it against a live tenant); no
  code probes it automatically at startup yet.
- **Delete operations and `mist_configured` assignment/unassignment.** Not
  implemented as tools; intentionally out of reach rather than a gap.
- **Correlated transport/handler audit `request_id`.** Tracked upstream as
  `mecmcp#269`.
- **Remote hash-chained audit forwarding to SSDF.** Specified, not yet
  implemented — see README's "Audit forwarding to the event store" section
  and `mecmcp#292`.

## Residual risk

Two-person approval assumes distinct token *names* map to distinct human
operators; nothing in this server can verify that a "second" approving token
is not held by the same person who staged the change. The Mist API token's
role is the outer bound on everything this server can do regardless of
MCP-side scoping — see `TOKEN_ROLE_GUIDANCE.md` for why that is an operator
decision this codebase cannot enforce. Base OCI image digests freeze
reviewed bytes but also freeze their vulnerabilities; operators must take
tested digest updates promptly. `--lab-mode`, once enabled, removes the
second-reviewer property for every change set created while it is on — the
audit trail records this honestly, but the control itself is gone for that
window.

## Verification obligations

Before a remote (non-loopback) release, the test suite and manual acceptance
run must cover:

- missing, malformed, invalid, and out-of-scope bearer tokens;
- a wildcard-scoped token attempting a `RESTRICTED_TOOLS` call (must refuse);
- Host/Origin allowlist failures;
- self-approval refusal (same token name staging and approving);
- `--lab-mode` audit-trail distinguishability from a genuine approval;
- a `plan_mist_change` patch containing `mist_configured` (must refuse);
- oversized Mist API response handling;
- the packaging checklist in `docs/PACKAGING_ACCEPTANCE.md`.

Security findings must follow the private disclosure process in
[`SECURITY.md`](../SECURITY.md).
