# Mist API token role guidance

There are **two separate credential layers** in this deployment, and they are
easy to conflate:

| Layer | What it is | Where it's configured | Who checks it |
|---|---|---|---|
| **Mist API token** | The outbound credential this server sends to the Mist cloud API (`Authorization: Token <token>`) | `mist-api-token` file, minted in the Mist portal | Mist's own API, entirely outside this codebase |
| **MCP bearer token** | The credential an MCP client presents to *this server* | `tokens.json`, minted with `rustmistmcp token add` | `mecmcp-auth` + this server's `RESTRICTED_TOOLS`/`MistGrant` checks |

The MCP bearer layer's scoping (`--devices`, `--tools`, `MistGrant`
`subjects`/`actions`/`allowed_operations`) is enforced entirely in this
server's code, and is deny-by-default — see `docs/THREAT_MODEL.md`. **None of
that matters if the underlying Mist API token itself is over-privileged**,
because the API token's role is the outer bound on everything a request can
do once it reaches Mist, regardless of how narrowly the MCP bearer token was
scoped. This document is about that first layer, which no amount of MCP-side
scoping can substitute for.

## Recommendation: a dedicated, least-privilege org token

**Do not use a personal/user-level Mist API token for this server.** Mist API
tokens can be minted per user or per organization, and — per Mist's own
documentation — inherit the privileges of the account that created them. A
user token:

- Inherits **that user's full role**, which is frequently broader than what
  automated tooling needs and changes whenever that user's role changes,
  invisibly to this server's operator.
- Shares that **user's rate-limit budget** with their own interactive use of
  the Mist portal and any other integration minted under their account — a
  burst of automated reads or a runaway agent loop can degrade or lock out
  the human whose token it is.
- Ties this server's continued operation to an individual's employment and
  account state. If that person leaves or their account is disabled, the
  integration breaks with no clear ownership trail.
- Makes audit attribution ambiguous: Mist's own audit log records the token's
  owning user, not "the automation," so a security review cannot cleanly
  separate a human's manual portal actions from this server's calls.

Instead:

1. **Create a dedicated organization API token** (*Organization ▸ Settings ▸
   API Tokens*), not a token minted under an individual's user account. This
   gives the credential its own identity in Mist's audit trail, independent
   of any one operator.
2. **Scope the token's role to the narrowest privilege this deployment
   actually needs**, following Mist's own role model:
   - If this deployment only uses read/search tools (the default majority of
     the tool surface — see `README.md`'s WAN edge tools table and the full
     `KNOWN_TOOLS` registry), mint a **read-only / observer-level** org role.
     Do not grant write/admin privileges "for later" — mint a second token
     when a write deployment is actually staged.
   - If this deployment also uses the batch-1 WAN edge change-set lifecycle
     (`plan_mist_change` → `approve_mist_change_set` →
     `apply_mist_change_set`), the token needs write privilege scoped to the
     WAN edge object types this server actually mutates (networks, services,
     service policies, gateway templates, device profiles) — not
     organization-wide super-admin. Consult current Mist role documentation
     for the narrowest role that covers those object types; Mist's role
     granularity changes over vendor releases, so re-verify at token mint
     time rather than trusting a past mapping.
   - **Never mint a super-admin or account-level token for this server.** A
     super-admin token defeats every MCP-side scope check described in
     `docs/THREAT_MODEL.md`: this server's `RESTRICTED_TOOLS` gate and
     `MistGrant` subjects narrow *which calls this server's code will
     attempt*, but they do nothing to narrow what the underlying credential
     is *authorized to do* once a call reaches Mist.
3. **One org token per deployment, not one shared across environments.** A
   lab/test deployment and a production deployment must use separate Mist
   API tokens scoped to separate orgs (or at minimum, separately revocable
   tokens), so revoking or rotating one never affects the other and a lab
   compromise cannot reach production.
4. **Record the token's role and org in your own change-management system**
   at mint time, since Mist's UI is the only place that role currently lives
   — this server has no way to introspect or display what privilege its
   configured token actually carries.

## Rotation and revocation

- Rotate the Mist API token on a defined schedule and immediately on any
  suspected compromise, operator departure, or LXC/host rebuild — see
  `docs/OPERATIONS.md`'s "Guest lifecycle" section for why destroying the
  host does **not** revoke the token at Mist's end.
- The Mist API token and the MCP bearer-token store rotate independently.
  Rotating one does not require rotating the other.
- After minting a replacement Mist API token, update `mist-api-token` in
  place (`chmod 0600`, correct ownership per `docs/OPERATIONS.md`) and
  restart the service; there is no live-reload for this credential.

## MCP bearer-token scoping (the second layer)

Once the Mist API token itself is least-privilege, scope MCP bearer tokens
the same way:

- Use `--devices` and `--tools` to name exact orgs/sites and tools rather
  than wildcards wherever the deployment allows it. `--tools '*'` resolves to
  every tool **except** `RESTRICTED_TOOLS` — the mutation tools and the
  privileged read tools (`get_mist_change_set`, `get_mist_self`, `get_mist_device`,
  `list_mist_wlans`, `get_mist_wan_config`, `list_mist_wan_config`,
  `invoke_mist_privileged_read`, `search_mist_audit_logs`) always require an
  explicit per-token grant; a wildcard token cannot reach them by accident.
- Mint the owner and approver of a change set as **separate named tokens**
  held by separate people. Self-approval is refused by token name, but two
  differently-named tokens held by the same human still defeat the intent of
  two-person control — see `docs/THREAT_MODEL.md`'s residual-risk section.
- Never run `--lab-mode` — which waives the second-approval requirement —
  against a deployment whose Mist API token can reach a production org. On
  the stdio transport there is no bearer layer at all, so this section does
  not apply there, and the Mist API token's role is the only bound.

## Summary

| Decision | Recommended | Avoid |
|---|---|---|
| Token origin | Dedicated organization API token | Personal/user API token |
| Token role | Narrowest role covering the tools this deployment actually uses | Super-admin / account-level |
| Token scope per environment | One token per deployment/environment | One token shared across lab and production |
| MCP bearer tool scope | Explicit `--tools` allowlist, or wildcard understood to exclude `RESTRICTED_TOOLS` | Assuming wildcard grants everything |
| Change-set principals | Two named tokens held by two people | One token, or two tokens held by one person |
