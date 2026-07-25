# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`rustmistmcp` is an MCP server for the **HPE Juniper Mist cloud**. The
repository is currently a **scaffold** — README, LICENSE, branding, and
toolchain pin only. There is no Cargo workspace, no crates, and no build/test
commands yet. Do not invent build instructions; add them here when the workspace
actually lands.

## The one architectural rule

This repo is a **consumer** of [`mecmcp`](https://github.com/fastrevmd-lab/mecmcp)
(local checkout: `~/Projects/mecmcp`), the vendor-neutral Rust foundation shared
across the mechub MCP server family. The split is not negotiable:

- **Upstream in `mecmcp`:** token auth/scopes/grants (`mecmcp-auth`), audit and
  redaction (`mecmcp-audit`), streamable-HTTP transport and limits
  (`mecmcp-transport`), CLI/TLS/shutdown (`mecmcp-runtime`), change-control
  state machine (`mecmcp-changeset`), inventory (`mecmcp-inventory`).
- **Here:** the Mist REST client, its API-token / OAuth 2.0 auth flow, response
  models, and the MCP tool surface built on them.

If you are about to write generic auth, transport, rate-limiting, or
change-control code in this repo, stop — it belongs in `mecmcp`. `mecmcp` is
itself mid-extraction (only `mecmcp-auth` exists so far); its `PLAN.md` and
`ANALYSIS.md` describe what lands when.

Sibling reference implementations for the *shape* of a mechub MCP server:
`~/Projects/RustJunosMCP` (NETCONF/SSH, runtime hardening) and
`~/Projects/rust-panosmcp` (HTTPS XML-API, change-control lifecycle). Mist is
closest to the PAN-OS repo — an HTTPS API against a remote control plane — so
prefer its structure when adding the client and tool layers. `~/Projects/rustsdcmcp`
(Security Director Cloud) is the nearest sibling in kind: also a cloud
management plane, also at scaffold stage.

## Cloud control plane, not device plane

Mist is multi-tenant SaaS. One org-scoped call reaches every site and every AP,
switch, and gateway in an estate. Consequences that must hold in any code added
here:

- Mutating tools are reachable **only** through `mecmcp-changeset`'s
  plan → digest → approve → apply → verify lifecycle. Never a direct write.
- Read-only tools land first and stay the majority of the surface.
- Bearer tokens carry explicit tool, **org**, and **site** scopes. Org-level
  reach is the default failure mode of this API; scoping is what contains it.
- Responses are bounded and paginated. An org-wide client or event query returns
  orders of magnitude more than a single-site one.

## Curated tools, not a generated registry

The functional target is the Mist half of
[`nowireless4u/hpe-networking-mcp`](https://github.com/nowireless4u/hpe-networking-mcp),
which registers ~1,050 spec-generated Mist tools. **Do not reproduce that
approach.** Tools here are hand-picked and hand-documented. When adding one, the
bar is that an operator would name it; a bulk import of the OpenAPI spec is a
rejected design, not a shortcut.

Domains worth covering, roughly in landing order: org/site inventory, device
inventory and stats (AP/switch/gateway), site health and SLE, WLAN/SSID, client
connectivity, events and alarms, audit logs, troubleshooting actions
(ping/traceroute/bounce), RRM and rogue detection, firmware, NAC/policy, guest
access, webhooks, floor plans, Marvis.

## API research discipline

Several Juniper doc pages return navigation-only content to fetchers. Do not
write endpoint paths, header names, region hosts, or pagination behavior from
memory or inference. Verify against:

- https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/restful-api-overview.html
- https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/task/create-token-for-rest-api.html
- https://www.juniper.net/documentation/us/en/software/mist/api/http/guides/overview/mist-apis

Verified so far:

- Base path `/api/v1`, per-region hosts — `api.mist.com` (Global 01),
  `api.eu.mist.com` (EU 01), `api.gc1.mist.com` (GovCloud). More regions exist;
  the region is operator-configured, never inferred.
- Auth header is literally `Authorization: Token <token>` (the word `Token`,
  a space, then the token). Tokens are user- or org-scoped and inherit the
  creating account's privileges.
- External OAuth 2.0 providers are supported.
- HTTP Basic auth with Mist login credentials is deprecated as of September
  2026 — do not implement it.

Everything else — the full region table, rate limits, pagination cursors, per-
resource shapes — is unverified. Record findings in `docs/` as they are confirmed.

## Conventions inherited from the family

- Rust edition 2024, MSRV 1.88, build toolchain pinned in `rust-toolchain.toml`.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn.
- Single MIT license (not dual). Repo name is lowercase, no dashes — mechub
  brand rule.
- `.gitignore` deliberately blocks `tokens.json`, `*.tokens.json`, `.env`,
  `*.pem`, `*.key`. Test fixtures under `crates/*/tests/fixtures/` are the only
  exception.
