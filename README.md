<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustmistmcp</h1>

<p align="center"><strong>Async Rust Model Context Protocol server for the HPE Juniper Mist cloud</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project
> and does not claim affiliation with or endorsement by Hewlett Packard
> Enterprise or Juniper Networks. Product names and trademarks are used only to
> identify the systems with which the software interoperates.

---

`rustmistmcp` exposes the **Juniper Mist cloud** — orgs, sites, APs, switches,
gateways, WLANs, clients, SLE, and Marvis — to MCP clients as a bounded,
auditable tool surface.

Where [`rustjunosmcp`](https://github.com/fastrevmd-lab/rustjunosmcp) talks
NETCONF to individual SRX devices and
[`rustpanosmcp`](https://github.com/fastrevmd-lab/rustpanosmcp) talks XML-API to
individual PAN-OS firewalls, this server talks to a **multi-tenant cloud control
plane**. One org-scoped call can reach every site and every access point in an
estate, so scoping, bounded responses, and change control are not garnish here;
they are the design.

The functional target is the Mist half of
[`nowireless4u/hpe-networking-mcp`](https://github.com/nowireless4u/hpe-networking-mcp)
— site health and SLE, device inventory and stats, WLAN/SSID management, client
connectivity, events and alarms, audit logs, RRM and rogue detection, firmware,
NAC/policy, guest access, webhooks, floor plans, and Marvis — reimplemented in
Rust on the `mecmcp` foundation rather than as a Python spec-driven registry.
That project registers on the order of a thousand generated tools; this one
deliberately will not. A curated, scoped, individually-documented surface is the
whole point of doing it again.

## Relationship to `mecmcp`

[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) is the vendor-neutral Rust
foundation shared by the mechub MCP server family. This repository is a
**consumer** of that foundation, not a fork of it:

| Concern | Where it lives |
|---|---|
| Token mint/digest/verify, `tokens.json`, scopes, grants, caller context | `mecmcp-auth` |
| Attribution, audit events, redaction, sinks | `mecmcp-audit` |
| Streamable-HTTP transport, host/Origin checks, rate + concurrency limits | `mecmcp-transport` |
| CLI skeleton, TLS bootstrap, signals, graceful shutdown | `mecmcp-runtime` |
| Plan → digest → approve → apply → verify change control | `mecmcp-changeset` |
| Org/site/tenant registry | `mecmcp-inventory` |
| **Mist REST client, token/OAuth auth, response models, tool surface** | **this repo** |

Everything that is *not* specific to the Mist API is upstream. If you find
yourself writing generic auth or transport code here, it belongs in `mecmcp`.

## The API

Mist publishes a versioned REST API under `/api/v1`, served from per-region
cloud endpoints. The org's home region determines the host:

| Region | Endpoint |
|---|---|
| Global 01 | `api.mist.com` |
| EU 01 | `api.eu.mist.com` |
| GovCloud | `api.gc1.mist.com` |

Additional regional clouds exist; the authoritative list is Juniper's *API
Endpoints and Global Regions* table, and the region must be operator-configured
rather than guessed.

Authentication is by **API token**, sent as `Authorization: Token <token>`.
Tokens may be minted per user or per organization, and inherit the privileges of
the account that created them. An external **OAuth 2.0** provider is also
supported. HTTP Basic authentication with Juniper Mist login credentials is
**deprecated as of September 2026** and will not be implemented here.

Primary references:

- [RESTful API Overview](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/restful-api-overview.html)
- [Create API Tokens](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/task/create-token-for-rest-api.html)
- [Mist API Reference](https://www.juniper.net/documentation/us/en/software/mist/api/http/guides/overview/mist-apis)

The concrete endpoint map, pagination, and rate-limit semantics are being vetted
directly against the live API reference before any client code lands — this
README will not restate a surface it has not verified.

## Status

**Scaffold.** Repository, license, and branding only. No crates, no binary, no
tool surface yet. Nothing here is usable against a real org.

Next, in order:

1. Pin the verified Mist API surface (region table, versioning, auth flow,
   pagination, rate limits, the resource groups worth exposing) into `docs/`.
2. Stand up the Cargo workspace against the `mecmcp` crates as they publish.
3. Read-only tools first — org/site inventory, device state, WLAN read, client
   and SLE queries — under bearer auth with per-token org and site scopes.
4. Mutating tools only behind `mecmcp-changeset`, never as direct writes.

## Design commitments

- **Curated, not generated.** Tools are chosen and documented by hand. A
  thousand auto-registered endpoints is a search problem handed to the model,
  not a capability.
- **Read before write.** Every mutating tool is reachable only through a
  plan → digest → approve → apply lifecycle. No tool writes to an org on a
  single unattested call.
- **Scoped tokens.** Bearer tokens carry explicit tool, org, and site scopes;
  an unscoped token is a configuration error, not a convenience.
- **Bounded I/O.** Request and response sizes are capped. A cloud control plane
  will happily hand back an estate-sized payload; the server will not.
- **Auditable by construction.** Attribution and redaction come from
  `mecmcp-audit`, so every call is traceable to a caller without leaking
  credentials into logs.
- **No secrets in the repo.** Mist API tokens and OAuth client secrets live in
  operator-managed files outside version control.

## License

Licensed under [MIT](LICENSE).
