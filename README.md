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
| **Mist REST client, API-token auth, response models, tool surface** | **this repo** |

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

The Mist vendor API supports API tokens and external OAuth 2.0. API tokens are
sent as `Authorization: Token <token>`, may be minted per user or organization,
and inherit the privileges of the account that created them. rustmistmcp v1 intentionally implements API-token authentication only; it does not accept OAuth
credentials. HTTP Basic authentication with Juniper Mist login credentials is
**deprecated as of September 2026** and will not be implemented here.

Primary references:

- [RESTful API Overview](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/restful-api-overview.html)
- [Create API Tokens](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/task/create-token-for-rest-api.html)
- [Mist API Reference](https://www.juniper.net/documentation/us/en/software/mist/api/http/guides/overview/mist-apis)

The concrete endpoint map, pagination, and rate-limit semantics are being vetted
directly against the live API reference before any client code lands — this
README will not restate a surface it has not verified.

## Status

**Foundation in progress; no live Mist client.** The workspace has an audited
operation catalog, strict profile metadata, authorization models, and a
catalog-bound injectable `MistClient` contract. The contract validates Mist
operation inputs and binds opaque cursors to a configured origin, but it has no
concrete HTTP implementation.

`mecmcp#90` remains the prerequisite for production outbound behavior. Until
that shared foundation lands, this repository does not load tokens, construct
HTTPS requests or URLs, expand paths, encode JSON or multipart payloads, stream
or decode responses, parse rate-limit or pagination data, apply retry policy,
or expose a live tool surface. `MistResponse` and `RateLimited` are DTOs that an
injected test or future shared client can supply; they are not evidence of local
transport support.

The accepted `mecmcp#90` plan now gives this consumer a concrete adoption
sequence. Rustmistmcp will consume each upstream phase only after it is
published in one coherent immutable revision:

| `mecmcp#90` phase | Rustmistmcp adoption |
|---|---|
| 1: `mecmcp-secret` | Load the Mist API token through the shared secret boundary. |
| 2a: bounded pooled HTTPS client | Construct the live Mist client with HTTPS-only, no-redirect, concurrency, and deadline policy. |
| 2b: streamed response limits | Enforce response byte ceilings before decoding Mist payloads. |
| 3: cancellable job polling | Implement Mist asynchronous job polling with product-owned terminal states and retry semantics. |
| 4: bounded OpenAPI path/query helpers | Expand whole path segments and validate bounded Mist pagination. |
| 5: extended `mecmcp-changeset` | Implement multi-target preview-bound Mist mutations; this phase remains last. |

Existing `TokenSecret`, cancellation, and changeset primitives will be reused,
not rebuilt. Mist header names, catalog policy, request/response schemas,
terminal states, retry classification, and deployment remain in this
repository.

## Pre-release packaging and deployment boundary

The checked-in Docker, archive, systemd, and LXC assets are **pre-release
packaging only**. They are not evidence of a production-ready Mist client or of
live readiness: `mecmcp#90` blocks the outbound client and Task 6 mutations.
No v1 release label or deployment acceptance may be claimed while that blocker
is open.

The OCI image is a multi-stage build with a digest-pinned Rust builder and a
digest-pinned distroless Debian 13 runtime. It runs only
`/usr/local/bin/rustmistmcp` as UID/GID `65532`; the runtime image has no shell,
package manager, or runtime fetcher. Its CA data comes from the distroless base.
Use an immutable image digest, never a mutable tag. The supplied compose example
is read-only, drops every capability, uses no-new-privileges, bounds PIDs and
`/tmp`, mounts `/etc/rustmistmcp` read-only, and mounts
`/var/lib/rustmistmcp` read-write. Do not place Mist or bearer secrets in image
layers, compose environment, or command arguments.

The checked-in service and OCI command use the shared CLI's exact loopback HTTP
contract: `/etc/rustmistmcp/mist.json`, the bearer store, port `30030`, JSON
audit with HMAC redaction, and direct journald delivery for systemd. OCI audit
goes to JSON stderr and does not mount the host journal socket. There is no
mutation-state flag or live-Mist readiness check. The shared CLI has no
`--version`; `mecmcp#159` tracks that gap, so release identity is verified with
`--help`, `BUILD-INFO`, and artifact/deployed SHA-256 values.

The compose example is Linux-only: host networking makes the container's
`127.0.0.1:30030` listener reachable from the same host without exposing it on
an external interface. Before starting it, make the bind-mounted state and
secret files accessible to numeric UID/GID `65532`:

```sh
install -d -m 0750 packaging/container/runtime
install -d -m 0700 packaging/container/state
cp examples/mist.example.json packaging/container/runtime/mist.json
printf '%s\n' '{"version":1,"tokens":[]}' > packaging/container/runtime/tokens.json
install -m 0600 /dev/null packaging/container/runtime/mist-api-token
install -m 0600 /dev/null packaging/container/runtime/audit-hmac.key
sudo chown root:65532 packaging/container/runtime/mist.json
sudo chmod 0640 packaging/container/runtime/mist.json
sudo chown 65532:65532 packaging/container/runtime/mist-api-token \
  packaging/container/runtime/tokens.json \
  packaging/container/runtime/audit-hmac.key
sudo chown -R 65532:65532 packaging/container/state
chmod 0600 packaging/container/runtime/mist-api-token \
  packaging/container/runtime/tokens.json \
  packaging/container/runtime/audit-hmac.key
RUSTMISTMCP_IMAGE='ghcr.io/fastrevmd-lab/rustmistmcp@sha256:<verified-64-hex-digest>' \
  docker compose -f packaging/container/compose.example.yaml up
```

Populate the two empty secret files without placing their values in an
environment variable, command argument, image layer, or Compose file.
Grant-bearing MCP bearer-token add/list/revoke/rotate remains unavailable:
`mecmcp#160` has merged the required API, but the published revision containing
it does not also contain the shared server crate required by this process. An
empty token store can start the pre-release listener but cannot authenticate an
operator. This bearer-token store is separate from the Mist API token used by
the outbound client.

### LXC operator prerequisites

Deploy only in a dedicated **Debian 13 unprivileged LXC with `nesting=1`**.
`nesting=1` is required for the target systemd version to report healthy mounts.
The guest cannot prove the host-side unprivileged and nesting settings. Verify
them in authorized host inventory, then explicitly attest them to the installer
with `RUSTMISTMCP_LXC_HOST_PROOF=unprivileged=1,nesting=1`; it also refuses
non-Debian-13 and non-LXC hosts.
Do not contact Proxmox or a Mist tenant as part of package construction. The lab
acceptance gate, if separately authorized, must first prove that VMID 613 and
its address are unused and must target only a newly provisioned 613 LXC; never
operate VMID 612 or snapshot an unrelated guest.

The archive installer validates its checksum and full archive layout before any
mutation, refuses to clobber live configuration, secrets, state, or a customized
unit (unless `RUSTMISTMCP_FORCE_UNIT=1` is set), and does not enable the service.
Use `install.sh --validate-only ARCHIVE ARCHIVE.sha256` without root for a
non-mutating preflight.
It installs non-live examples as `/etc/rustmistmcp/mist.example.json` and
`/etc/rustmistmcp/tokens.example.json`. Configure live files manually:

| Path | Required ownership/mode | Purpose |
|---|---|---|
| `/usr/local/bin/rustmistmcp` | `root:root`, `0755` | Release binary |
| `/etc/rustmistmcp/mist.json` | `root:rustmistmcp`, `0640` | Service-readable Mist profile |
| `/etc/rustmistmcp/mist-api-token` | `rustmistmcp:rustmistmcp`, `0600` | v1 outbound Mist API credential |
| `/etc/rustmistmcp/tokens.json` | `rustmistmcp:rustmistmcp`, `0600` | Bearer-token store |
| `/etc/rustmistmcp/audit-hmac.key` | `rustmistmcp:rustmistmcp`, `0600` | Audit HMAC key |
| `/var/lib/rustmistmcp/changeset-state.json` | service-user state, `0700` parent | Durable state path |

Persistent journald is bounded to 512 MiB. Configure remote journal/SIEM
forwarding before real traffic. While `mecmcp#158` remains open, file-audit
startup is not claimed fail-closed; journald is the delivery baseline. While
`mecmcp#156` remains open, graceful HTTP draining/SIGTERM completion is not
claimed. Any external bind requires TLS plus exact allowed Host and Origin
configuration; the default deployment posture is loopback only.

For each release candidate, build from a clean tree with
`scripts/build-release.sh`; it writes a deterministic
`rustmistmcp-v<VERSION>-<TARGET_TRIPLE>.tar.gz`, sidecar SHA-256, and
`BUILD-INFO`. Measure the produced binary's glibc floor before deployment:

```sh
objdump -T bin/rustmistmcp | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -Vu | tail -1
```

Release CI produces checksums, an SBOM, provenance, multi-architecture OCI
images, and an immutable digest record. Refresh the upstream reference/spec once
at RC, regenerate the catalog, review the delta, and require zero parity gaps
before any separate deployment acceptance.

Next, in order:

1. Consume `mecmcp#90` phases 1 through 4 and implement the production outbound
   Mist client plus `/self` identity probe.
2. Adopt merged `mecmcp#160` once it is published in the same coherent revision
   as the complete shared server foundation; resolve `mecmcp#159` for a shared
   version surface.
3. Complete read-only live-tenant acceptance only after the RC reference refresh
   and zero-gap parity review.
4. Consume `mecmcp#90` phase 5 and add mutations only behind
   `mecmcp-changeset`, never as direct writes.

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
- **No secrets in the repo.** Mist API tokens live in operator-managed files
  outside version control. v1 does not accept OAuth client secrets.

## License

Licensed under [MIT](LICENSE).
