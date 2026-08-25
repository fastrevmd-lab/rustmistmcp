# rustmistmcp pre-release operations

This is operator guidance for credential-free pre-release artifacts. It is not
release acceptance. The outbound `HttpMistClient` has served live read-only
traffic from a lab LXC (issue #11), but that run was loopback-only with no TLS,
so the TLS, Host/Origin, and bad-bearer rows of `PACKAGING_ACCEPTANCE.md` are
still unproven. Batch-1 WAN edge mutations exist behind the change-set lifecycle,
but no live-tenant apply has been performed.

## Install boundary

Use a clean-tree archive and verify it without root:

```sh
packaging/lxc/install.sh --validate-only ARCHIVE.tar.gz ARCHIVE.tar.gz.sha256
```

The validator binds one exact 64-hex sidecar record to the requested basename,
accepts only one exact allowlisted release root and regular files/directories,
then extracts into a temporary directory and verifies canonical object types.
Inside the dedicated Debian 13 LXC, separately verify the host configuration is
unprivileged with `nesting=1`; the guest cannot prove those host-side settings.
After that authorized check, run:

```sh
sudo RUSTMISTMCP_LXC_HOST_PROOF='unprivileged=1,nesting=1' \
  packaging/lxc/install.sh ARCHIVE.tar.gz ARCHIVE.tar.gz.sha256
```

The installer refuses other Debian releases and non-LXC guests, retains live
configuration, secrets, state, journald customization, and customized units,
and deliberately does not enable the service.

Before enabling a finalized service command, create only regular, non-symlink
live files. On a new systemd/LXC deployment, use these exact ownership and mode
commands:

```sh
sudo install -D -o root -g rustmistmcp -m 0640 \
  packaging/examples/mist.example.json /etc/rustmistmcp/mist.json
sudo install -o rustmistmcp -g rustmistmcp -m 0600 /dev/null \
  /etc/rustmistmcp/mist-api-token
sudo install -o rustmistmcp -g rustmistmcp -m 0600 \
  packaging/examples/tokens.example.json /var/lib/rustmistmcp/tokens.json
sudo install -o rustmistmcp -g rustmistmcp -m 0600 /dev/null \
  /etc/rustmistmcp/audit-hmac.key
```

Populate `mist-api-token` and `audit-hmac.key` through protected stdin or an
authorized secret manager, never through an environment variable, command
argument, repository file, or shell history. The installer rejects existing
directories, devices, FIFOs, symlinks, and dangling symlinks at any of the
three live-secret paths before host mutation, then rechecks before changing
their ownership or mode. State belongs below `/var/lib/rustmistmcp`.

The installed unit uses the checked-in shared flags for Mist configuration,
token store, audit journald/HMAC, loopback bind, and port 30030. No mutation
state flag exists. For an external bind, TLS and exact Host/Origin values are
mandatory. Graceful HTTP shutdown (`mecmcp#156`) is wired: SIGTERM and SIGINT
cancel the listener, which then waits up to 10 seconds for in-flight requests.
That is the configured behaviour, not an acceptance-verified drain. File-audit
startup is fail-closed (`mecmcp#158`): an unopenable `--audit-log-file` fails
startup with `initializing audit tracing` rather than degrading to no audit.
Grant-bearing MCP bearer-token lifecycle is the shared
`token_cmd::run_with_grant`; the Mist-typed adapter it used to need is deleted.
`token add` creates a grantless token; list, rotate, revoke, and subsequent adds
preserve existing validated Mist grants. The operator-authentication store is
separate from the outbound Mist API token.

### Transport-level audit

Every `tools/call` produces a transport audit event in addition to the
handler's enriched one, and its outcome is settled from the scope-preflight
result: `authorization=denied` with reason `insufficient_scope` when the
preflight refuses, `allowed`/`ok` when it passes.

That was not always true. `mecmcp#268` settled the outcome *before* running the
preflight, so a request answered with 403 carried a single audit record saying
`allowed`/`ok`, and the handler never ran to correct it. Fixed in `mecmcp#270`
and first released in **v0.8.8**, which this repo pins. No build carrying the
defect should be deployed.

`mecmcp#269` remains open: the transport and handler events mint different
`request_id`s, so the two halves of one request cannot be correlated. That
degrades analysis; it does not make any single record false.

### The lab token deliberately runs on one authorization layer

The `acceptance` token on LXC 952 pairs a wildcard shared scope with an
org-scoped Mist grant:

```json
"devices": ["*"],
"grant": { "subjects": ["org/<org-uuid>"] }
```

`MistScopePreflight` checks wire `org_id`/`site_id` arguments against
**`devices`**, not against the grant, and `ScopeSet::Wildcard` allows every
name. So for this token the early transport check is inert and the handler's
grant check is the only thing enforcing org reach. The handler is documented as
the final boundary and does enforce `subjects` — a call to an unscoped org is
still refused — but the two-layer design is running on one layer.

**This is a deliberate lab choice, not an oversight.** The Mist org behind 952
exists to exercise this server; a wildcard `devices` scope keeps new read tools
testable without reminting a token for each one. Recorded here so nobody
mistakes an intentionally-open scope for a tightened one that regressed.

One condition attaches to it: **do not carry this shape to a token with
production reach.** Set `devices` to the same subjects the grant names, so both
layers agree.

The second condition is now satisfied. Tightening `devices` makes preflight
denials reachable for the first time, and those had to audit honestly first —
on v0.8.7 they logged as allowed (`mecmcp#268`). This repo pins v0.8.8, which
records them as denied, so the scope can be tightened whenever the lab no longer
needs it open.

Tracked in issue #17.

### Guest lifecycle

The deployment is **LXC 952 on pve2**, tagged `protected`. Do not stop,
destroy, restore over, or upgrade it without an explicit decision and a
snapshot first — check the tag, not this document, before any guest operation.

It was briefly VMID 610 tagged `disposable`; both changed in the 2026-08-12
renumber and 610 no longer exists in the cluster. The hostname is still
`rustmistmcp-610`, so hostname and VMID disagree — trust the VMID.

Nothing irreplaceable lives on the guest: the configuration, deployed binary
hash, token grant shape, and all seven audit records are captured in issue #11.
What does live there is a **live Mist API token** at
`/etc/rustmistmcp/mist-api-token`. If the guest is ever rebuilt or retired,
**revoke or rotate that token at the Mist portal** rather than assuming the
credential dies with the filesystem — deleting an LVM volume does not tell Mist
the token is gone, and an org-scoped API token nobody holds is still an
org-scoped API token that exists.

The same applies to the `acceptance` MCP bearer token in
`/var/lib/rustmistmcp/tokens.json`, though that one is only reachable through this
server's loopback listener, so destroying the guest genuinely does end it.

## Repository security workflow prerequisite

The organization-owned repository requires an encrypted `GITLEAKS_LICENSE`
secret for `gitleaks/gitleaks-action` v3. Configure it at repository or
organization scope before requiring the security workflow. GitHub supplies
`GITHUB_TOKEN`; the workflow passes both values explicitly to the pinned action.

## Logs and upgrades

The installed journald drop-in keeps persistent logs bounded to 512 MiB. Configure
remote journal/SIEM forwarding before carrying real traffic; do not set
`Seal=yes` in an unprivileged LXC. For an upgrade, validate the new archive,
compare its SHA-256 with the release record, retain the existing binary under an
explicit versioned rollback name, install the candidate, and restart. Roll back
immediately if the active and listener checks fail. Compare the deployed binary
hash verbatim with the archive candidate hash. `rustmistmcp --version` reports
the binary name and version (`mecmcp#159` closed), but a version string is not
provenance: keep `--help`, `BUILD-INFO`, and exact candidate/deployed hashes as
the identity evidence.

Measure the binary's glibc requirement rather than assuming it:

```sh
objdump -T /usr/local/bin/rustmistmcp | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -Vu | tail -1
```

## WAN edge configuration tools

The `get_mist_wan_config` tool reads one configuration object by ID: networks,
services, service policies, gateway templates, or device profiles. Its
object→operation mapping (`getOrgNetwork`, `getOrgService`, `getOrgServicePolicy`,
`getOrgGatewayTemplate`, `getOrgDeviceProfile`) is the same mapping the
change-set lifecycle will use when fetching the `before` state its digest binds
to. This matching is intentional: the read operation a tool uses to retrieve one
object must be the exact catalog read that corresponds to the write on that same
object type, so `get_mist_wan_config`'s resolution is the authoritative map for
both read and write flows.

## Change-set write lifecycle

Batch-1 WAN edge mutations — create and update for networks, services, service
policies, gateway templates, and device profiles — are reachable only through a
plan → digest → approve → apply → verify lifecycle. Delete operations and
`mist_configured` device-profile assignment/unassignment remain out of reach.

The four change-set tools (`plan_mist_change`, `get_mist_change_set`,
`approve_mist_change_set`, `apply_mist_change_set`) all live in `RESTRICTED_TOOLS`,
so a wildcard-tools token scope cannot reach them. Explicit tool grants are
required.

### Two-principal approval

Approval requires a second principal: the approver's token name must differ from
the change set's owner. The refusal compares token names, which `mecmcp-auth`
guarantees are unique within a store. What no code can enforce is that two
differently-named tokens are not held by the same human. This control assumes
tokens are issued to distinct people; if that assumption is violated, the
two-person property breaks.

### Merge-patch semantics

The patch body is merged onto the configuration object's current state using
JSON Merge Patch (RFC 7386) semantics with one critical detail: **arrays replace
wholesale**. There is no element-wise edit — setting `"vlans": [10, 20]` replaces
the entire array, it does not append or merge. Additionally, **`null` deletes a
field** rather than setting it to the literal null value.

### Refused fields

`plan_mist_change` refuses any patch containing the `mist_configured` field and
will not stage the change set. This refusal is immutable: an operator cannot
approve it past.

### State file and upgrades

Change-set state persists at `/var/lib/rustmistmcp/changeset-state.json`, which
packaging reserves and the OCI runtime mounts read-write. **Preserve this file
across upgrades.** Losing it strands every planned and approved change set.

Versions prior to the org-scope fix lack `org_id` in stored previews and will
refuse at apply with "preview missing org_id". When upgrading across this change,
re-plan any change set that was staged but not yet applied.

## Egress filtering

The packaged unit declares `IPAddressDeny` to block egress to cloud metadata
and link-local ranges. However, **systemd cannot enforce these directives in an
unprivileged LXC** — every guest in this fleet is one. systemd implements them
with cgroup BPF and fails open when it cannot load the program, so the unit can
declare a full egress policy while enforcing none of it. `systemd-analyze
security` reads the declaration and cannot tell the difference.

The installer probes actual enforcement and prints one of four verdicts:

- `egress filter: ENFORCED` — the host attaches the BPF program *and* the
  installed unit declares a policy
- `egress filter: NOT ENFORCED` — the host cannot attach it; guidance follows
- `egress filter: NO POLICY` — the host could enforce, but the installed unit
  declares no `IPAddressDeny` (a preserved customized unit overrides the
  packaged one; re-install with `RUSTMISTMCP_FORCE_UNIT=1` to restore it)
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

Both conditions matter. A host-capability check alone would report success over
a service filtering nothing.

The probe uses IP accounting, which rides the same BPF attachment, so a
populated counter proves the filter attached. Check it any time:

```console
systemctl show rustmistmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`RUSTMISTMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse anything
short of `ENFORCED` — including `UNKNOWN`, since an unmeasurable host is
exactly as unguaranteed as a non-enforcing one.

### Enforcing it where systemd cannot

Any result other than `ENFORCED` means the unit directives are **unproven**, and
the control should move outward — to whatever layer actually sees this
workload's packets. `NOT ENFORCED` and `NO POLICY` mean they are demonstrably
doing nothing; `UNKNOWN` means nothing was measured and they may well be
working. Do not treat the last as the first.

The policy does not change with the runtime:

1. deny `169.254.0.0/16` and `fd00:ec2::254` — cloud metadata, the route from a
   compromised HTTP client to a stolen credential
2. deny link-local (`fe80::/10`) — not used by any supported target
3. deny the local subnet **except** your DNS resolver — blocks lateral movement
   while keeping name resolution working (not currently declared in this
   server's unit; add via drop-in if needed)

The mechanism does. Configure it with your platform's own documentation rather
than a recipe here — these are the layers, not instructions:

| Runtime | Layer that sees this workload's packets |
|---|---|
| Proxmox LXC / VM | per-guest interface firewall |
| libvirt / KVM | `nwfilter` on the guest interface |
| Kubernetes | `NetworkPolicy` egress, on a CNI that implements it |
| Cloud instance | in-guest packet filter for **both** metadata addresses, plus security groups for everything else |
| Bare metal, VM with working systemd | the unit directives; this section does not apply |

Two properties are worth checking whatever you choose, because both are common
and both produce a control that reads as present and is not:

- **Some layers accept egress policy without enforcing it.** Container network
  attachment and some CNI implementations are the usual cases.
- **Cloud metadata often bypasses the cloud firewall.** On EC2, IMDS traffic is
  handled below the security group and NACL layer, so an egress rule there does
  not block it. This applies to the IPv6 endpoint too — `fd00:ec2::254` is ULA
  rather than link-local, so it is easy to file mentally under "ordinary routed
  traffic the firewall sees", and it is not. The control has to be in-guest, or
  IMDS disabled outright. Consult your provider's current metadata-hardening
  guidance; it changes, and getting it wrong is silent.

Whichever you pick, a rule that has not been exercised from inside the workload
is an assumption. Verify it, and re-verify after a reboot — in-kernel firewall
rules are not persistent unless you made them so.
