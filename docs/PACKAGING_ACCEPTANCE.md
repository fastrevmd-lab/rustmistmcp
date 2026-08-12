# Packaging acceptance record

This credential-free template is intentionally empty: no live tenant, Proxmox,
or VMID has been queried or changed by packaging work.

It is **not** a record of the chunk 7 lab run. That run reached a real Mist org
from LXC 610 and is recorded in issue #11; this checklist targets a separate
release deployment on VMID 613 and stays unfilled until that happens. Nothing
below may be ticked from 610's evidence — in particular 610 was loopback-only
with no TLS, so the TLS, Host/Origin, and bad-bearer rows were never exercised
by it.

## Authorization and target checks

- [ ] Authorized lab inventory confirms VMID **613** and its address are unused.
- [ ] A new unprivileged Debian 13 LXC, and only that LXC, is provisioned with
  `nesting=1`; VMID 612 and unrelated guests are untouched.
- [ ] Release-specific snapshot name, node, and pre-deploy binary SHA recorded.

## Artifact and host evidence

- [ ] GitHub archive checksum, candidate binary hash, deployed hash, and
  immutable OCI digest match the recorded release values.
- [ ] Supported `--version`, `--help`, `BUILD-INFO`, candidate/deployed hashes,
  active/enabled service, running system state, expected lone listener,
  ownership/mode checks (`mist.json` `root:rustmistmcp` `0640`; Mist API token,
  MCP bearer-token store, and audit HMAC key `rustmistmcp:rustmistmcp` `0600`),
  persistent journal, and forwarding state are recorded without credentials.
  `--version` reports the binary name and version now that `mecmcp#159` has
  closed; it does not replace the hash evidence.
- [ ] No secret appears in unit properties, environment, process arguments, or
  acceptance evidence.

## Authorization and read-only smoke

- [ ] TLS hostname and chain, anonymous/bad-bearer rejection, least-privilege
  bearer authentication, exact Host/Origin enforcement, and a read-only Mist MCP
  operation scoped to the approved test org/site are independently recorded.
- [ ] No mutating Mist tool is used for packaging acceptance; change-set state
  stays inactive and its history/hash is preserved.

Grant-bearing MCP bearer-token lifecycle acceptance must exercise the four
lifecycle tests listed in `docs/UPSTREAM_COMPATIBILITY.md`, which now run
against the shared `token_cmd::run_with_grant` rather than a local adapter.
The lifecycle does not author new Mist grants and is separate from the outbound
Mist API-token credential.

Do not fill this record until the upstream-reference refresh/regeneration has
been reviewed with zero parity gaps and the runtime/outbound blockers are closed.
