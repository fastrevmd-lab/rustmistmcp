# Packaging acceptance record

This credential-free template is intentionally empty: no live tenant, Proxmox,
or VMID has been queried or changed by packaging work. Its boxes are ticked
by the human who runs the acceptance pass against real infrastructure, never
by an automated PR — a checklist item marked complete by anything other than
first-hand evidence is not evidence.

Read [`THREAT_MODEL.md`](THREAT_MODEL.md) and
[`TOKEN_ROLE_GUIDANCE.md`](TOKEN_ROLE_GUIDANCE.md) before running this
checklist. Packaging acceptance proves the artifact was built and deployed as
documented; it does not by itself prove the Mist API token behind it is
least-privilege — that is a separate operator decision the checklist below
cannot verify for you.

It is **not** a record of the chunk 7 lab run. That run reached a real Mist org
from LXC 952 and is recorded in issue #11; this checklist targets a separate
release deployment on VMID 613 and stays unfilled until that happens. Nothing
below may be ticked from 952's evidence — in particular 952 was loopback-only
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

## Token role check

- [ ] The outbound Mist API token behind this deployment is a **dedicated
  organization token**, not a personal/user token, per
  `docs/TOKEN_ROLE_GUIDANCE.md`.
- [ ] The token's Mist portal role is the narrowest role that covers the
  tools this deployment actually grants (read-only unless the WAN edge
  change-set lifecycle is in use) — recorded outside this repo, since the
  server cannot introspect the token's role.
- [ ] This deployment's Mist API token is not shared with any other
  deployment or environment (lab and production use separately revocable
  tokens).

## Image provenance (pending MEC-349)

Signed release images and CI pinned to exact digests are tracked as a
follow-on to `rustsdcmcp#182` / MEC-349 and are **not yet implemented** for
this repository. Until that lands, this section stays unchecked and the
existing digest-pinned-but-unsigned OCI image evidence above (candidate
binary hash, deployed hash, immutable OCI digest) is the available
provenance bar.

- [ ] cosign signature and SBOM/provenance attestation verified against the
  deployed image digest (blocked on MEC-349 landing in `mecmcp`/`rustsdcmcp`
  and being extended to this repository's release pipeline).

Do not fill this record until the upstream-reference refresh/regeneration has
been reviewed with zero parity gaps and the runtime/outbound blockers are closed.
