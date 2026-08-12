# rustmistmcp pre-release operations

This is operator guidance for credential-free pre-release artifacts. It is not
release acceptance. The outbound `HttpMistClient` has served live read-only
traffic from a lab LXC (issue #11), but that run was loopback-only with no TLS,
so the TLS, Host/Origin, and bad-bearer rows of `PACKAGING_ACCEPTANCE.md` are
still unproven. Mutation tooling is absent by design.

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
  packaging/examples/tokens.example.json /etc/rustmistmcp/tokens.json
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

### Known audit defect imported with `mecmcp` v0.8.7

**A scope-preflight denial is recorded as allowed.** `mecmcp#268`: the shared
transport settles its `tools/call` audit outcome with `succeed()` *before*
running the preflight, so a request denied for an out-of-scope `org_id` or
`site_id` answers 403 while its only audit record says `allowed`/`ok`. The
handler never runs, so nothing corrects it. A correlated second record would not
help either, because `mecmcp#269` gives the transport and handler events
different `request_id` values.

Both are upstream defects and must be fixed there, not worked around here —
generic transport and audit code does not belong in this repo.

Neither is present in the running lab deployment, which is why the issue #11
acceptance evidence is trustworthy: LXC 610 runs a build predating this bump,
and v0.7.3 emits no transport-level `tools/call` event at all. Its seven audit
records come from the handler, which settles the outcome after the decision —
the two failed reads on 2026-08-09 are recorded as `result=error`, correctly.

**`mecmcp#268` must be fixed and consumed before LXC 610 is upgraded to a
v0.8.7 build.** Once it is, a denied call starts logging as an allowed one, and
the audit trail stops being able to answer the question it exists to answer:
whether a token ever reached an org it was not scoped for. Snapshot 610 before
any upgrade, per the family's rollback rule.

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
