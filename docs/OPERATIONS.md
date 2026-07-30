# rustmistmcp pre-release operations

This is operator guidance for credential-free pre-release artifacts. It is not
release acceptance and does not establish that the blocked outbound Mist client
works. `mecmcp#90` must close before live-Mist operations; mutation tooling is
also absent while that blocker remains open.

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
mandatory. No
graceful HTTP drain/SIGTERM-completion claim is permitted while `mecmcp#156` is
open, and file-audit startup is not fail-closed while `mecmcp#158` is open.
Grant-bearing MCP bearer-token lifecycle remains unavailable. `mecmcp#160` has
merged the required API, but no published coherent revision yet contains it
together with the shared server crate consumed here. This operator-authentication
store is separate from the outbound Mist API token.

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
hash verbatim with the archive candidate hash. Because `mecmcp#159` tracks the
missing shared `--version`, use `rustmistmcp --help`, `BUILD-INFO`, and exact
candidate/deployed hashes for identity evidence.

Measure the binary's glibc requirement rather than assuming it:

```sh
objdump -T /usr/local/bin/rustmistmcp | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -Vu | tail -1
```
