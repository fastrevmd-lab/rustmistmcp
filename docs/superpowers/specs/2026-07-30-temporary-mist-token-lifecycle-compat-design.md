# Temporary Mist Token Lifecycle Compatibility Design

## Status

Approved in conversation on 2026-07-30 as a narrow exception to the v1
ownership boundary. This exception applies only to grant-aware bearer-token
command dispatch. It does not authorize a local replacement for
`mecmcp-server`, `mecmcp-http`, or any other shared foundation.

## Problem

Rustmistmcp consumes one immutable `mecmcp` revision,
`75a1e9db10a21a85876f337313ba47bc0329d74d`, because that revision contains the
shared `mecmcp-server` APIs used throughout the MCP handler. Its shared token
command is fixed to `TokenStoreFile<NoGrant>`, so it cannot list, rotate,
revoke, or add alongside a token carrying `MistGrant`.

`mecmcp#160` fixed this through
`mecmcp_runtime::token_cmd::run_with_grant`, but the fix is available only on
the divergent `mecmcp` main history. Main does not contain the
`mecmcp-server` crate. Splitting the process across those revisions would
duplicate shared crate identities and violate the workspace's single-revision
invariant.

## Goal

Provide a private, Mist-typed compatibility adapter that makes the existing
shared token CLI safe for a `TokenStoreFile<MistGrant>` while keeping every
storage and validation primitive in `mecmcp`.

The adapter must be small enough to delete in one change when a coherent
upstream revision contains both `mecmcp-server` and `run_with_grant`.

## Non-Goals

The compatibility work will not:

- implement or vendor `mecmcp-server`;
- implement any `mecmcp#90` phase locally;
- add a generic grant abstraction or export a reusable token API;
- add Mist grant-authoring CLI flags;
- add mutation tools or a local change-set envelope;
- contact a Mist tenant, Proxmox, VMID 612, or any deployment target;
- modify `mecmcp` or any other repository.

New tokens created through the existing shared CLI remain grantless. That is
the fail-closed behavior supplied by upstream `run_with_grant` when its
`new_grant` argument is `None`.

## Architecture

Add one private module to the `rustmistmcp` binary crate:

`crates/rustmistmcp/src/mist_token_cmd.rs`

Its only public-to-the-crate entry point accepts the existing
`mecmcp_runtime::cli::TokenAction` and dispatches it against
`TokenStoreFile<MistGrant>`. The type is fixed; the module must not be generic
over a grant type.

The adapter reuses:

- `TokenStoreFile<MistGrant>` for secure loading, validation, minting, rotation,
  revocation, grant preservation, and atomic writes;
- `KnownNames` and `ScopeSet` for shared scope validation;
- `mecmcp_runtime::token_cmd::parse_provenance` for the shared provenance
  contract;
- the shared `TokenAction` command shape and error type.

Only the glue that the pinned `run` function keeps private is local:

- converting the already parsed device and tool values into `ScopeSet`;
- rendering the existing token list format;
- dispatching add, list, rotate, and revoke using the Mist grant type;
- sending the optional SIGHUP reload signal with the existing semantics.

`main.rs` continues to validate that `--tokens-file` is absolute before calling
the adapter. Token commands remain local and must not load the Mist profile,
read the Mist API token, or make a network request.

## Command Behavior

### Add

`token add` parses scopes and provenance using the shared rules, then calls
`TokenStoreFile::<MistGrant>::add_with_options` with `grant: None`. Existing
grant-bearing entries must survive the whole-file rewrite unchanged. The
one-time plaintext token is printed only to stdout.

### List

`token list` loads the file as `MistGrant` and preserves the shared table
format. Grant contents are never printed.

### Rotate

`token rotate` rotates only the selected token secret and preserves its grant,
scopes, creation time, expiry, and provenance. The replacement plaintext is
printed only to stdout.

### Revoke

`token revoke` removes only the selected token and preserves every surviving
entry, including its grant. Revoking an absent token remains a successful
no-op with the existing diagnostic.

### Reload

After a successful mutating command, an optional positive PID receives SIGHUP
on Unix. Invalid PIDs fail. Supplying a PID on a platform without SIGHUP fails
as unsupported. A failed signal does not roll back the already completed token
file mutation, matching the pinned shared command behavior.

## Safety and Error Handling

The adapter returns `mecmcp_runtime::token_cmd::TokenCommandError` so storage,
scope, argument, and I/O errors retain the established operator-facing
contract.

`MistGrant` already uses `#[serde(deny_unknown_fields)]`. A token document
containing an unknown grant field therefore fails during load before any
mutation or rewrite. Tests must prove the original bytes remain unchanged.

The adapter must not log or format token plaintext, token digests, Mist API
credentials, or grant details. It prints plaintext only in the same add/rotate
stdout paths as the shared command.

## Compatibility Ledger

Add `docs/UPSTREAM_COMPATIBILITY.md` with one row containing:

- upstream issue `mecmcp#160` and merged PR `mecmcp#170`;
- local module `crates/rustmistmcp/src/mist_token_cmd.rs`;
- reason the merged API cannot yet be consumed from the coherent pin;
- the exact removal condition;
- the tests that must remain after migration.

The row's removal condition is:

> One immutable `mecmcp` revision contains the required `mecmcp-server` surface
> and `mecmcp_runtime::token_cmd::run_with_grant`.

At that point, replace the private adapter call with
`run_with_grant::<MistGrant>(..., None)`, delete the module and ledger row, and
retain the binary lifecycle tests against the upstream implementation.

## Tests

Tests are introduced before implementation and cover:

1. A grant-bearing store can be listed through the rustmistmcp binary.
2. Rotation changes the secret digest while preserving the exact `MistGrant`.
3. Revocation removes only the named token and preserves another token's grant.
4. Adding a grantless token to a grant-bearing store preserves the existing
   grant and gives the new entry no grant.
5. An unknown Mist grant field fails closed and leaves the file byte-identical.
6. Token commands do not load the Mist profile or contact Mist.
7. Relative token-store paths remain refused.
8. Invalid reload PIDs retain the shared error behavior.
9. The compatibility ledger names the module, upstream issue, merged PR, and
   deletion condition.

The full workspace, strict Clippy, formatting, packaging, and release-policy
gates must remain green.

## Release Impact

This compatibility adapter removes only the local grant-bearing token
lifecycle blocker. It does not make rustmistmcp release-ready.

The live Mist client remains blocked on the unimplemented phases of
`mecmcp#90`. Mutations remain blocked on phase 5. Graceful HTTP shutdown,
fail-closed file-audit initialization, shared version reporting, live-tenant
acceptance, and LXC deployment acceptance retain their existing gates.
