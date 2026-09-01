# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.2.0. Earlier tags (0.1.0, 0.1.1) predate it and are
recoverable from `git log` and the release tags — noted so the omission is
visible rather than looking like those versions never existed.

## [Unreleased]

## [0.3.0] - 2026-09-01

### Added

- **An approval now binds the preview it was shown.** mecmcp 0.23.0 adds a v5
  approval digest that carries the stored preview's digest, and this server does
  store a preview, so approvals are signed with v5 rather than v4. An approver
  now vouches for the exact preview they saw, not merely for the plan, and the
  coordinator refuses any later write that swaps or drops that preview.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.21.0` to `v0.23.0`, spanning two
  minors, and updated the pinned upstream revision in the workspace contract
  test from `dbae2e38` to `d61867d7`.
- The apply takes `claim_change_set_for_apply` instead of writing
  `Approved -> Applying` itself. 0.22.0 made the claim the only legal route onto
  that edge -- it does the read and the write under one lock, so two applies
  cannot both read `Approved` and both issue the write -- and the plain
  `update_change_set` this used is now refused outright. `ApplyHandle::None`,
  because a Mist write is synchronous and returns no pollable handle: a crash
  mid-apply leaves an outcome only the service knows, which is what
  `apply_without_handle` records honestly.
- The drift-detection path claims before settling. It wrote `Approved -> Failed`
  directly, which 0.22.0's transition policy refuses; the refusal was swallowed
  into an audit line, so a drifted change set stayed `Approved` and its stale
  approval remained spendable. It now claims first -- nothing has been sent to
  Mist at that point -- which gives the settle a legal `Applying -> Failed` and
  spends the approval, so a drifted plan cannot be retried. That claim uses
  `ApplyHandle::Expected`, the opposite of the apply path, and for the opposite
  reason: the marker decides how a crash is read back, and on this branch
  nothing was sent, so recovering to `Failed` states the truth. Handleless would
  strand a record known not to have run.
- `ChangeSetRecord` literals carry the new `apply_without_handle` field.
- `jsonschema` bumped from 0.50.1 to 0.51.0.
- `toml` bumped from 0.8.23 to 1.1.4+spec-1.1.0, and the workspace-contract
  test now uses `toml::from_str` instead of `str::parse`, as toml 1.x changed
  the `FromStr` implementation on `Value` to stop after the first table header.

### Performance

- **Compiled JSON Schema validators are now cached** (#59). Request and response
  validation previously compiled the schema on every call — roughly 2.2 MB cloned
  from the components registry, then compiled, then dropped. Measured against the
  pinned catalog (1059 operations, 4.6 MB source):

  | stage | before | after |
  |---|---|---|
  | per call, uncached | 63.25 ms | 1.14 us |
  | first call | ~100 ms | ~100 ms |

  **Per-call validation drops from 63 ms to 1 us**, a ~55,000x speedup for cached
  validators. The catalog is immutable once parsed, so compiled validators are
  memoised. Cache misses race harmlessly: concurrent compilations of the same
  schema may occur, with the first insert winning. Compile failures are not cached,
  keeping catalog defects visible rather than frozen.

  The cache key includes operation name, parameter location and name, and for
  responses both status code and media type, ensuring distinct schemas never
  share a cache entry. This addresses the known issue (#59) noted in v0.2.0.

### Security

- **Moved off the yanked chacha20 0.10.1.** The supply-chain gate went red when
  chacha20 0.10.1 was yanked upstream. This is a transitive dependency through
  `rand -> rmcp -> mecmcp-server`, so nothing here selects it directly. The
  lockfile now pins the compatible 0.10.2 release.

### Upgrading

- **A binary-only rollback to a build pinned at mecmcp v0.21.0 will refuse to
  start once any change set has been approved under this one.** A v5 approval
  forces the change-set state file to schema 6, which the v0.21.0 reader does
  not accept -- correctly, since it cannot verify what it cannot parse. Roll the
  state file back with the binary, or restore a pre-upgrade snapshot.

## [0.2.0] - 2026-08-25

### Added

- **SSDF evidence pipeline** (mecmcp#292). Evidence is attributed to the
  applying request rather than to the change set, and receipts name the
  executor. An ambiguous write is reported as ambiguous, not as a failed
  write.

### Changed

- **The embedded catalog is parsed once instead of twice** (#39). It was
  parsed into a `serde_json::Value` to recompute fingerprints and again into
  the typed document. A 4.6 MB document costs roughly ten times its size as a
  `Value` tree, and glibc does not return that arena when the transient parse
  is dropped, so the cost was permanent resident memory:

  | stage | before | after |
  |---|---|---|
  | after `Catalog::embedded()` | 90.3 MB | 45.3 MB |
  | after `relaxed_components()` | 90.3 MB | 63.4 MB |

  **Resident drops 90.3 MB -> 63.4 MB, a 30% cut.**

  **Fingerprint verification moves from startup to the test gate.** Be precise
  about this: 0.1.1 recomputed every operation's `source_fingerprint` on each
  process start, and 0.2.0 does not — `Catalog::embedded` now uses
  `Fingerprints::Trust`. The check still runs, but under `cargo test` / CI, via
  `catalog_fingerprints_are_verified_for_the_embedded_bytes`, which drives the
  same bytes through the verifying `Catalog::from_json` path. It does **not**
  run at startup or during a plain `cargo build`.

  That trade is sound because `include_str!` freezes the catalog into the
  binary at compile time, so a shipped binary's fingerprints cannot drift — but
  operators should not infer a runtime enforcement that no longer exists.
  `Catalog::from_json`, the entry point for bytes of unknown provenance, still
  verifies every one.

- **`mecmcp` 0.11.0 -> 0.19.0.** That is the jump from the v0.1.1 baseline;
  0.17.0 existed only as an untagged intermediate commit.

### Upgrade note — rolling back needs the state file, not just the binary

`mecmcp-changeset` state carries a schema version. v0.1.1 links 0.11.0, whose
reader accepts **v1-v3 only**. 0.2.0 links 0.19.0, which accepts v1-v4 and
**stamps v4 on any write to a store holding a real approval**.

Once this release has written such a store, reinstalling the 0.1.1 binary alone
will not start — it rejects the file with `unsupported changeset state
version 4`. **Roll back with the Proxmox snapshot**, which restores `/var/lib`
along with the binary.
- `rmcp` 3.1.2 -> 3.1.4.
- Toolchain moved to 1.98.0 in full, not just the Dockerfile.
- `jsonschema` 0.37.4 -> 0.50.0, `getrandom` 0.2 -> 0.4.

### Security

- **Tier-2 hardening.** `tokens.json` migrates to `/var/lib` and the systemd
  unit is hardened.
- **The legacy token store is no longer shadowed by an empty one**, and the
  fallback is restricted to the canonical path. Token paths compare
  byte-for-byte rather than by `Path` equality.
- **An advisory scan never prevents startup.** A scan failure previously took
  the server down.
- Packaging probes real egress enforcement rather than implying it.

### Testing

- **Regression coverage for the audit-capture race**, not a behaviour change.
  `v0.1.1` already carried the global-subscriber/thread-local-writer
  implementation; the added guard pins it so the race cannot return. Upgrading
  does not change audit behaviour.
- `scripts/test-release-policy.sh` derives the expected version from
  `Cargo.toml` instead of hardcoding it. It had been pinned to `v0.1.1`, so
  every version bump silently turned both CI workflows red with "RC tag
  version X does not match Cargo version Y".

### Known

- **#59 — every request and response validation clones the whole components
  registry**, roughly 37 ms and 2.2 MB per call. That is the hot-path half of
  the memory story and is *not* addressed here.
