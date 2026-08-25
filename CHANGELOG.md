# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.2.0. Earlier tags (0.1.0, 0.1.1) predate it and are
recoverable from `git log` and the release tags — noted so the omission is
visible rather than looking like those versions never existed.

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
