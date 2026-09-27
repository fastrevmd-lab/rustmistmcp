## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] `cargo audit` and `cargo deny check` are clean, or any new advisory/license exception is called out below
- [ ] No secrets, credentials, real Mist org/site identifiers, device serials, hostnames, or captured live-tenant responses in code, tests, fixtures, or this description
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] Does this touch a device-facing config/command path (the Mist API client, or the `plan_mist_change` / `approve_mist_change_set` / `apply_mist_change_set` change-set lifecycle)? If yes, describe below and confirm it stays behind the existing plan → digest → approve → apply lifecycle with deterministic code deciding, not a model output.
- [ ] Fixtures and examples added or changed are synthetic — no real device output or live-tenant data

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
