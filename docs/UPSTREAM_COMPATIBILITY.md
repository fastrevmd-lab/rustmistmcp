# Upstream compatibility ledger

Temporary compatibility code is allowed only when the shared implementation
exists upstream but cannot be consumed from the repository's one coherent
`mecmcp` revision. Every row must name an objective deletion condition.

| Local module | Upstream | Why it is local | Removal condition | Tests retained after removal |
|---|---|---|---|---|
| _(none)_ | | | | |

The ledger's only row was `crates/rustmistmcp/src/mist_token_cmd.rs`, an adapter
for grant-preserving token commands (`mecmcp#160`). Its removal condition was
"one immutable `mecmcp` revision contains the required `mecmcp-server` surface
and `token_cmd::run_with_grant`". Revision `850f529` (`mecmcp` v0.8.8) contains
both, the adapter is deleted, and `main` calls
`run_with_grant::<MistGrant>(..., None)` directly.

The four tests named in that row are retained and still run against the shared
implementation, in `crates/rustmistmcp/tests/runtime_contract.rs`:
`grant_bearing_token_lifecycle_preserves_mist_authority`,
`token_add_to_grant_bearing_store_preserves_existing_grant`,
`unknown_mist_grant_field_is_refused_without_rewrite`, and
`invalid_token_reload_pid_preserves_shared_post_write_behavior`.

This ledger does not authorize local implementations of `mecmcp#90`,
`mecmcp-server`, or another broadly reusable foundation.
