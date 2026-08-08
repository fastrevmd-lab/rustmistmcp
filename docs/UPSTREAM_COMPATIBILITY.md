# Upstream compatibility ledger

Temporary compatibility code is allowed only when the shared implementation
exists upstream but cannot be consumed from the repository's one coherent
`mecmcp` revision. Every row must name an objective deletion condition.

| Local module | Upstream | Why it is local | Removal condition | Tests retained after removal |
|---|---|---|---|---|
| `crates/rustmistmcp/src/mist_token_cmd.rs` | `mecmcp#160`, merged as `mecmcp#170` | The current immutable revision contains the required `mecmcp-server` surface but predates grant-generic token commands. The main history contains `token_cmd::run_with_grant` but no `mecmcp-server`, and split revisions would duplicate shared type identities. | One immutable `mecmcp` revision contains the required `mecmcp-server` surface and `token_cmd::run_with_grant`. Replace the adapter call with `run_with_grant::<MistGrant>(..., None)`, then delete this module and row. | `grant_bearing_token_lifecycle_preserves_mist_authority`, `token_add_to_grant_bearing_store_preserves_existing_grant`, `unknown_mist_grant_field_is_refused_without_rewrite`, and `invalid_token_reload_pid_preserves_shared_post_write_behavior`. |

This ledger does not authorize local implementations of `mecmcp#90`,
`mecmcp-server`, or another broadly reusable foundation.
