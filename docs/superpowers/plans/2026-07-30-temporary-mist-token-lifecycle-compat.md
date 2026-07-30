# Temporary Mist Token Lifecycle Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a private, temporary `MistGrant` token-command adapter that safely manages grant-bearing bearer-token stores on the current coherent `mecmcp` pin.

**Architecture:** Keep every persisted token primitive in `mecmcp-auth` and keep the shared CLI shape and provenance parser in `mecmcp-runtime`. Add one non-generic binary-private module that supplies only the grant-typed command dispatch, list rendering, scope conversion, and SIGHUP glue unavailable on the pinned revision, then track its mandatory deletion in an upstream-compatibility ledger.

**Tech Stack:** Rust 1.88, Rust 2024 edition, `mecmcp-auth`, `mecmcp-runtime`, `rustix`, Clap, Cargo integration tests.

## Global Constraints

- Modify only `/home/mharman/Projects/rustmistmcp/.worktrees/mist-mcp-v1`; do not modify `mecmcp`, `rustsdcmcp`, or any other repository.
- Keep all `mecmcp-*` dependencies on the existing immutable revision `75a1e9db10a21a85876f337313ba47bc0329d74d`.
- The local adapter is fixed to `MistGrant`; it must not be generic or publicly exported.
- Reuse `TokenStoreFile<MistGrant>`, `KnownNames`, `ScopeSet`, `TokenAction`, `TokenCommandError`, and `parse_provenance`.
- New tokens created by the shared CLI remain grantless.
- Do not implement any `mecmcp#90` phase, grant-authoring flags, mutations, or live Mist networking.
- Do not contact a Mist tenant, Proxmox, VMID 612, or any deployment target.
- Preserve the pinned shared CLI's output, SIGHUP, and post-write signal-failure behavior.
- Introduce tests before implementation and observe the intended failures.
- Use `apply_patch` for project file edits.

---

### Task 1: Private Mist-typed token lifecycle adapter

**Files:**
- Create: `crates/rustmistmcp/src/mist_token_cmd.rs`
- Modify: `crates/rustmistmcp/src/main.rs`
- Modify: `crates/rustmistmcp/src/lib.rs`
- Modify: `crates/rustmistmcp/Cargo.toml`
- Modify: `crates/rustmistmcp/tests/runtime_contract.rs`

**Interfaces:**
- Consumes: `mecmcp_runtime::cli::TokenAction`, `mecmcp_runtime::token_cmd::{parse_provenance, TokenCommandError}`, `mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile}`, `rustmistmcp_core::MistGrant`.
- Produces: `pub(crate) fn run(action: TokenAction, known_tools: &[&str]) -> Result<(), TokenCommandError>` in a binary-private module.

- [ ] **Step 1: Add grant-store test helpers**

In `crates/rustmistmcp/tests/runtime_contract.rs`, add `path::Path` to the
existing `std` imports:

```rust
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::Command,
    sync::Arc,
    time::Duration,
};
```

Add these helpers immediately after `handler()`:

```rust
fn privileged_grant() -> MistGrant {
    MistGrant {
        allowed_operations: vec!["getSelf".to_owned()],
        actions: vec![MistAction::PrivilegedRead],
        subjects: vec![MistTarget::org(ORG_ID).expect("target")],
    }
}

fn add_grant_bearing_token(path: &Path, name: &str, grant: MistGrant) {
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add_with_options(
        path,
        name,
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_self".to_owned()]),
        None,
        Some(grant),
        None,
        None,
        None,
        None,
        &known,
    )
    .expect("grant-bearing token");
}
```

- [ ] **Step 2: Replace the blocker test with the complete lifecycle contract**

Replace `grant_bearing_token_lifecycle_reports_the_upstream_blocker` with:

```rust
#[test]
fn grant_bearing_token_lifecycle_preserves_mist_authority() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let grant = privileged_grant();
    add_grant_bearing_token(&tokens, "privileged", grant.clone());
    add_grant_bearing_token(&tokens, "survivor", grant.clone());

    let listed = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run token list");
    assert!(
        listed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("privileged"), "{stdout}");
    assert!(stdout.contains("survivor"), "{stdout}");
    assert!(!stdout.contains("allowed_operations"), "{stdout}");

    let before = TokenStoreFile::<MistGrant>::load(&tokens).expect("token store");
    let before_digest = before
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token")
        .digest
        .clone();

    let rotated = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "rotate",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "privileged",
        ])
        .output()
        .expect("run token rotate");
    assert!(
        rotated.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert!(!rotated.stdout.is_empty(), "rotated secret is printed once");

    let after_rotate =
        TokenStoreFile::<MistGrant>::load(&tokens).expect("rotated token store");
    let privileged = after_rotate
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token");
    assert_ne!(privileged.digest, before_digest);
    assert_eq!(privileged.grant, Some(grant.clone()));

    let revoked = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "revoke",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "privileged",
        ])
        .output()
        .expect("run token revoke");
    assert!(
        revoked.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );

    let after_revoke =
        TokenStoreFile::<MistGrant>::load(&tokens).expect("revoked token store");
    assert!(
        after_revoke
            .store()
            .entries()
            .iter()
            .all(|entry| entry.name != "privileged")
    );
    let survivor = after_revoke
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "survivor")
        .expect("surviving token");
    assert_eq!(survivor.grant, Some(grant));
}
```

- [ ] **Step 3: Add the add-to-existing-store contract**

Add:

```rust
#[test]
fn token_add_to_grant_bearing_store_preserves_existing_grant() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let grant = privileged_grant();
    add_grant_bearing_token(&tokens, "privileged", grant.clone());

    let added = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "ordinary-reader",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token add");
    assert!(
        added.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(!added.stdout.is_empty(), "one-time secret is printed");

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("token store");
    let privileged = store
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token");
    let ordinary = store
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "ordinary-reader")
        .expect("ordinary token");
    assert_eq!(privileged.grant, Some(grant));
    assert_eq!(ordinary.grant, None);
}
```

- [ ] **Step 4: Add forward-compatibility and reload-error contracts**

Add:

```rust
#[test]
fn unknown_mist_grant_field_is_refused_without_rewrite() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    add_grant_bearing_token(&tokens, "privileged", privileged_grant());

    let raw = fs::read_to_string(&tokens).expect("token document");
    let mut document: serde_json::Value =
        serde_json::from_str(&raw).expect("token document JSON");
    document["tokens"][0]["grant"]
        .as_object_mut()
        .expect("grant object")
        .insert(
            "future_restriction".to_owned(),
            serde_json::json!({"maximum_targets": 1}),
        );
    let doctored = serde_json::to_string_pretty(&document).expect("doctored JSON");
    fs::write(&tokens, &doctored).expect("write doctored token document");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run token list");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field"), "{stderr}");
    assert!(stderr.contains("future_restriction"), "{stderr}");
    assert_eq!(
        fs::read_to_string(&tokens).expect("unchanged token document"),
        doctored
    );
}

#[cfg(unix)]
#[test]
fn invalid_token_reload_pid_preserves_shared_post_write_behavior() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "written-before-signal",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
            "--server-pid",
            "0",
        ])
        .output()
        .expect("run token add");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("server PID must be positive")
    );

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("written token store");
    assert!(
        store
            .store()
            .entries()
            .iter()
            .any(|entry| entry.name == "written-before-signal"),
        "the shared contract writes atomically before requesting reload"
    );
}

#[test]
fn token_adapter_preserves_shared_wildcard_scope_refusal() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let mixed = format!("*,org/{ORG_ID}");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "mixed-scope",
            "--devices",
            &mixed,
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token add");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "invalid devices scope: '*' cannot be mixed with exact names"
        )
    );
    assert!(!tokens.exists());
}
```

- [ ] **Step 5: Run the runtime tests and observe the missing adapter**

Run:

```bash
cargo test -p rustmistmcp --test runtime_contract --locked
```

Expected: FAIL. The renamed lifecycle and add-to-existing-store tests fail
because the current command tries to deserialize `MistGrant` as `NoGrant`; the
unknown-field test fails because the diagnostic does not reach
`future_restriction`.

- [ ] **Step 6: Move rustix from a test-only dependency to a runtime dependency**

In `crates/rustmistmcp/Cargo.toml`, add this under `[dependencies]`:

```toml
rustix = { version = "1", features = ["process"] }
```

Remove the identical `rustix` entry from `[dev-dependencies]`. This does not add
a new resolved crate; the pinned shared runtime already uses rustix.

- [ ] **Step 7: Add the private adapter**

Create `crates/rustmistmcp/src/mist_token_cmd.rs`:

```rust
//! Temporary Mist-typed token lifecycle adapter.
//!
//! Delete this module when one coherent mecmcp revision contains both the
//! required mecmcp-server surface and token_cmd::run_with_grant.

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_runtime::{
    cli::TokenAction,
    token_cmd::{TokenCommandError, parse_provenance},
};
use rustmistmcp_core::MistGrant;
use std::{io::Write as _, path::Path};

pub(crate) fn run(
    action: TokenAction,
    known_tools: &[&str],
) -> Result<(), TokenCommandError> {
    let known = KnownNames {
        devices: None,
        tools: known_tools,
    };

    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => {
            let devices = parse_scope(devices, "devices")?;
            let tools = parse_scope(tools, "tools")?;
            let provenance =
                parse_provenance(provider, provider_tier, on_behalf_of, actor_type)?;
            let secret = TokenStoreFile::<MistGrant>::add_with_options(
                &tokens_file,
                &name,
                devices,
                tools,
                None,
                None,
                provenance.provider,
                provenance.provider_tier,
                provenance.on_behalf_of,
                provenance.actor_type,
                &known,
            )?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)
        }
        TokenAction::List { tokens_file } => list(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::<MistGrant>::revoke(&tokens_file, &name, &known)?;
            if removed {
                eprintln!("revoked '{name}'");
            } else {
                eprintln!("no such token '{name}' (no-op)");
            }
            signal_reload(server_pid)
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let secret = TokenStoreFile::<MistGrant>::rotate(&tokens_file, &name, &known)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)
        }
    }
}

fn parse_scope(
    values: Vec<String>,
    field: &'static str,
) -> Result<ScopeSet, TokenCommandError> {
    if values.is_empty() {
        return Err(TokenCommandError::Scope {
            field,
            message: "at least one exact name or '*' is required".to_owned(),
        });
    }
    if values.iter().any(|value| value == "*") {
        if values.len() == 1 {
            return Ok(ScopeSet::Wildcard);
        }
        return Err(TokenCommandError::Scope {
            field,
            message: "'*' cannot be mixed with exact names".to_owned(),
        });
    }
    Ok(ScopeSet::Allowlist(values))
}

fn list(path: &Path) -> Result<(), TokenCommandError> {
    let store_file = TokenStoreFile::<MistGrant>::load(path)?;
    let store = store_file.store();
    if store.is_empty() {
        eprintln!("(no tokens)");
        return Ok(());
    }

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<32} {:<24} {:<24} CREATED_AT",
        "NAME", "DEVICES", "TOOLS"
    )?;
    for entry in store.entries() {
        let devices = match &entry.devices {
            ScopeSet::Wildcard => "*".to_owned(),
            ScopeSet::Allowlist(values) => values.join(","),
        };
        let tools = match &entry.tools {
            ScopeSet::Wildcard => "*".to_owned(),
            ScopeSet::Allowlist(values) => values.join(","),
        };
        writeln!(
            out,
            "{:<32} {:<24} {:<24} {}",
            entry.name,
            devices,
            tools,
            entry.created_at.to_rfc3339()
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    let Some(raw) = pid else {
        return Ok(());
    };
    let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server PID must be positive",
        )
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP)
        .map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    if pid.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SIGHUP reload is available only on Unix",
        )
        .into());
    }
    Ok(())
}
```

- [ ] **Step 8: Wire the binary to the adapter**

At the top of `crates/rustmistmcp/src/main.rs`, add:

```rust
mod mist_token_cmd;
```

Remove `GRANT_TOKEN_LIFECYCLE_BLOCKER` from the `rustmistmcp` import. Replace
the current token command return with:

```rust
return mist_token_cmd::run(action, KNOWN_TOOLS)
    .map_err(|error| anyhow::anyhow!("{error}"));
```

Delete `GRANT_TOKEN_LIFECYCLE_BLOCKER` and its documentation from
`crates/rustmistmcp/src/lib.rs`.

- [ ] **Step 9: Format and run the focused tests**

Run:

```bash
cargo fmt --all
cargo test -p rustmistmcp --test runtime_contract --locked
```

Expected: PASS with 17 runtime contract tests. In particular, list, add,
rotate, and revoke work on a `MistGrant` store; the doctored unknown grant is
rejected; the invalid PID test confirms the file mutation precedes signalling.

- [ ] **Step 10: Run strict static analysis**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Expected: both commands exit 0.

- [ ] **Step 11: Commit the adapter**

```bash
git add crates/rustmistmcp/Cargo.toml \
  crates/rustmistmcp/src/lib.rs \
  crates/rustmistmcp/src/main.rs \
  crates/rustmistmcp/src/mist_token_cmd.rs \
  crates/rustmistmcp/tests/runtime_contract.rs
git commit -m "feat: add temporary Mist token lifecycle adapter"
```

### Task 2: Compatibility ledger and operator status

**Files:**
- Create: `docs/UPSTREAM_COMPATIBILITY.md`
- Modify: `crates/rustmistmcp/tests/runtime_contract.rs`
- Modify: `README.md`
- Modify: `docs/OPERATIONS.md`
- Modify: `docs/PACKAGING_ACCEPTANCE.md`
- Modify: `docs/superpowers/specs/2026-07-29-rustmistmcp-v1-design.md`
- Modify: `docs/superpowers/plans/2026-07-29-rustmistmcp-v1.md`
- Modify: `packaging/lxc/install.sh`

**Interfaces:**
- Consumes: private adapter from Task 1 and the approved compatibility design.
- Produces: an auditable ledger row whose deletion condition is tied to a coherent upstream revision.

- [ ] **Step 1: Add a failing compatibility-ledger contract**

Near the constants in `crates/rustmistmcp/tests/runtime_contract.rs`, add:

```rust
const UPSTREAM_COMPATIBILITY: &str =
    include_str!("../../../docs/UPSTREAM_COMPATIBILITY.md");
```

Add:

```rust
#[test]
fn temporary_token_adapter_has_an_exact_upstream_removal_contract() {
    for required in [
        "crates/rustmistmcp/src/mist_token_cmd.rs",
        "mecmcp#160",
        "mecmcp#170",
        "mecmcp-server",
        "token_cmd::run_with_grant",
        "grant_bearing_token_lifecycle_preserves_mist_authority",
    ] {
        assert!(
            UPSTREAM_COMPATIBILITY.contains(required),
            "compatibility ledger is missing {required}"
        );
    }
}
```

- [ ] **Step 2: Run the ledger test and observe the missing file**

Run:

```bash
cargo test -p rustmistmcp --test runtime_contract \
  temporary_token_adapter_has_an_exact_upstream_removal_contract --locked
```

Expected: compilation fails because
`docs/UPSTREAM_COMPATIBILITY.md` does not exist.

- [ ] **Step 3: Create the compatibility ledger**

Create `docs/UPSTREAM_COMPATIBILITY.md`:

```markdown
# Upstream compatibility ledger

Temporary compatibility code is allowed only when the shared implementation
exists upstream but cannot be consumed from the repository's one coherent
`mecmcp` revision. Every row must name an objective deletion condition.

| Local module | Upstream | Why it is local | Removal condition | Tests retained after removal |
|---|---|---|---|---|
| `crates/rustmistmcp/src/mist_token_cmd.rs` | `mecmcp#160`, merged as `mecmcp#170` | The current immutable revision contains the required `mecmcp-server` surface but predates grant-generic token commands. The main history contains `token_cmd::run_with_grant` but no `mecmcp-server`, and split revisions would duplicate shared type identities. | One immutable `mecmcp` revision contains the required `mecmcp-server` surface and `token_cmd::run_with_grant`. Replace the adapter call with `run_with_grant::<MistGrant>(..., None)`, then delete this module and row. | `grant_bearing_token_lifecycle_preserves_mist_authority`, `token_add_to_grant_bearing_store_preserves_existing_grant`, `unknown_mist_grant_field_is_refused_without_rewrite`, and `invalid_token_reload_pid_preserves_shared_post_write_behavior`. |

This ledger does not authorize local implementations of `mecmcp#90`,
`mecmcp-server`, or another broadly reusable foundation.
```

- [ ] **Step 4: Update the general ownership rule**

In `README.md`, immediately after the statement that generic auth or transport
belongs in `mecmcp`, add:

```markdown
The sole temporary exception is recorded in
[`docs/UPSTREAM_COMPATIBILITY.md`](docs/UPSTREAM_COMPATIBILITY.md): a private,
Mist-typed token lifecycle adapter needed because the current `mecmcp-server`
revision predates merged `mecmcp#160`. It must be deleted at the ledger's
objective removal condition.
```

In `docs/superpowers/specs/2026-07-29-rustmistmcp-v1-design.md`, append this
paragraph to **Ownership Boundary**:

```markdown
One narrow exception was approved on 2026-07-30: the private Mist-typed token
lifecycle adapter specified in
`2026-07-30-temporary-mist-token-lifecycle-compat-design.md`. Its upstream
ledger and objective deletion condition are mandatory; it does not change the
ownership of any `mecmcp#90` foundation.
```

- [ ] **Step 5: Replace obsolete #160 blocker language**

In `README.md`, replace the paragraph beginning
`Grant-bearing MCP bearer-token add/list/revoke/rotate remains unavailable`
with:

```markdown
Grant-bearing MCP bearer-token add/list/revoke/rotate is temporarily supported
by the private Mist-typed adapter recorded in
[`docs/UPSTREAM_COMPATIBILITY.md`](docs/UPSTREAM_COMPATIBILITY.md). New tokens
created by `token add` remain grantless; the adapter preserves and manages
existing validated `MistGrant` values. This bearer-token store is separate from
the Mist API token used by the outbound client.
```

Replace README step 2 under `Next, in order` with:

```markdown
2. Remove the temporary token adapter once merged `mecmcp#160` is published in
   the same coherent revision as the complete shared server foundation; resolve
   `mecmcp#159` for a shared version surface.
```

In `docs/OPERATIONS.md`, replace the grant lifecycle blocker paragraph with:

```markdown
Grant-bearing MCP bearer-token lifecycle is provided temporarily by the
Mist-typed adapter in `docs/UPSTREAM_COMPATIBILITY.md`. `token add` creates a
grantless token; list, rotate, revoke, and subsequent adds preserve existing
validated Mist grants. The operator-authentication store is separate from the
outbound Mist API token.
```

In `docs/PACKAGING_ACCEPTANCE.md`, replace the #160 prohibition with:

```markdown
Grant-bearing MCP bearer-token lifecycle acceptance must exercise the temporary
adapter tests named in `docs/UPSTREAM_COMPATIBILITY.md`. The adapter does not
author new Mist grants and is separate from the outbound Mist API-token
credential.
```

In `packaging/lxc/install.sh`, replace the final next-step line with:

```bash
printf '%s\n' 'Next: configure the live Mist profile/credentials, mint a grantless bearer token with rustmistmcp token add, configure journal forwarding, then enable and start rustmistmcp.'
```

- [ ] **Step 6: Update the original implementation plan status**

In `docs/superpowers/plans/2026-07-29-rustmistmcp-v1.md`, replace the #160
sentence in the Task 7 sequencing update with:

```markdown
Merged `mecmcp#160` is consumed temporarily through the private Mist-typed
adapter and compatibility ledger approved on 2026-07-30. Delete that adapter
when a coherent revision contains the required shared server surface and
`run_with_grant`.
```

- [ ] **Step 7: Run the focused contracts**

Run:

```bash
cargo test -p rustmistmcp --test runtime_contract --locked
./scripts/verify-packaging.sh
./scripts/test-release-policy.sh
```

Expected:

- runtime contract: PASS with 18 tests;
- `LXC installer validation behavior: PASS`;
- `packaging policy: PASS`;
- `release policy behavior: PASS`.

- [ ] **Step 8: Check the compatibility boundary mechanically**

Run:

```bash
rg -n "run_with_grant|mecmcp#160|mist_token_cmd" \
  README.md docs crates packaging
rg -n "pub fn|fn run<|<G[:>]" crates/rustmistmcp/src/mist_token_cmd.rs
```

Expected:

- every local compatibility reference points to the ledger, approved design,
  implementation plan, tests, or private module;
- the adapter exposes only `pub(crate) fn run`;
- the adapter contains no generic `<G>` grant API.

- [ ] **Step 9: Commit the ledger and documentation**

```bash
git add README.md \
  crates/rustmistmcp/tests/runtime_contract.rs \
  docs/OPERATIONS.md \
  docs/PACKAGING_ACCEPTANCE.md \
  docs/UPSTREAM_COMPATIBILITY.md \
  docs/superpowers/plans/2026-07-29-rustmistmcp-v1.md \
  docs/superpowers/specs/2026-07-29-rustmistmcp-v1-design.md \
  packaging/lxc/install.sh
git commit -m "docs: track temporary mecmcp compatibility"
```

### Task 3: Full verification and review

**Files:**
- Verify only; modify files only to address a concrete finding, then rerun the affected gate.

**Interfaces:**
- Consumes: the two committed tasks.
- Produces: evidence that the temporary adapter preserves the existing release and security contracts.

- [ ] **Step 1: Run the Rust gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Expected: formatting and Clippy exit 0; all workspace tests and doctests pass.

- [ ] **Step 2: Run dependency and policy gates**

```bash
cargo audit
cargo deny check
./scripts/verify-packaging.sh
./scripts/test-release-policy.sh
./scripts/test-lxc-installer.sh
```

Expected: audit and deny exit 0; packaging, release-policy, and malicious
installer behavior tests pass.

- [ ] **Step 3: Review the final diff against the approved exception**

Run:

```bash
git diff 8dd84ea..HEAD -- \
  Cargo.toml Cargo.lock crates README.md docs packaging .github scripts
git status --short --branch
```

Review for:

- no changed `mecmcp` revision;
- no generic grant type or public compatibility API;
- no #90 implementation;
- no token, digest, grant, or Mist API secret in diagnostics;
- no changes outside rustmistmcp;
- a clean worktree.

- [ ] **Step 4: Request independent code review**

Use `superpowers:requesting-code-review` against the commits created by Tasks 1
and 2. The review brief must explicitly ask for:

- semantic parity with merged `mecmcp#160`;
- preservation of existing grants across all rewrites;
- stdout/stderr secret handling;
- signal-after-write behavior;
- objective removability and ledger accuracy;
- confirmation that no generic shared foundation was recreated.

Expected: no unresolved findings. Address any finding in a new focused commit
and repeat Steps 1–4.
