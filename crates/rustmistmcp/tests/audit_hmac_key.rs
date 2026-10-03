//! The container image must not ship unkeyed audit by omission (mecmcp#376 /
//! MEC-978): the binary must pre-provision `--audit-hmac-key-file` on first
//! run, mirroring `packaging/lxc/install.sh`'s own key-generation step, so a
//! fresh container volume converges on the same keyed-audit posture.
#![allow(clippy::unwrap_used)]

use std::process::Command;

/// Starting with `--audit-hmac-key-file` pointing at a path that does not
/// exist yet must create it: 64 lowercase hex characters (a 32-byte key) at
/// mode 0600. The process still exits non-zero (there is no reachable device
/// mapping here), but key generation happens before that failure.
#[test]
fn a_missing_hmac_key_file_is_generated() {
    let key_dir = tempfile::tempdir().expect("key dir");
    let key_path = key_dir.path().join("audit-hmac.key");

    let _ = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "--audit-redact",
            "devices=hmac",
            "--audit-hmac-key-file",
            key_path.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run binary");

    assert!(
        key_path.exists(),
        "the HMAC key file must be generated when absent"
    );
    let contents = std::fs::read_to_string(&key_path).expect("read key file");
    assert_eq!(
        contents.len(),
        64,
        "the generated key must be 32 bytes hex-encoded, got {} chars: {contents}",
        contents.len()
    );
    assert!(
        contents.chars().all(|c| c.is_ascii_hexdigit()),
        "the generated key must be hex, got: {contents}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path)
            .expect("stat key file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the generated key file must be mode 0600, got {mode:o}"
        );
    }
}

/// An existing, non-empty key file must never be overwritten -- rotating it
/// silently would break verification of every audit record signed under the
/// old key.
#[test]
fn an_existing_hmac_key_file_is_left_untouched() {
    let key_dir = tempfile::tempdir().expect("key dir");
    let key_path = key_dir.path().join("audit-hmac.key");
    std::fs::write(&key_path, "deadbeef").expect("write pre-existing key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let _ = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "--audit-redact",
            "devices=hmac",
            "--audit-hmac-key-file",
            key_path.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run binary");

    let contents = std::fs::read_to_string(&key_path).expect("read key file");
    assert_eq!(
        contents, "deadbeef",
        "a pre-existing non-empty key file must not be rotated, got: {contents}"
    );
}

/// The container image must not ship unkeyed audit by omission (mecmcp#376 /
/// MEC-978): five of six server images ran with no `--audit-hmac-key-file`
/// in ENTRYPOINT while every systemd unit keyed it. CMD is operator-replaced
/// on every `docker run` with extra arguments, so the flag must live in
/// ENTRYPOINT, not CMD, to survive that.
#[test]
fn the_entrypoint_pre_provisions_an_audit_hmac_key() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let text = std::fs::read_to_string(repo_root.join("Dockerfile")).expect("read Dockerfile");
    let entrypoint_start = text
        .find("ENTRYPOINT [")
        .expect("Dockerfile has an ENTRYPOINT instruction");
    let entrypoint_end = text[entrypoint_start..]
        .find(']')
        .map(|offset| entrypoint_start + offset)
        .expect("ENTRYPOINT instruction is closed");
    let entrypoint = &text[entrypoint_start..entrypoint_end];

    assert!(
        entrypoint.contains("--audit-hmac-key-file"),
        "ENTRYPOINT must carry --audit-hmac-key-file so the image generates a \
         keyed audit HMAC key on first run instead of shipping unkeyed by \
         omission, got: {entrypoint}"
    );
}
