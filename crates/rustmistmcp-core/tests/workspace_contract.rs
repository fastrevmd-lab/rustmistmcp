//! Compile-time workspace-manifest contract for the initial crate boundary.

use std::path::Path;

const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");
const CORE_MANIFEST: &str = include_str!("../Cargo.toml");
const SERVER_MANIFEST: &str = include_str!("../../rustmistmcp/Cargo.toml");

const MECMCP_REVISION: &str = "3eac1100b02f31254967cd07c926acf89994b287";

#[test]
fn workspace_metadata_lints_and_shared_revision_are_locked() {
    for expected in [
        "members = [\"crates/rustmistmcp-core\", \"crates/rustmistmcp\"]",
        "default-members = [\"crates/rustmistmcp-core\", \"crates/rustmistmcp\"]",
        "resolver = \"2\"",
        "version = \"0.1.0\"",
        "edition = \"2024\"",
        "rust-version = \"1.88\"",
        "license = \"MIT\"",
        "repository = \"https://github.com/fastrevmd-lab/rustmistmcp\"",
        "authors = [\"fastrevmd-lab\"]",
        "missing_docs = \"warn\"",
        "unsafe_code = \"forbid\"",
        "all = { level = \"warn\", priority = -1 }",
        "dbg_macro = \"deny\"",
        "todo = \"deny\"",
        "unwrap_used = \"warn\"",
        "lto = \"thin\"",
        "codegen-units = 1",
        "strip = \"symbols\"",
        "mecmcp#90 and mecmcp#91 remain open prerequisites",
    ] {
        assert!(
            WORKSPACE_MANIFEST.contains(expected),
            "workspace manifest is missing `{expected}`"
        );
    }

    for manifest in [CORE_MANIFEST, SERVER_MANIFEST] {
        for expected in [
            "version.workspace = true",
            "edition.workspace = true",
            "rust-version.workspace = true",
            "license.workspace = true",
            "repository.workspace = true",
            "workspace = true",
        ] {
            assert!(
                manifest.contains(expected),
                "package manifest is missing `{expected}`"
            );
        }
    }

    for source_path in [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustmistmcp/src/lib.rs"),
    ] {
        assert!(
            source_path.is_file(),
            "workspace library target must exist at {}",
            source_path.display()
        );
    }

    assert_workspace_mecmcp_dependencies_are_pinned(WORKSPACE_MANIFEST);
}

fn assert_workspace_mecmcp_dependencies_are_pinned(manifest: &str) {
    let manifest: toml::Value = manifest
        .parse()
        .expect("workspace manifest must be valid TOML");
    let dependencies = manifest["workspace"]["dependencies"]
        .as_table()
        .expect("workspace manifest must contain [workspace.dependencies]");
    let mecmcp_dependencies: Vec<_> = dependencies
        .iter()
        .filter(|(name, _)| name.starts_with("mecmcp-"))
        .collect();

    assert!(
        !mecmcp_dependencies.is_empty(),
        "workspace must declare at least one shared mecmcp dependency"
    );

    for (crate_name, dependency) in mecmcp_dependencies {
        let dependency = dependency
            .as_table()
            .unwrap_or_else(|| panic!("{crate_name} must use an inline dependency table"));
        assert_eq!(
            dependency.get("git").and_then(toml::Value::as_str),
            Some("https://github.com/fastrevmd-lab/mecmcp"),
            "{crate_name} must use the approved mecmcp Git source"
        );
        assert_eq!(
            dependency.get("rev").and_then(toml::Value::as_str),
            Some(MECMCP_REVISION),
            "{crate_name} must use the shared immutable mecmcp revision"
        );
    }
}
