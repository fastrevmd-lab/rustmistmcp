#!/usr/bin/env bash
# Build one deterministic, credential-free release archive from a clean tree.
set -euo pipefail
umask 022

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if [[ ${RUSTMISTMCP_CI_SOURCE_VERIFIED:-0} == 1 ]]; then
    [[ ${RUSTMISTMCP_COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || {
        printf '%s\n' 'CI source mode requires RUSTMISTMCP_COMMIT as exactly 40 lowercase hex' >&2
        exit 1
    }
    [[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]+$ ]] || {
        printf '%s\n' 'CI source mode requires numeric SOURCE_DATE_EPOCH' >&2
        exit 1
    }
    source_commit=$RUSTMISTMCP_COMMIT
elif [[ ${RUSTMISTMCP_ALLOW_DIRTY:-0} != 1 ]] &&
    [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
        printf '%s\n' 'refusing to build from a dirty tree (set RUSTMISTMCP_ALLOW_DIRTY=1 to override)' >&2
        exit 1
else
    source_commit=$(git rev-parse HEAD)
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
fi

target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
cargo_version=$(awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = / {
        gsub(/"/, "", $3); print $3; exit
    }
' Cargo.toml)
[[ -n $cargo_version ]] || { printf '%s\n' 'could not determine package version' >&2; exit 1; }
version=${RUSTMISTMCP_RELEASE_VERSION:-$cargo_version}
if [[ $version != "$cargo_version" ]]; then
    rc_suffix=${version#"$cargo_version-rc"}
    [[ $version == "$cargo_version-rc$rc_suffix" && $rc_suffix =~ ^[1-9][0-9]*$ ]] || {
        printf 'release version must equal Cargo version or a matching RC: Cargo=%s release=%s\n' "$cargo_version" "$version" >&2
        exit 1
    }
fi

export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/usr/src/rustmistmcp"

cargo build --release --locked --bin rustmistmcp --target "$target"

out=${RUSTMISTMCP_DIST_DIR:-$root/dist}
cargo_target_dir=${CARGO_TARGET_DIR:-$root/target}
if [[ $cargo_target_dir != /* ]]; then
    cargo_target_dir="$root/$cargo_target_dir"
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
name="rustmistmcp-v${version}-${target}"
payload="$stage/$name"
mkdir -p "$payload/bin" "$payload/docs" "$payload/packaging/systemd" "$payload/packaging/journald" "$payload/packaging/lxc" "$payload/packaging/examples"
install -m 0755 "$cargo_target_dir/$target/release/rustmistmcp" "$payload/bin/rustmistmcp"
install -m 0644 LICENSE README.md "$payload/"
install -m 0644 docs/OPERATIONS.md docs/PACKAGING_ACCEPTANCE.md "$payload/docs/"
install -m 0644 packaging/systemd/rustmistmcp.service packaging/systemd/rustmistmcp.sysusers packaging/systemd/rustmistmcp.tmpfiles "$payload/packaging/systemd/"
install -m 0644 packaging/journald/mecmcp.conf "$payload/packaging/journald/"
install -m 0755 packaging/lxc/install.sh "$payload/packaging/lxc/"
install -m 0644 packaging/examples/mist.example.json packaging/examples/tokens.example.json "$payload/packaging/examples/"
binary_sha256=$(sha256sum "$payload/bin/rustmistmcp" | awk '{print $1}')
printf 'version=%s\ncargo_version=%s\ntarget=%s\ncommit=%s\nrustc=%s\nsource_date_epoch=%s\nbinary_sha256=%s\n' \
    "$version" "$cargo_version" "$target" "$source_commit" "$(rustc -V)" "$SOURCE_DATE_EPOCH" "$binary_sha256" > "$payload/BUILD-INFO"

mkdir -p "$out"
archive="$out/$name.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - "$name" | gzip -n > "$archive"
(cd "$out" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
printf '%s\n' "$archive"
