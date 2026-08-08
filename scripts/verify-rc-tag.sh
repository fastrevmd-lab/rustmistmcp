#!/usr/bin/env bash
# Require an RC tag whose base semantic version equals workspace.package.version.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tag=${1:?usage: verify-rc-tag.sh v<VERSION>-rc<N>}
[[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-rc([1-9][0-9]*)$ ]] || {
    printf 'invalid release-candidate tag: %s\n' "$tag" >&2
    exit 1
}
tag_version=${BASH_REMATCH[1]}
cargo_version=$(awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = / {
        gsub(/"/, "", $3); print $3; exit
    }
' "$root/Cargo.toml")
[[ -n $cargo_version ]] || {
    printf '%s\n' 'workspace.package.version is missing' >&2
    exit 1
}
[[ $tag_version == "$cargo_version" ]] || {
    printf 'RC tag version %s does not match Cargo version %s\n' "$tag_version" "$cargo_version" >&2
    exit 1
}
printf 'validated RC tag %s for Cargo version %s\n' "$tag" "$cargo_version"
