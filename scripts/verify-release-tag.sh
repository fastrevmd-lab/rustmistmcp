#!/usr/bin/env bash
# Require a production or RC tag whose base semantic version equals workspace.package.version.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tag=${1:?usage: verify-release-tag.sh v<VERSION> | v<VERSION>-rc<N>}

# Accept both production tags (vX.Y.Z) and RC tags (vX.Y.Z-rcN)
if [[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    tag_version=${BASH_REMATCH[1]}
    tag_type="production"
elif [[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-rc([1-9][0-9]*)$ ]]; then
    tag_version=${BASH_REMATCH[1]}
    tag_type="RC"
else
    printf 'invalid release tag: %s (expected vX.Y.Z or vX.Y.Z-rcN)\n' "$tag" >&2
    exit 1
fi

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
    printf '%s tag version %s does not match Cargo version %s\n' "$tag_type" "$tag_version" "$cargo_version" >&2
    exit 1
}
printf 'validated %s tag %s for Cargo version %s\n' "$tag_type" "$tag" "$cargo_version"
