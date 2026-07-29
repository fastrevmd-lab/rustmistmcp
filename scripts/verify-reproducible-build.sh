#!/usr/bin/env bash
# Rebuild twice from the same clean source epoch and compare release archives.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
first=$(mktemp -d)
second=$(mktemp -d)
first_target=$(mktemp -d)
second_target=$(mktemp -d)
trap 'rm -rf "$first" "$second" "$first_target" "$second_target"' EXIT

(
    umask 022
    SOURCE_DATE_EPOCH=$epoch CARGO_TARGET_DIR="$first_target" \
        RUSTMISTMCP_DIST_DIR="$first" scripts/build-release.sh
)
(
    umask 077
    SOURCE_DATE_EPOCH=$epoch CARGO_TARGET_DIR="$second_target" \
        RUSTMISTMCP_DIST_DIR="$second" scripts/build-release.sh
)
cmp "$first"/*.tar.gz "$second"/*.tar.gz
cmp "$first"/*.sha256 "$second"/*.sha256
printf '%s\n' 'reproducible archive: PASS'
