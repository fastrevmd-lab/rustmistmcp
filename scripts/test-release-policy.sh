#!/usr/bin/env bash
# Behavioral tests for release tag and dirty-tree policy.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Derived, not hardcoded: this file previously pinned v0.1.1 and every version
# bump silently turned both CI workflows red with "RC tag version X does not
# match Cargo version Y".
version=$(grep -m1 -E '^version[[:space:]]*=' "$root/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$version" ] || { printf '%s\n' 'could not read workspace version' >&2; exit 1; }

"$root/scripts/verify-release-tag.sh" "v${version}-rc1"
"$root/scripts/verify-release-tag.sh" "v${version}"
if "$root/scripts/verify-release-tag.sh" v9.0.0-rc1 >/dev/null 2>&1; then
    printf '%s\n' 'mismatched RC tag was accepted' >&2
    exit 1
fi
if "$root/scripts/verify-release-tag.sh" v9.0.0 >/dev/null 2>&1; then
    printf '%s\n' 'mismatched production tag was accepted' >&2
    exit 1
fi
if "$root/scripts/verify-release-tag.sh" invalid-tag >/dev/null 2>&1; then
    printf '%s\n' 'invalid tag format was accepted' >&2
    exit 1
fi

fixture="$work/repo"
mkdir -p "$fixture/scripts"
cp "$root/scripts/build-release.sh" "$fixture/scripts/"
cp "$root/Cargo.toml" "$fixture/"
git -C "$fixture" init -q
git -C "$fixture" config user.name packaging-test
git -C "$fixture" config user.email packaging-test@example.invalid
git -C "$fixture" add Cargo.toml scripts/build-release.sh
git -C "$fixture" commit -qm baseline
printf '%s\n' dirty > "$fixture/untracked-build-input"
if output=$(cd "$fixture" && scripts/build-release.sh 2>&1); then
    printf '%s\n' 'untracked build input was accepted' >&2
    exit 1
fi
grep -Fq 'refusing to build from a dirty tree' <<<"$output" || {
    printf 'dirty-tree refusal was not the failure cause:\n%s\n' "$output" >&2
    exit 1
}

if output=$(cd "$fixture" &&
    RUSTMISTMCP_CI_SOURCE_VERIFIED=1 SOURCE_DATE_EPOCH=1700000000 scripts/build-release.sh 2>&1); then
    printf '%s\n' 'CI source mode accepted a missing commit' >&2
    exit 1
fi
grep -Fq 'CI source mode requires RUSTMISTMCP_COMMIT' <<<"$output" || {
    printf 'missing CI commit was not the failure cause:\n%s\n' "$output" >&2
    exit 1
}

rm "$fixture/untracked-build-input"
if output=$(cd "$fixture" &&
    RUSTMISTMCP_RELEASE_VERSION=9.0.0-rc1 scripts/build-release.sh 2>&1); then
    printf '%s\n' 'archive accepted a release version inconsistent with Cargo' >&2
    exit 1
fi
grep -Fq 'release version must equal Cargo version or a matching RC' <<<"$output" || {
    printf 'release-version mismatch was not the failure cause:\n%s\n' "$output" >&2
    exit 1
}

printf '%s\n' 'release policy behavior: PASS'
