#!/usr/bin/env bash
# Validate, extract, hash-check, execute, and measure one release archive.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive_arg=${1:?usage: smoke-release-archive.sh ARCHIVE ARCHIVE.sha256}
sidecar_arg=${2:?usage: smoke-release-archive.sh ARCHIVE ARCHIVE.sha256}

archive_base=$(basename -- "$archive_arg")
[[ $archive_base =~ ^rustmistmcp-v[0-9][0-9A-Za-z.+~-]*-[A-Za-z0-9_][A-Za-z0-9_.-]*\.tar\.gz$ ]] || {
    printf '%s\n' 'archive basename does not match the release naming contract' >&2
    exit 1
}
umask 077
work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT
archive="$work/$archive_base"
sidecar="$work/checksum"
cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive"
cp --no-dereference --archive --no-target-directory -- "$sidecar_arg" "$sidecar"
[[ -f $archive && ! -L $archive && -r $archive ]] || {
    printf '%s\n' 'private archive copy must be a readable regular file' >&2
    exit 1
}
[[ -f $sidecar && ! -L $sidecar && -r $sidecar ]] || {
    printf '%s\n' 'private sidecar copy must be a readable regular file' >&2
    exit 1
}

"$root/packaging/lxc/install.sh" --validate-only "$archive" "$sidecar"
extract_root="$work/extracted"
mkdir "$extract_root"
tar -xzf "$archive" -C "$extract_root" --no-same-owner --no-same-permissions
release_root=${archive_base%.tar.gz}
payload="$extract_root/$release_root"
binary="$payload/bin/rustmistmcp"
build_info="$payload/BUILD-INFO"

expected_binary_sha=$(sed -n 's/^binary_sha256=//p' "$build_info")
[[ $expected_binary_sha =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' 'BUILD-INFO has no valid binary_sha256' >&2
    exit 1
}
actual_binary_sha=$(sha256sum "$binary" | awk '{print $1}')
[[ $actual_binary_sha == "$expected_binary_sha" ]] || {
    printf '%s\n' 'extracted binary hash does not match BUILD-INFO' >&2
    exit 1
}
"$binary" --help | grep -Fq 'Usage: rustmistmcp'
if ! command -v objdump >/dev/null; then
    printf '%s\n' 'objdump is required to measure the glibc floor' >&2
    exit 1
fi
glibc_floor=$(objdump -T "$binary" |
    grep -oE 'GLIBC_[0-9]+\.[0-9]+' |
    sort -Vu |
    tail -1)
[[ $glibc_floor =~ ^GLIBC_[0-9]+\.[0-9]+$ ]] || {
    printf '%s\n' 'could not measure a glibc floor' >&2
    exit 1
}
printf 'archive smoke: PASS binary_sha256=%s glibc_floor=%s\n' "$actual_binary_sha" "$glibc_floor"
