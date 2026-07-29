#!/usr/bin/env bash
# Behavioral archive-validation tests; never invokes the installer mutation path.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
installer="$root/packaging/lxc/install.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

release_name=rustmistmcp-v0.1.0-x86_64-unknown-linux-gnu

make_payload() {
    local parent=$1
    local payload="$parent/$release_name"
    mkdir -p \
        "$payload/bin" \
        "$payload/docs" \
        "$payload/packaging/examples" \
        "$payload/packaging/journald" \
        "$payload/packaging/lxc" \
        "$payload/packaging/systemd"
    printf '#!/usr/bin/env sh\nexit 0\n' > "$payload/bin/rustmistmcp"
    chmod 0755 "$payload/bin/rustmistmcp"
    printf '%s\n' MIT > "$payload/LICENSE"
    printf '%s\n' '# rustmistmcp' > "$payload/README.md"
    printf '%s\n' 'version=0.1.0' > "$payload/BUILD-INFO"
    printf '%s\n' '# operations' > "$payload/docs/OPERATIONS.md"
    printf '%s\n' '# acceptance' > "$payload/docs/PACKAGING_ACCEPTANCE.md"
    printf '%s\n' '{}' > "$payload/packaging/examples/mist.example.json"
    printf '%s\n' '{"version":1,"tokens":[]}' > "$payload/packaging/examples/tokens.example.json"
    printf '%s\n' '[Journal]' > "$payload/packaging/journald/mecmcp.conf"
    printf '#!/usr/bin/env sh\nexit 0\n' > "$payload/packaging/lxc/install.sh"
    chmod 0755 "$payload/packaging/lxc/install.sh"
    printf '%s\n' '[Service]' > "$payload/packaging/systemd/rustmistmcp.service"
    printf '%s\n' 'u rustmistmcp' > "$payload/packaging/systemd/rustmistmcp.sysusers"
    printf '%s\n' 'd /etc/rustmistmcp' > "$payload/packaging/systemd/rustmistmcp.tmpfiles"
}

pack_payload() {
    local parent=$1
    local archive=$2
    tar --sort=name -C "$parent" -czf "$archive" "$release_name"
    (cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
}

expect_valid() {
    local archive=$1
    local sidecar=$2
    timeout 15s "$installer" --validate-only "$archive" "$sidecar" >/dev/null
}

expect_invalid() {
    local label=$1
    local archive=$2
    local sidecar=$3
    if timeout 15s "$installer" --validate-only "$archive" "$sidecar" >/dev/null 2>&1; then
        printf 'expected validation failure for %s\n' "$label" >&2
        exit 1
    fi
}

expect_invalid_message() {
    local label=$1
    local archive=$2
    local sidecar=$3
    local expected=$4
    local output
    if output=$(timeout 15s "$installer" --validate-only "$archive" "$sidecar" 2>&1); then
        printf 'expected validation failure for %s\n' "$label" >&2
        exit 1
    fi
    if [[ $output != *"$expected"* ]]; then
        printf 'validation for %s did not report expected reason: %s\n' "$label" "$output" >&2
        exit 1
    fi
}

expect_invalid_without_blocking() {
    local label=$1
    local archive=$2
    local sidecar=$3
    local status
    set +e
    timeout 2s "$installer" --validate-only "$archive" "$sidecar" >/dev/null 2>&1
    status=$?
    set -e
    if [[ $status -eq 124 ]]; then
        printf 'validation blocked on caller-controlled special file for %s\n' "$label" >&2
        exit 1
    fi
    if [[ $status -eq 0 ]]; then
        printf 'expected validation failure for %s\n' "$label" >&2
        exit 1
    fi
}

valid_parent="$work/valid-parent"
mkdir -p "$valid_parent"
make_payload "$valid_parent"
valid_archive="$work/$release_name.tar.gz"
pack_payload "$valid_parent" "$valid_archive"
expect_valid "$valid_archive" "$valid_archive.sha256"

other_name=rustmistmcp-v0.1.1-x86_64-unknown-linux-gnu
other_parent="$work/other-parent"
mkdir -p "$other_parent"
cp -a "$valid_parent/$release_name" "$other_parent/$other_name"
tar --sort=name -C "$other_parent" -czf "$work/$other_name.tar.gz" "$other_name"
(cd "$work" && sha256sum "$other_name.tar.gz" > "$other_name.tar.gz.sha256")
expect_invalid wrong-sidecar "$valid_archive" "$work/$other_name.tar.gz.sha256"

cp "$valid_archive.sha256" "$work/two-records.sha256"
printf '%064d  %s\n' 0 "$(basename "$valid_archive")" >> "$work/two-records.sha256"
expect_invalid multiple-sidecar-records "$valid_archive" "$work/two-records.sha256"

unexpected_parent="$work/unexpected-parent"
cp -a "$valid_parent" "$unexpected_parent"
printf '%s\n' nope > "$unexpected_parent/$release_name/unexpected"
mkdir "$work/unexpected-case"
pack_payload "$unexpected_parent" "$work/unexpected-case/$release_name.tar.gz"
expect_invalid unexpected-member "$work/unexpected-case/$release_name.tar.gz" "$work/unexpected-case/$release_name.tar.gz.sha256"

symlink_parent="$work/symlink-parent"
cp -a "$valid_parent" "$symlink_parent"
rm "$symlink_parent/$release_name/bin/rustmistmcp"
ln -s /etc/passwd "$symlink_parent/$release_name/bin/rustmistmcp"
mkdir "$work/symlink-case"
pack_payload "$symlink_parent" "$work/symlink-case/$release_name.tar.gz"
expect_invalid symlink "$work/symlink-case/$release_name.tar.gz" "$work/symlink-case/$release_name.tar.gz.sha256"

hardlink_parent="$work/hardlink-parent"
cp -a "$valid_parent" "$hardlink_parent"
rm "$hardlink_parent/$release_name/bin/rustmistmcp"
ln "$hardlink_parent/$release_name/LICENSE" "$hardlink_parent/$release_name/bin/rustmistmcp"
mkdir "$work/hardlink-case"
pack_payload "$hardlink_parent" "$work/hardlink-case/$release_name.tar.gz"
expect_invalid hardlink "$work/hardlink-case/$release_name.tar.gz" "$work/hardlink-case/$release_name.tar.gz.sha256"

fifo_parent="$work/fifo-parent"
cp -a "$valid_parent" "$fifo_parent"
rm "$fifo_parent/$release_name/bin/rustmistmcp"
mkfifo "$fifo_parent/$release_name/bin/rustmistmcp"
mkdir "$work/fifo-case"
pack_payload "$fifo_parent" "$work/fifo-case/$release_name.tar.gz"
expect_invalid fifo "$work/fifo-case/$release_name.tar.gz" "$work/fifo-case/$release_name.tar.gz.sha256"

mkdir "$work/duplicate-case"
duplicate_raw="$work/duplicate-case/$release_name.tar"
tar --sort=name -C "$valid_parent" -cf "$duplicate_raw" "$release_name"
tar -C "$valid_parent" -rf "$duplicate_raw" "$release_name/bin/rustmistmcp"
gzip -n "$duplicate_raw"
(cd "$work/duplicate-case" && sha256sum "$release_name.tar.gz" > "$release_name.tar.gz.sha256")
expect_invalid duplicate "$work/duplicate-case/$release_name.tar.gz" "$work/duplicate-case/$release_name.tar.gz.sha256"

mkdir "$work/absolute-case"
absolute_raw="$work/absolute-case/$release_name.tar"
tar --sort=name --absolute-names --transform 's,^,/,' -C "$valid_parent" -cf "$absolute_raw" "$release_name"
gzip -n "$absolute_raw"
(cd "$work/absolute-case" && sha256sum "$release_name.tar.gz" > "$release_name.tar.gz.sha256")
expect_invalid_message \
    absolute-path \
    "$work/absolute-case/$release_name.tar.gz" \
    "$work/absolute-case/$release_name.tar.gz.sha256" \
    'archive contains an absolute or dot-segment path'

mkdir "$work/dotdot-case"
dotdot_raw="$work/dotdot-case/$release_name.tar"
tar --sort=name --transform 's,^,../,' -C "$valid_parent" -cf "$dotdot_raw" "$release_name"
gzip -n "$dotdot_raw"
(cd "$work/dotdot-case" && sha256sum "$release_name.tar.gz" > "$release_name.tar.gz.sha256")
expect_invalid dot-dot "$work/dotdot-case/$release_name.tar.gz" "$work/dotdot-case/$release_name.tar.gz.sha256"

# Caller-side special files must be copied as objects into the private
# directory and rejected there, never opened for an unbounded content read.
source_fifo_case="$work/source-fifo-case"
mkdir "$source_fifo_case"
source_fifo_archive="$source_fifo_case/$release_name.tar.gz"
mkfifo "$source_fifo_archive"
printf '%064d  %s\n' 0 "$(basename "$source_fifo_archive")" > "$source_fifo_archive.sha256"
expect_invalid_without_blocking caller-archive-fifo "$source_fifo_archive" "$source_fifo_archive.sha256"

checksum_fifo_case="$work/checksum-fifo-case"
mkdir "$checksum_fifo_case"
checksum_fifo_archive="$checksum_fifo_case/$release_name.tar.gz"
cp "$valid_archive" "$checksum_fifo_archive"
mkfifo "$checksum_fifo_archive.sha256"
expect_invalid_without_blocking caller-checksum-fifo "$checksum_fifo_archive" "$checksum_fifo_archive.sha256"

# A caller can replace both source paths after the checksum read. Validation must
# continue exclusively from the installer's private snapshots.
swap_case="$work/swap-case"
swap_bin="$work/swap-bin"
mkdir "$swap_case" "$swap_bin"
swap_archive="$swap_case/$release_name.tar.gz"
cp "$valid_archive" "$swap_archive"
cp "$valid_archive.sha256" "$swap_archive.sha256"
sed -i "s#  $(basename "$valid_archive")\$#  $(basename "$swap_archive")#" "$swap_archive.sha256"
# The single-quoted lines are the literal body of the generated wrapper.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'result=$("$REAL_SHA256SUM" "$@")' \
    'printf "%s\n" "caller replaced archive after checksum read" > "$SWAP_ARCHIVE"' \
    'printf "%s\n" "caller replaced checksum after checksum read" > "$SWAP_SIDECAR"' \
    'printf "%s\n" "$result"' > "$swap_bin/sha256sum"
chmod 0755 "$swap_bin/sha256sum"
real_sha256sum=$(command -v sha256sum)
PATH="$swap_bin:$PATH" \
    REAL_SHA256SUM="$real_sha256sum" \
    SWAP_ARCHIVE="$swap_archive" \
    SWAP_SIDECAR="$swap_archive.sha256" \
    expect_valid "$swap_archive" "$swap_archive.sha256"

printf '%s\n' 'LXC installer validation behavior: PASS'
