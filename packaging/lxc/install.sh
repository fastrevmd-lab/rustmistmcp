#!/usr/bin/env bash
# Install a verified rustmistmcp release archive in Debian 13 LXC only.
set -euo pipefail

die() {
    printf 'rustmistmcp installer: %s\n' "$*" >&2
    exit 1
}

require_safe_live_secret() {
    local path=$1
    [[ ! -L $path ]] || die "live secret path must not be a symlink: $path"
    [[ ! -e $path || -f $path ]] ||
        die "existing live secret path must be a regular file: $path"
}

usage() {
    printf '%s\n' \
        'usage: install.sh [--validate-only] /path/to/rustmistmcp-v<VERSION>-<TARGET>.tar.gz /path/to/archive.sha256' >&2
    exit 2
}

validate_only=0
if [[ ${1:-} == --validate-only ]]; then
    validate_only=1
    shift
fi
[[ $# -eq 2 ]] || usage
archive_arg=$1
checksum_arg=$2

# Snapshot both caller-controlled inputs before reading either of them. All
# validation, listing, and extraction below uses only these private copies.
umask 077
work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT
archive="$work/archive"
checksum="$work/checksum"
cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive" ||
    die 'archive cannot be copied into the private validation directory'
cp --no-dereference --archive --no-target-directory -- "$checksum_arg" "$checksum" ||
    die 'checksum cannot be copied into the private validation directory'
[[ -f $archive && ! -L $archive && -r $archive ]] ||
    die 'private archive copy must be a readable regular file'
[[ -f $checksum && ! -L $checksum && -r $checksum ]] ||
    die 'private checksum copy must be a readable regular file'

archive_base=$(basename -- "$archive_arg")
[[ $archive_base =~ ^rustmistmcp-v[0-9][0-9A-Za-z.+~-]*-[A-Za-z0-9_][A-Za-z0-9_.-]*\.tar\.gz$ ]] ||
    die 'archive basename does not match the release naming contract'
release_root=${archive_base%.tar.gz}

# Bind one exact lowercase SHA-256 record to the requested archive basename.
mapfile -t checksum_lines < "$checksum"
[[ ${#checksum_lines[@]} -eq 1 ]] || die 'checksum sidecar must contain exactly one record'
[[ ${checksum_lines[0]} =~ ^([0-9a-f]{64})\ \ ([^/]+)$ ]] ||
    die 'checksum sidecar must be: 64 lowercase hex, two spaces, archive basename'
expected_digest=${BASH_REMATCH[1]}
sidecar_name=${BASH_REMATCH[2]}
[[ $sidecar_name == "$archive_base" ]] || die 'checksum sidecar is not bound to the requested archive'
actual_digest=$(sha256sum "$archive" | awk '{print $1}')
[[ $actual_digest == "$expected_digest" ]] || die 'archive SHA-256 does not match the sidecar'

# Validate member names, multiplicity, and types before extraction.
members_file="$work/members"
verbose_file="$work/verbose"
tar --absolute-names -tzf "$archive" > "$members_file" ||
    die 'archive cannot be listed as gzip-compressed tar'
tar --absolute-names -tvzf "$archive" > "$verbose_file" ||
    die 'archive member metadata cannot be listed'
mapfile -t members < "$members_file"
[[ ${#members[@]} -gt 0 ]] || die 'archive is empty'

expected_directories=(
    "$release_root/"
    "$release_root/bin/"
    "$release_root/docs/"
    "$release_root/packaging/"
    "$release_root/packaging/examples/"
    "$release_root/packaging/lxc/"
    "$release_root/packaging/systemd/"
)
expected_files=(
    "$release_root/BUILD-INFO"
    "$release_root/LICENSE"
    "$release_root/README.md"
    "$release_root/bin/rustmistmcp"
    "$release_root/docs/OPERATIONS.md"
    "$release_root/docs/PACKAGING_ACCEPTANCE.md"
    "$release_root/packaging/examples/mist.example.json"
    "$release_root/packaging/examples/tokens.example.json"
    "$release_root/packaging/lxc/install.sh"
    "$release_root/packaging/systemd/rustmistmcp.service"
    "$release_root/packaging/systemd/rustmistmcp.sysusers"
    "$release_root/packaging/systemd/rustmistmcp.tmpfiles"
)
declare -A expected=()
declare -A seen=()
for member in "${expected_directories[@]}" "${expected_files[@]}"; do
    expected["$member"]=1
done
for member in "${members[@]}"; do
    [[ -n $member ]] || die 'archive contains an empty member name'
    [[ $member != /* && $member != ./* && $member != ../* &&
        $member != */../* && $member != */.. && $member != */./* && $member != */. ]] ||
        die "archive contains an absolute or dot-segment path: $member"
    [[ ${expected[$member]+present} ]] || die "archive contains an unexpected member: $member"
    [[ ! ${seen[$member]+present} ]] || die "archive contains a duplicate member: $member"
    seen["$member"]=1
done
for member in "${!expected[@]}"; do
    [[ ${seen[$member]+present} ]] || die "archive is missing required member: $member"
done
while IFS= read -r metadata; do
    case ${metadata:0:1} in
        -|d) ;;
        *) die 'archive contains a link, device, or FIFO member' ;;
    esac
done < "$verbose_file"

# Extract only to a fresh temporary directory, then verify without following links.
extract_root="$work/extracted"
mkdir "$extract_root"
tar -xzf "$archive" -C "$extract_root" --no-same-owner --no-same-permissions ||
    die 'archive extraction failed'
payload="$extract_root/$release_root"
unexpected_type=$(find -P "$payload" -mindepth 1 ! -type d ! -type f -print -quit)
[[ -z $unexpected_type ]] || die "extracted payload has an unsafe object type: $unexpected_type"
for member in "${expected_directories[@]}"; do
    extracted="$extract_root/${member%/}"
    [[ -d $extracted && ! -L $extracted ]] || die "required directory is unsafe after extraction: $member"
    [[ $(realpath -e -- "$extracted") == "$extract_root/${member%/}" ]] ||
        die "required directory escapes the extraction root: $member"
done
for member in "${expected_files[@]}"; do
    extracted="$extract_root/$member"
    [[ -f $extracted && ! -L $extracted ]] || die "required file is unsafe after extraction: $member"
    [[ $(realpath -e -- "$extracted") == "$extract_root/$member" ]] ||
        die "required file escapes the extraction root: $member"
done

if (( validate_only )); then
    printf 'validated %s sha256:%s\n' "$archive_base" "$actual_digest"
    exit 0
fi

# Host mutation is allowed only after archive validation and explicit platform proof.
[[ $(id -u) -eq 0 ]] || die 'run as root inside the target LXC'
[[ -r /etc/os-release ]] || die 'cannot verify Debian release'
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || die 'installer requires Debian 13'
[[ $(systemd-detect-virt --container 2>/dev/null || true) == lxc ]] ||
    die 'installer requires an LXC guest'
[[ ${RUSTMISTMCP_LXC_HOST_PROOF:-} == 'unprivileged=1,nesting=1' ]] ||
    die 'host-side proof required: verify unprivileged=1 and features nesting=1, then set RUSTMISTMCP_LXC_HOST_PROOF=unprivileged=1,nesting=1'

# Refuse an unsafe live-secret target before the first host mutation. Repeat the
# checks immediately before secret handling to narrow the remaining race window.
require_safe_live_secret /var/lib/rustmistmcp/tokens.json
require_safe_live_secret /etc/rustmistmcp/audit-hmac.key
require_safe_live_secret /etc/rustmistmcp/mist-api-token

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates
if [[ ${RUSTMISTMCP_INSTALL_VERIFY_TOOLS:-0} == 1 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl
fi
apt-get clean
rm -rf /var/lib/apt/lists/*

install -D -m 0644 "$payload/packaging/systemd/rustmistmcp.sysusers" /usr/lib/sysusers.d/rustmistmcp.conf
install -D -m 0644 "$payload/packaging/systemd/rustmistmcp.tmpfiles" /usr/lib/tmpfiles.d/rustmistmcp.conf
systemd-sysusers
systemd-tmpfiles --create /usr/lib/tmpfiles.d/rustmistmcp.conf

install -D -o root -g root -m 0755 "$payload/bin/rustmistmcp" /usr/local/bin/rustmistmcp

# Remove stale mecmcp.conf if present. Stop shipping it per rustmistmcp#44.
if [[ -e /etc/systemd/journald.conf.d/mecmcp.conf ]]; then
    rm -f /etc/systemd/journald.conf.d/mecmcp.conf
fi
if [[ ! -e /etc/systemd/system/rustmistmcp.service || ${RUSTMISTMCP_FORCE_UNIT:-0} == 1 ]]; then
    install -D -m 0644 "$payload/packaging/systemd/rustmistmcp.service" /etc/systemd/system/rustmistmcp.service
fi

# Examples are non-live. Live config, credentials, state, and customized units are preserved.
install -D -m 0644 "$payload/packaging/examples/mist.example.json" /etc/rustmistmcp/mist.example.json
install -D -m 0644 "$payload/packaging/examples/tokens.example.json" /etc/rustmistmcp/tokens.example.json
require_safe_live_secret /var/lib/rustmistmcp/tokens.json
require_safe_live_secret /etc/rustmistmcp/audit-hmac.key
require_safe_live_secret /etc/rustmistmcp/mist-api-token
if [[ ! -e /var/lib/rustmistmcp/tokens.json ]]; then
    install -m 0600 -o rustmistmcp -g rustmistmcp /dev/null /var/lib/rustmistmcp/tokens.json
    printf '%s\n' '{"version":1,"tokens":[]}' > /var/lib/rustmistmcp/tokens.json
fi
chown rustmistmcp:rustmistmcp -- /var/lib/rustmistmcp/tokens.json
chmod 0600 -- /var/lib/rustmistmcp/tokens.json
if [[ -e /etc/rustmistmcp/audit-hmac.key ]]; then
    chown rustmistmcp:rustmistmcp -- /etc/rustmistmcp/audit-hmac.key
    chmod 0600 -- /etc/rustmistmcp/audit-hmac.key
fi
if [[ -e /etc/rustmistmcp/mist-api-token ]]; then
    chown rustmistmcp:rustmistmcp -- /etc/rustmistmcp/mist-api-token
    chmod 0600 -- /etc/rustmistmcp/mist-api-token
fi

systemctl daemon-reload
systemctl restart systemd-journald
printf '%s\n' 'Installed rustmistmcp without enabling it.'
printf '%s\n' 'Next: configure the live Mist profile/credentials, mint a grantless bearer token with rustmistmcp token add, configure journal forwarding, then enable and start rustmistmcp.'
