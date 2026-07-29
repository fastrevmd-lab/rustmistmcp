#!/usr/bin/env bash
# Static delivery-policy contract for pre-release rustmistmcp artifacts.
# Dollar expressions in single quotes below are intentionally matched as
# literal source/workflow text rather than expanded by this policy script.
# shellcheck disable=SC2016
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

failures=0

require_file() {
    if [[ ! -f $1 ]]; then
        printf 'missing required file: %s\n' "$1" >&2
        failures=$((failures + 1))
    fi
}

require_contains() {
    local file=$1
    local pattern=$2
    if ! grep -Fq -- "$pattern" "$file"; then
        printf 'missing required text in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_regex() {
    local file=$1
    local pattern=$2
    if ! grep -Eq -- "$pattern" "$file"; then
        printf 'missing required pattern in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_absent() {
    local file=$1
    local pattern=$2
    if grep -Eq -- "$pattern" "$file"; then
        printf 'forbidden text in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_count() {
    local file=$1
    local pattern=$2
    local expected=$3
    local actual
    actual=$(grep -Fc -- "$pattern" "$file" || true)
    if [[ $actual -ne $expected ]]; then
        printf 'unexpected count in %s for %s: expected %s, got %s\n' \
            "$file" "$pattern" "$expected" "$actual" >&2
        failures=$((failures + 1))
    fi
}

require_before() {
    local file=$1
    local first=$2
    local second=$3
    local first_line
    local second_line
    first_line=$(grep -nF -- "$first" "$file" | head -n 1 | cut -d: -f1 || true)
    second_line=$(grep -nF -- "$second" "$file" | head -n 1 | cut -d: -f1 || true)
    if [[ -z $first_line || -z $second_line || $first_line -ge $second_line ]]; then
        printf 'required ordering missing in %s: %s before %s\n' "$file" "$first" "$second" >&2
        failures=$((failures + 1))
    fi
}

required_files=(
    .dockerignore
    Dockerfile
    .github/dependabot.yml
    packaging/container/compose.example.yaml
    packaging/lxc/install.sh
    packaging/systemd/rustmistmcp.service
    packaging/systemd/rustmistmcp.sysusers
    packaging/systemd/rustmistmcp.tmpfiles
    packaging/journald/mecmcp.conf
    scripts/build-release.sh
    scripts/smoke-oci.sh
    scripts/smoke-release-archive.sh
    scripts/test-lxc-installer.sh
    .github/workflows/ci.yml
    .github/workflows/release.yml
    .github/workflows/security.yml
)
for file in "${required_files[@]}"; do
    require_file "$file"
done

if (( failures > 0 )); then
    printf 'packaging policy: FAIL (%d violation(s))\n' "$failures" >&2
    exit 1
fi

dockerfile=Dockerfile
compose=packaging/container/compose.example.yaml
installer=packaging/lxc/install.sh
unit=packaging/systemd/rustmistmcp.service
sysusers=packaging/systemd/rustmistmcp.sysusers
tmpfiles=packaging/systemd/rustmistmcp.tmpfiles
journald=packaging/journald/mecmcp.conf

require_regex "$dockerfile" '^FROM rust:1\.97\.0-slim-bookworm@sha256:[0-9a-f]{64} AS builder$'
require_regex "$dockerfile" '^FROM gcr\.io/distroless/cc-debian13:nonroot@sha256:[0-9a-f]{64}$'
require_absent "$dockerfile" '^# syntax='
require_contains "$dockerfile" 'USER 65532:65532'
require_contains "$dockerfile" 'ENTRYPOINT ["/usr/local/bin/rustmistmcp"]'
require_contains "$dockerfile" 'EXPOSE 30030'
require_contains "$dockerfile" 'COPY docs/mist-api/catalog.json ./docs/mist-api/catalog.json'
require_contains "$dockerfile" 'CMD ["--device-mapping", "/etc/rustmistmcp/mist.json", "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "30030", "--tokens-file", "/etc/rustmistmcp/tokens.json", "--audit-format", "json", "--audit-redact", "devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac", "--audit-hmac-key-file", "/etc/rustmistmcp/audit-hmac.key"]'
require_absent "$dockerfile" --audit-journald
require_contains "$dockerfile" 'STOPSIGNAL SIGTERM'
require_absent "$dockerfile" '(apt-get|apk add|dnf install|yum install|curl |wget |/bin/sh)'
for ignored in '.git' '.worktrees' 'target' 'dist' 'tokens.json' '*.tokens.json' '.env' '*.pem' '*.key' '!docs/mist-api/catalog.json'; do
    require_contains .dockerignore "$ignored"
done

require_contains "$compose" 'user: "65532:65532"'
require_contains "$compose" 'network_mode: host'
require_contains "$compose" 'read_only: true'
require_contains "$compose" 'cap_drop:'
require_contains "$compose" '- ALL'
require_contains "$compose" 'no-new-privileges:true'
require_contains "$compose" 'pids_limit:'
require_contains "$compose" '/etc/rustmistmcp:ro'
require_contains "$compose" '/var/lib/rustmistmcp:rw'
require_absent "$compose" '/run/systemd/journal/socket'
require_contains "$compose" 'size=16m'
require_absent "$compose" '(MIST.*TOKEN|TOKEN=.*|API_KEY|APIKEY|SECRET=.*)'
require_absent "$compose" '(ports:|--host 0\.0\.0\.0|--allow-insecure-bind)'

require_contains "$sysusers" 'u rustmistmcp - "rustmistmcp service user" /var/lib/rustmistmcp'
require_contains "$tmpfiles" 'd /etc/rustmistmcp 0750 root rustmistmcp -'
require_contains "$tmpfiles" 'd /var/lib/rustmistmcp 0700 rustmistmcp rustmistmcp -'
require_contains "$journald" 'Storage=persistent'
require_contains "$journald" 'SystemMaxUse=512M'
require_absent "$journald" '^Seal='

require_contains "$unit" 'User=rustmistmcp'
require_contains "$unit" 'Group=rustmistmcp'
require_contains "$unit" 'UMask=0077'
require_contains "$unit" 'ReadOnlyPaths=/etc/rustmistmcp'
require_contains "$unit" 'ReadWritePaths=/var/lib/rustmistmcp'
require_contains "$unit" 'NoNewPrivileges=yes'
require_contains "$unit" 'CapabilityBoundingSet='
require_contains "$unit" 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
require_contains "$unit" 'TasksMax='
require_contains "$unit" 'LimitNOFILE='
for runtime_arg in \
    'ExecStart=/usr/local/bin/rustmistmcp' \
    '--device-mapping /etc/rustmistmcp/mist.json' \
    '--transport streamable-http' \
    '--host 127.0.0.1' \
    '--port 30030' \
    '--tokens-file /etc/rustmistmcp/tokens.json' \
    '--audit-format json' \
    '--audit-journald' \
    '--audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac' \
    '--audit-hmac-key-file /etc/rustmistmcp/audit-hmac.key'; do
    require_contains "$unit" "$runtime_arg"
done
require_absent "$unit" '(changeset-state|mutation-state|--state)'

require_contains "$installer" 'umask 077'
require_contains "$installer" 'work=$(mktemp -d)'
require_contains "$installer" 'chmod 0700 "$work"'
require_contains "$installer" 'cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive"'
require_contains "$installer" 'cp --no-dereference --archive --no-target-directory -- "$checksum_arg" "$checksum"'
require_contains "$installer" '[[ -f $archive && ! -L $archive && -r $archive ]]'
require_contains "$installer" '[[ -f $checksum && ! -L $checksum && -r $checksum ]]'
require_contains "$installer" 'tar --absolute-names -tzf "$archive"'
require_contains "$installer" 'tar --absolute-names -tvzf "$archive"'
require_absent "$installer" 'tar[[:space:]]+--absolute-names[[:space:]]+-x'
require_contains "$installer" 'require_safe_live_secret /etc/rustmistmcp/tokens.json'
require_contains "$installer" 'require_safe_live_secret /etc/rustmistmcp/audit-hmac.key'
require_contains "$installer" 'require_safe_live_secret /etc/rustmistmcp/mist-api-token'
require_contains "$installer" '[[ ! -L $path ]]'
require_contains "$installer" '[[ ! -e $path || -f $path ]]'
require_before "$installer" 'require_safe_live_secret /etc/rustmistmcp/tokens.json' 'apt-get update'
require_before "$installer" 'require_safe_live_secret /etc/rustmistmcp/audit-hmac.key' 'apt-get update'
require_before "$installer" 'require_safe_live_secret /etc/rustmistmcp/mist-api-token' 'apt-get update'
require_contains "$installer" 'apt-get update'
require_contains "$installer" 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl'
require_contains "$installer" '--validate-only'
require_contains "$installer" 'systemd-detect-virt'
require_contains "$installer" 'VERSION_ID'
require_contains "$installer" 'RUSTMISTMCP_LXC_HOST_PROOF'
require_contains "$installer" 'find -P'
require_contains "$installer" 'realpath'
require_contains "$installer" '/etc/rustmistmcp/tokens.json'
require_contains "$installer" '/etc/rustmistmcp/audit-hmac.key'
require_contains "$installer" 'install -m 0600'
require_contains "$installer" 'systemctl daemon-reload'
require_absent "$installer" 'systemctl enable'

require_contains scripts/build-release.sh 'git status --porcelain=v1 --untracked-files=all'
require_contains scripts/build-release.sh 'umask 022'
require_contains scripts/build-release.sh 'CARGO_TARGET_DIR'
require_contains scripts/build-release.sh 'RUSTMISTMCP_CI_SOURCE_VERIFIED'
require_contains scripts/build-release.sh 'RUSTMISTMCP_COMMIT'
require_contains scripts/build-release.sh 'RUSTMISTMCP_RELEASE_VERSION'
require_contains scripts/build-release.sh 'SOURCE_DATE_EPOCH'
require_contains scripts/build-release.sh 'gzip -n'
require_contains scripts/build-release.sh 'BUILD-INFO'
require_contains scripts/build-release.sh 'docs/OPERATIONS.md'
require_contains scripts/build-release.sh 'docs/PACKAGING_ACCEPTANCE.md'
require_contains scripts/smoke-release-archive.sh 'cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive"'
require_contains scripts/smoke-release-archive.sh 'cp --no-dereference --archive --no-target-directory -- "$sidecar_arg" "$sidecar"'
require_contains scripts/smoke-release-archive.sh '[[ -f $archive && ! -L $archive && -r $archive ]]'
require_contains scripts/smoke-release-archive.sh '[[ -f $sidecar && ! -L $sidecar && -r $sidecar ]]'
require_absent scripts/smoke-release-archive.sh 'tar[[:space:]]+--absolute-names[[:space:]]+-x'

while IFS= read -r action_line; do
    if [[ ! $action_line =~ uses:[[:space:]]+[^[:space:]@]+@[0-9a-f]{40}[[:space:]]*$ ]]; then
        printf 'workflow action is not pinned to exactly 40 hex: %s\n' "$action_line" >&2
        failures=$((failures + 1))
    fi
done < <(rg '^[[:space:]]*-[[:space:]]+uses:' .github/workflows -g '*.yml' -g '*.yaml' | cut -d: -f2-)
require_contains .github/workflows/ci.yml 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
require_contains .github/workflows/release.yml 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
require_contains .github/workflows/security.yml 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
for workflow in .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/security.yml; do
    if ! awk '
        function finish_checkout() {
            if (in_checkout && !credentials_disabled) {
                exit 1
            }
            in_checkout = 0
            credentials_disabled = 0
        }
        /^[[:space:]]*-[[:space:]]+uses:[[:space:]]+actions\/checkout@/ {
            finish_checkout()
            in_checkout = 1
            checkout_indent = match($0, /[^[:space:]]/) - 1
            next
        }
        in_checkout {
            current_indent = match($0, /[^[:space:]]/) - 1
            if ($0 ~ /^[[:space:]]*-[[:space:]]+/ && current_indent == checkout_indent) {
                finish_checkout()
                next
            }
            if ($0 ~ /^[[:space:]]+persist-credentials:[[:space:]]+false[[:space:]]*$/) {
                credentials_disabled = 1
            }
        }
        END {
            finish_checkout()
        }
    ' "$workflow"; then
        printf 'every checkout must set persist-credentials:false: %s\n' "$workflow" >&2
        failures=$((failures + 1))
    fi
done
require_contains .github/workflows/release.yml 'linux/amd64,linux/arm64'
require_contains .github/workflows/release.yml 'provenance: mode=max'
require_contains .github/workflows/release.yml 'sbom: true'
require_contains .github/workflows/release.yml "tags: ['v*-rc*']"
require_contains .github/workflows/release.yml 'needs: verify'
require_contains .github/workflows/release.yml 'Validate RC tag against Cargo version'
require_contains .github/workflows/release.yml 'rust:1.97.0-slim-bookworm@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d'
require_absent .github/workflows/ci.yml '--version'
require_absent .github/workflows/release.yml '--version'
require_contains .github/workflows/ci.yml '--help'
require_contains .github/workflows/ci.yml 'rustup toolchain install 1.88.0 --profile minimal'
require_contains .github/workflows/ci.yml 'scripts/smoke-oci.sh'
require_contains .github/workflows/ci.yml 'RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh'
require_contains .github/workflows/release.yml 'RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh'
require_contains .github/workflows/security.yml 'gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e'
require_contains .github/workflows/security.yml 'GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}'
require_contains .github/workflows/security.yml 'GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}'
require_contains .github/workflows/release.yml 'actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f'
require_contains .github/workflows/release.yml 'actions/attest-build-provenance@96278af6caaf10aea03fd8d33a09a777ca52d62f'
require_regex .github/workflows/release.yml '^permissions: \{\}$'
require_count .github/workflows/release.yml 'contents: read' 3
require_count .github/workflows/release.yml 'packages: write' 1
require_count .github/workflows/release.yml 'id-token: write' 1
require_count .github/workflows/release.yml 'attestations: write' 1
require_contains .github/workflows/release.yml 'cargo +1.88.0 check --workspace --locked'
require_contains .github/workflows/release.yml 'cargo doc --workspace --no-deps --locked'
require_contains .github/workflows/release.yml 'cargo audit'
require_contains .github/workflows/release.yml 'cargo deny check'
require_contains .github/workflows/release.yml 'scripts/verify-reproducible-build.sh'
require_contains .github/workflows/release.yml 'npm exec --yes --package=yaml@2.8.1 yaml -- valid "$file"'
require_contains .github/workflows/release.yml 'gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e'
require_contains .github/workflows/release.yml 'GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}'
require_contains .github/dependabot.yml 'package-ecosystem: "github-actions"'
require_contains .github/dependabot.yml 'package-ecosystem: "docker"'
require_contains deny.toml '"MIT-0"'

require_contains README.md 'The Mist vendor API supports API tokens and external OAuth 2.0.'
require_contains README.md 'rustmistmcp v1 intentionally implements API-token authentication only'
require_contains README.md '| **Mist REST client, API-token auth, response models, tool surface** | **this repo** |'
require_absent README.md 'Mist REST client, token/OAuth auth'
require_contains CLAUDE.md 'Mist supports API tokens and external OAuth 2.0, but rustmistmcp v1 intentionally implements API-token authentication only.'
require_absent README.md 'Grant-bearing Mist token'
require_absent README.md 'grant-bearing Mist token'
require_contains README.md 'Grant-bearing MCP bearer-token add/list/revoke/rotate'
require_contains CLAUDE.md 'Grant-bearing MCP bearer-token lifecycle is blocked by'
require_contains docs/OPERATIONS.md 'sudo install -D -o root -g rustmistmcp -m 0640'
require_contains docs/OPERATIONS.md 'sudo install -o rustmistmcp -g rustmistmcp -m 0600 /dev/null'
require_contains docs/OPERATIONS.md '/etc/rustmistmcp/mist-api-token'
require_contains docs/OPERATIONS.md '/etc/rustmistmcp/tokens.json'
require_contains docs/OPERATIONS.md '/etc/rustmistmcp/audit-hmac.key'
require_contains docs/OPERATIONS.md 'organization-owned repository requires an encrypted `GITLEAKS_LICENSE`'
require_contains README.md '`/etc/rustmistmcp/mist.json` | `root:rustmistmcp`, `0640`'
require_contains README.md '`/etc/rustmistmcp/mist-api-token` | `rustmistmcp:rustmistmcp`, `0600`'
require_contains README.md '`/etc/rustmistmcp/tokens.json` | `rustmistmcp:rustmistmcp`, `0600`'
require_contains README.md '`/etc/rustmistmcp/audit-hmac.key` | `rustmistmcp:rustmistmcp`, `0600`'

if ! cmp -s examples/mist.example.json packaging/examples/mist.example.json; then
    printf '%s\n' 'packaging Mist example must match checked-in runtime example' >&2
    failures=$((failures + 1))
fi

if ! scripts/test-lxc-installer.sh; then
    printf '%s\n' 'LXC installer behavioral validation failed' >&2
    failures=$((failures + 1))
fi

runtime_binary=${RUSTMISTMCP_BINARY:-target/debug/rustmistmcp}
if [[ ! -x $runtime_binary ]]; then
    printf 'runtime command smoke binary is missing: %s\n' "$runtime_binary" >&2
    failures=$((failures + 1))
elif ! "$runtime_binary" \
    --device-mapping /etc/rustmistmcp/mist.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30030 \
    --tokens-file /etc/rustmistmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac \
    --audit-hmac-key-file /etc/rustmistmcp/audit-hmac.key \
    --help >/dev/null; then
    printf '%s\n' 'packaged runtime command does not parse' >&2
    failures=$((failures + 1))
fi

if rg -n 'Command::new' --glob '*.rs' crates/*/src; then
    printf '%s\n' 'runtime process spawning is incompatible with the distroless contract' >&2
    failures=$((failures + 1))
fi

if (( failures > 0 )); then
    printf 'packaging policy: FAIL (%d violation(s))\n' "$failures" >&2
    exit 1
fi
printf 'packaging policy: PASS\n'
