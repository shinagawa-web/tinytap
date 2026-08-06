#!/bin/sh
# curl -fsSL https://raw.githubusercontent.com/shinagawa-web/tinytap/main/scripts/install.sh | sh
#
# Detects Linux amd64/arm64, downloads the matching GoReleaser archive from
# the latest (or pinned) GitHub release, verifies its SHA-256 checksum, and
# installs the `tinytap` binary. POSIX sh only (no bashisms) since the
# target machine's shell isn't guaranteed to be bash.
#
# Env overrides:
#   TINYTAP_VERSION   pin a release tag (e.g. v0.6.2) instead of latest
#   INSTALL_DIR        install directory (default /usr/local/bin)

set -eu

repo="shinagawa-web/tinytap"
install_dir="${INSTALL_DIR:-/usr/local/bin}"

log() {
    printf '%s\n' "$*" >&2
}

fail() {
    log "error: $*"
    exit 1
}

fetch() {
    # fetch <url> <output-path>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail "need curl or wget to download tinytap"
    fi
}

os="$(uname -s)"
[ "$os" = "Linux" ] || fail "tinytap only runs on Linux (eBPF is a Linux kernel technology) — detected: $os. See the README's 'Where tinytap Runs' section for running it inside a Linux VM."

arch="$(uname -m)"
case "$arch" in
    x86_64 | amd64)
        arch="amd64"
        ;;
    aarch64 | arm64)
        arch="arm64"
        ;;
    *)
        fail "unsupported architecture: $arch (tinytap ships linux/amd64 and linux/arm64 only)"
        ;;
esac

version="${TINYTAP_VERSION:-}"
if [ -z "$version" ]; then
    log "Looking up latest tinytap release..."
    latest_url="https://api.github.com/repos/${repo}/releases/latest"
    tmp_latest="$(mktemp)"
    trap 'rm -f "$tmp_latest"' EXIT
    fetch "$latest_url" "$tmp_latest" || fail "could not reach $latest_url"
    version="$(grep -o '"tag_name": *"[^"]*"' "$tmp_latest" | head -n1 | cut -d'"' -f4)"
    rm -f "$tmp_latest"
    trap - EXIT
    [ -n "$version" ] || fail "could not determine latest release version from $latest_url"
fi

version_number="${version#v}"
archive="tinytap_${version_number}_linux_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${version}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

log "Downloading ${archive} (${version})..."
fetch "${base_url}/${archive}" "${tmp_dir}/${archive}" || fail "download failed: ${base_url}/${archive}"
fetch "${base_url}/checksums.txt" "${tmp_dir}/checksums.txt" || fail "could not download checksums.txt for ${version}"

log "Verifying checksum..."
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp_dir" && sha256sum --check --ignore-missing checksums.txt) || fail "checksum verification failed for ${archive}"
elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmp_dir" && shasum -a 256 --check --ignore-missing checksums.txt) || fail "checksum verification failed for ${archive}"
else
    fail "need sha256sum or shasum to verify the downloaded archive"
fi

log "Extracting..."
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir" tinytap

if [ -w "$install_dir" ]; then
    install -m 755 "${tmp_dir}/tinytap" "${install_dir}/tinytap"
elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 755 "${tmp_dir}/tinytap" "${install_dir}/tinytap"
else
    fail "${install_dir} is not writable and sudo is not available; set INSTALL_DIR to a writable path"
fi

log "Installed ${install_dir}/tinytap (${version})"
log "Run 'tinytap doctor' to check for missing capabilities, or see the README's 'Running without full root' section."
