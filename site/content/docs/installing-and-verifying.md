---
title: Installing & Verifying Releases
weight: 11
---

# Installing & Verifying Releases

## Installing a specific version or location

Two env vars change the install script's behavior. Set them on the `sh`
side of the pipe, not before `curl`, since a `VAR=val curl ... | sh` prefix
only reaches `curl`, not the piped-in script:

```bash
curl -fsSL https://raw.githubusercontent.com/shinagawa-web/tinytap/main/scripts/install.sh | TINYTAP_VERSION=v0.6.1 sh   # pin a release instead of the latest
curl -fsSL https://raw.githubusercontent.com/shinagawa-web/tinytap/main/scripts/install.sh | INSTALL_DIR=~/bin sh       # install somewhere other than /usr/local/bin
```

## Verifying a release download

The install script already verifies the downloaded archive's SHA-256
checksum automatically. This section is for downloading a release archive
by hand instead (from the
[releases page](https://github.com/shinagawa-web/tinytap/releases) or in a
script that intentionally avoids `curl | sh`) and confirming its full chain
of trust, including the cosign signature the install script doesn't check.

Every tagged release publishes, alongside the `linux_amd64`/`linux_arm64` archives:

- `checksums.txt`: SHA-256 of every archive and SBOM in the release

- `checksums.txt.sigstore.json`: a keyless [cosign](https://docs.sigstore.dev/cosign/overview/) signature over `checksums.txt`, minted from the release workflow's own GitHub Actions OIDC identity (no private key is stored anywhere)

- `<archive>.sbom.json`: an SBOM for each archive ([syft](https://github.com/anchore/syft), SPDX format)

- `multiple.intoto.jsonl`: SLSA build provenance, attesting which source commit and workflow run produced these artifacts

To verify the full chain of trust manually instead of trusting the script:

```bash
sha256sum --check --ignore-missing checksums.txt
```

Verify `checksums.txt` itself was produced by tinytap's release workflow
(requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3+):

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "^https://github.com/shinagawa-web/tinytap/\.github/workflows/release\.yml@refs/tags/v.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Since every archive and SBOM is listed by digest inside `checksums.txt`, a
passing `cosign verify-blob` on `checksums.txt` plus a passing `sha256sum
--check` on the archive establishes the whole chain: this exact archive
came from this exact release workflow run.
