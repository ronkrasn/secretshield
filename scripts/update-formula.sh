#!/usr/bin/env bash
# Update Homebrew formula with new version and sha256 checksum
# Usage: ./scripts/update-formula.sh [version] [repo_owner/repo_name]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FORMULA_PATH="${REPO_ROOT}/Formula/secretshield.rb"

# Determine version
if [ $# -ge 1 ]; then
    VERSION="${1#v}"
else
    # Extract version from pyproject.toml
    VERSION=$(grep -E '^version\s*=\s*' "${REPO_ROOT}/pyproject.toml" | head -n 1 | sed -E 's/version\s*=\s*"([^"]+)".*/\1/')
fi

REPO="${2:-ronkrasnopolski/secretshield}"
TAG="v${VERSION}"
TARBALL_URL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"

echo "🛡️  Updating Homebrew Formula for SecretShield..."
echo "  Version: ${VERSION}"
echo "  Tag:     ${TAG}"
echo "  Repo:    ${REPO}"
echo "  URL:     ${TARBALL_URL}"

# Try to download tarball to calculate sha256, or calculate from local git archive
TMP_TARBALL=$(mktemp /tmp/secretshield-XXXXXX.tar.gz)
trap 'rm -f "${TMP_TARBALL}"' EXIT

if curl --output /dev/null --silent --head --fail "${TARBALL_URL}"; then
    echo "  Downloading release tarball from GitHub..."
    curl -sSL "${TARBALL_URL}" -o "${TMP_TARBALL}"
else
    echo "  Notice: Remote release tarball not yet published. Generating local git archive checksum..."
    git -C "${REPO_ROOT}" archive --format=tar.gz --prefix="secretshield-${VERSION}/" -o "${TMP_TARBALL}" HEAD
fi

SHA256=$(shasum -a 256 "${TMP_TARBALL}" | awk '{print $1}')
echo "  SHA256:  ${SHA256}"

# Update Formula/secretshield.rb
if [ -f "${FORMULA_PATH}" ]; then
    # Update URL
    sed -i '' -E "s|url \"https://github.com/[^/]+/[^/]+/archive/refs/tags/v[0-9.]+\.tar\.gz\"|url \"${TARBALL_URL}\"|g" "${FORMULA_PATH}" || sed -i -E "s|url \"https://github.com/[^/]+/[^/]+/archive/refs/tags/v[0-9.]+\.tar\.gz\"|url \"${TARBALL_URL}\"|g" "${FORMULA_PATH}"
    # Update SHA256
    sed -i '' -E "s/sha256 \"[a-f0-9]{64}\"/sha256 \"${SHA256}\"/g" "${FORMULA_PATH}" || sed -i -E "s/sha256 \"[a-f0-9]{64}\"/sha256 \"${SHA256}\"/g" "${FORMULA_PATH}"
    echo "✔ Successfully updated ${FORMULA_PATH}!"
else
    echo "Error: ${FORMULA_PATH} not found!" >&2
    exit 1
fi
