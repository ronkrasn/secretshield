#!/usr/bin/env bash
# Publish / Sync SecretShield Homebrew Tap Repository
# Usage: ./scripts/publish-tap.sh [github_username] [version] [--dry-run]
# Example: ./scripts/publish-tap.sh ronkrasnopolski 0.1.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FORMULA_SOURCE="${REPO_ROOT}/Formula/secretshield.rb"

USERNAME="${1:-ronkrasnopolski}"
DRY_RUN=0

# Parse arguments
VERSION=""
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        DRY_RUN=1
    elif [ -z "$VERSION" ] && [ "$arg" != "$USERNAME" ]; then
        VERSION="${arg#v}"
    fi
done

if [ -z "$VERSION" ]; then
    VERSION=$(grep -E '^version\s*=\s*' "${REPO_ROOT}/pyproject.toml" | head -n 1 | sed -E 's/version\s*=\s*"([^"]+)".*/\1/')
fi

TAP_REPO="homebrew-secretshield"
TAP_URL="https://github.com/${USERNAME}/${TAP_REPO}.git"

echo "========================================================================"
echo "      🛡️  SECRETSHIELD HOMEBREW TAP PUBLISHER & SYNC"
echo "========================================================================"
echo "  GitHub User:  ${USERNAME}"
echo "  Version:      ${VERSION}"
echo "  Tap Repo:     ${USERNAME}/${TAP_REPO}"
echo "  Source File:  ${FORMULA_SOURCE}"
echo "========================================================================"

# Update formula checksum first
"${SCRIPT_DIR}/update-formula.sh" "${VERSION}" "${USERNAME}/secretshield"

if [ "${DRY_RUN}" = "1" ]; then
    echo -e "\n[Dry-Run Mode] Formula verified. Ready to sync to ${TAP_URL}."
    exit 0
fi

TEMP_DIR=$(mktemp -d /tmp/secretshield-tap-XXXXXX)
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo -e "\nCloning tap repository from ${TAP_URL}..."
if git clone "${TAP_URL}" "${TEMP_DIR}" 2>/dev/null; then
    echo "  ✔ Found existing tap repository."
else
    echo "  Notice: Tap repository not cloned. Initializing new local tap directory..."
    mkdir -p "${TEMP_DIR}"
    git -C "${TEMP_DIR}" init
    git -C "${TEMP_DIR}" remote add origin "${TAP_URL}" || true
fi

# Copy Formula
mkdir -p "${TEMP_DIR}/Formula"
cp "${FORMULA_SOURCE}" "${TEMP_DIR}/Formula/secretshield.rb"

# Create a clean README for the tap
cat << 'EOF' > "${TEMP_DIR}/README.md"
# Homebrew Tap for SecretShield 🛡️

Official Homebrew tap for [SecretShield](https://github.com/ronkrasnopolski/secretshield) — Zero-Expose Git Guard & Automated Cloud Key Vault Remediation Agent.

## Installation

```bash
brew tap ronkrasnopolski/secretshield
brew install secretshield
```

Or install in a single command:
```bash
brew install ronkrasnopolski/secretshield/secretshield
```

## Documentation

See the main [SecretShield Repository](https://github.com/ronkrasnopolski/secretshield) for full usage instructions and key vault integrations.
EOF

# Git commit and push instructions
cd "${TEMP_DIR}"
git add Formula/secretshield.rb README.md
if git diff --staged --quiet; then
    echo "✔ Tap repository is already up to date with version ${VERSION}!"
else
    git commit -m "Update secretshield formula to v${VERSION}"
    echo -e "\nReady to push formula to GitHub. Run the following command if not pushed automatically:"
    echo -e "  cd ${TEMP_DIR} && git push origin main\n"
    
    if git push origin main 2>/dev/null; then
        echo "✔ Successfully pushed v${VERSION} formula to ${TAP_URL}!"
    else
        echo "Notice: Could not push automatically (authentication or remote repo creation required)."
        echo "To finish, create the public repository 'https://github.com/${USERNAME}/${TAP_REPO}' on GitHub,"
        echo "then push the generated tap directory."
    fi
fi
