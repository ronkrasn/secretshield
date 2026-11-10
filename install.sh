#!/usr/bin/env bash
# SecretShield One-Line Installer & Setup Script
# Usage: curl -sSL https://raw.githubusercontent.com/ronkrasn/secretshield/main/install.sh | bash
#    or: ./install.sh

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[92m"
YELLOW="\033[93m"
CYAN="\033[96m"
RED="\033[91m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "          🛡️   INSTALLING SECRETSHIELD REPO GUARD & VAULT AGENT"
echo "========================================================================"
echo -e "${RESET}"

# Check Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}Error: Python 3.8+ is required but not found in PATH.${RESET}"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "  ✔ Found Python ${BOLD}${PY_VERSION}${RESET}"

# Check Git
if ! command -v git >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Git is not installed. SecretShield Git hooks will be inactive.${RESET}"
fi

# Determine install location
TARGET_DIR="${HOME}/.secretshield"
BIN_DIR="${HOME}/.local/bin"

mkdir -p "${BIN_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If brew is installed and formula exists locally, prefer brew if requested
if [ -f "${SCRIPT_DIR}/Formula/secretshield.rb" ] && command -v brew >/dev/null 2>&1 && [ "${USE_BREW:-0}" = "1" ]; then
    echo -e "  Installing via Homebrew formula..."
    brew install --build-from-source "${SCRIPT_DIR}/Formula/secretshield.rb"
elif [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
    echo -e "  Installing from local source at ${SCRIPT_DIR}..."
    python3 -m pip install --quiet --upgrade pip || true
    python3 -m pip install --quiet -e "${SCRIPT_DIR}" || {
        # Fallback if pip install fails without virtualenv: symlink binary
        echo -e "  Creating symlink in ${BIN_DIR}/secretshield..."
        ln -sf "${SCRIPT_DIR}/bin/secretshield" "${BIN_DIR}/secretshield"
    }
else
    echo -e "  Cloning latest SecretShield repository to ${TARGET_DIR}..."
    rm -rf "${TARGET_DIR}"
    git clone --depth 1 https://github.com/ronkrasn/secretshield.git "${TARGET_DIR}"
    ln -sf "${TARGET_DIR}/bin/secretshield" "${BIN_DIR}/secretshield"
    python3 -m pip install --quiet -e "${TARGET_DIR}" 2>/dev/null || true
fi

# Ensure ~/.local/bin is in PATH reminder
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo -e "\n${YELLOW}Notice: Add ${BIN_DIR} to your PATH to run 'secretshield' directly:${RESET}"
    echo -e "  export PATH=\"${BIN_DIR}:\$PATH\""
fi

echo -e "\n${GREEN}${BOLD}✔ SecretShield installed successfully!${RESET}\n"

# Ensure .secretshield.json is added to .gitignore if in a git repository
if [ -d ".git" ] || [ -f ".gitignore" ]; then
    if [ -f ".gitignore" ]; then
        if ! grep -qs '^\.secretshield\.json' .gitignore && ! grep -qs '^/\.secretshield\.json' .gitignore; then
            echo -e "\n# SecretShield local configuration\n.secretshield.json" >> .gitignore
            echo -e "  ${GREEN}✔ Added .secretshield.json to .gitignore${RESET}"
        fi
    fi
fi

# Run setup wizard if interactive terminal
if [ -t 0 ]; then
    echo -e "Launching interactive setup wizard..."
    if command -v secretshield >/dev/null 2>&1; then
        secretshield setup
    elif [ -f "${BIN_DIR}/secretshield" ]; then
        "${BIN_DIR}/secretshield" setup
    else
        python3 -m secretshield setup
    fi
fi
