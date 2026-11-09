# SecretShield Release & Public Launch Guide 🚀

This document outlines the step-by-step process for making SecretShield public on GitHub and distributing it globally via Homebrew.

---

## 1. Initial Public Repository Setup

1. **Create the public repository on GitHub**:
   - URL: `https://github.com/ronkrasnopolski/secretshield` (Public)

2. **Push your local commits**:
   ```bash
   git remote add origin https://github.com/ronkrasnopolski/secretshield.git
   git branch -M main
   git push -u origin main
   ```

3. **Create the First Release Tag (`v0.1.0`)**:
   ```bash
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```
   *Or go to GitHub -> Releases -> Draft a new release -> Tag `v0.1.0` -> Publish.*

---

## 2. Set Up the Homebrew Tap (`homebrew-secretshield`)

1. **Create a new public repository on GitHub**:
   - Repository name: `homebrew-secretshield`
   - URL: `https://github.com/ronkrasnopolski/homebrew-secretshield` (Public)

2. **Sync the Formula**:
   Run the automated sync script from the `secretshield` repository root:
   ```bash
   ./scripts/publish-tap.sh ronkrasnopolski 0.1.0
   ```

3. **Verify Public Installation**:
   Any user anywhere in the world on macOS or Linux can now install SecretShield via:
   ```bash
   brew tap ronkrasnopolski/secretshield
   brew install secretshield
   ```
   Or directly:
   ```bash
   brew install https://raw.githubusercontent.com/ronkrasnopolski/secretshield/main/Formula/secretshield.rb
   ```

---

## 3. Subsequent Version Releases (e.g. `v0.2.0`)

Whenever you prepare a new version:
1. Update `version = "0.2.0"` in `pyproject.toml` and `secretshield/__init__.py`.
2. Commit and tag:
   ```bash
   git commit -am "chore: bump version to v0.2.0"
   git tag v0.2.0
   git push origin main --tags
   ```
3. Update the tap formula:
   ```bash
   ./scripts/publish-tap.sh ronkrasnopolski 0.2.0
   ```
   *(If GitHub Actions CI is configured with `HOMEBREW_TAP_TOKEN`, this step happens automatically).*
