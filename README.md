# 🛡️ SecretShield

> **Zero-Expose Git Guard & Automated Cloud Key Vault Remediation Agent**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)](pyproject.toml)
[![Git Hooks](https://img.shields.io/badge/hooks-pre--commit%20%7C%20pre--push-orange.svg)](#git-hooks-integration)
[![Zero Dependency](https://img.shields.io/badge/dependencies-zero%20pip-success.svg)](#installation)

SecretShield is an open-source security tool and Git hook agent that intercepts hardcoded secrets (API keys, database credentials, tokens, private keys) in source code, `.env` files, YAML, and JSON *before* they can ever be committed or pushed to remote repositories.

Instead of merely failing your commit, **SecretShield automatically or interactively migrates the exposed secret directly to your connected Cloud Key Vault (Google Secret Manager, Google Cloud KMS, HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault)** and replaces the plaintext secret in your code with clean environment variable references or encrypted envelopes.

---

## 🌟 Key Features

- 🔍 **Multi-Scanner Architecture**: Wraps industry standards ([Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog)) with an ultra-fast **Native Python regex + Shannon entropy fallback** that requires **zero** external binary or pip dependencies.
- ⚡ **Auto-Remediation & TTY Agent**:
  - Live colored diff preview directly in your terminal.
  - Interactive selection: Migrate to Cloud Vault, Encrypt via KMS Envelope, Save to Local `.env.staging`, or Replace with Env Var placeholder.
  - Automatically re-stages remediated files so your commit continues cleanly.
- 🔐 **Multi-Vault Cloud Integrations**:
  - **Google Cloud Secret Manager (GSM)**: Versioned secret payloads (`gsm://projects/.../secrets/...`).
  - **Google Cloud KMS**: Direct envelope encryption with base64 ciphertexts (`kms://projects/.../cryptoKeys/...`).
  - **HashiCorp Vault KV**: v1 / v2 Secret Engine storage (`vault://secret/data/...#value`).
  - **AWS Secrets Manager**: Region-aware secret creation & updates (`aws-sm://...`).
  - **Azure Key Vault**: Azure secret set (`azure-kv://...`).
  - **Local Env Fallback**: Safely extracts to `.env.staging` / `.env.local` and adds them to `.gitignore`.
- 🪝 **Git Hooks (`pre-commit` & `pre-push`)**: Intercepts staged diffs and unpushed commit ranges before code ever leaves your machine.
- 🧙‍♂️ **Interactive Shell Setup Wizard**: Fast `secretshield setup` CLI menu that auto-detects existing CLI tools, GCP project IDs, AWS regions, and generates `.secretshield.json`.

---

## 🏗️ Architecture & Workflow

```mermaid
flowchart TD
    A["Developer Runs: git commit -m 'feat: add stripe integration'"] --> B["SecretShield Pre-Commit Hook"]
    B --> C{"Inspect Staged Diff / Files"}
    C --> D["Multi-Scanner Engine\n(Gitleaks / TruffleHog / Native)"]
    D --> E{"Exposed Secret Detected?"}
    E -- No --> F["✔ Git Commit Allowed"]
    E -- Yes --> G["🚨 Interactive Remediation Agent"]
    
    G --> H["[1] Migrate to Cloud Secret Manager\n(Google GSM / AWS SM / Azure KV / Vault)"]
    G --> I["[2] Encrypt via KMS Envelope\n(Google KMS)"]
    G --> J["[3] Save to Local .env.staging\n(Auto-gitignored)"]
    G --> K["[4] Replace with Env Var Placeholder"]
    G --> L["[5] Ignore / SecretShieldIgnore"]
    G --> M["[6] Abort Commit"]
    
    H --> N["Rewrite Code Syntax\n(JS/TS, Python, Go, YAML, .env)"]
    I --> N
    J --> N
    K --> N
    
    N --> O["Auto Re-Stage Clean Files (git add)"]
    O --> F
```

---

## 🚀 Quickstart & Installation

### Option 1: Install with Homebrew (Recommended for macOS & Linux)
```bash
# Add Homebrew Tap and install
brew tap ronkrasnopolski/secretshield
brew install secretshield

# Or install in a single command:
brew install ronkrasnopolski/secretshield/secretshield

# To install from local source formula:
brew install --formula Formula/secretshield.rb
```

### Option 2: One-Line Install Script
```bash
curl -sSL https://raw.githubusercontent.com/ronkrasnopolski/secretshield/main/install.sh | bash
```

### Option 3: Clone & Local Setup
```bash
git clone https://github.com/ronkrasnopolski/secretshield.git
cd secretshield

# Run setup wizard in any repository:
./bin/secretshield setup
```

### Option 4: Python Pip / Editable Install
```bash
pip install -e .

# Run wizard
secretshield setup
```

---

## 🧙‍♂️ Interactive Setup Wizard (`secretshield setup`)

Running `secretshield setup` launches an interactive terminal wizard that configures your repository in seconds:

```text
========================================================================
   🛡️   SECRETSHIELD SETUP WIZARD — PREVENT EXPOSING HARDCODED SECRETS
========================================================================

  Detected Environment Tools:
    Gitleaks: ✔ Found | TruffleHog: ✖ Not installed
    gcloud: ✔ Found | AWS CLI: ✔ Found | Azure CLI: ✖ Not installed | Vault: ✖ Not installed

  Step 1: Choose Secret Scanner Engine:
    [1] Auto (Use Gitleaks/TruffleHog if present, native Python fallback) (Recommended)
    [2] Gitleaks (CLI)
    [3] TruffleHog (CLI)
    [4] Native Python (Zero external dependencies)

  Step 2: Choose Key Vault Provider:
    [1] Google Cloud Secret Manager (GSM) (Recommended)
    [2] Google Cloud KMS (Envelope Encryption)
    [3] HashiCorp Vault KV
    [4] AWS Secrets Manager
    [5] Azure Key Vault
    [6] Local Env File (.env.staging / .env.local)

  Step 3: Configure Parameters (Auto-detects GCP project / AWS region)
  Step 4: Remediation Mode (Interactive / Auto / Warn)
  Step 5: Testing Vault Connection... ✔ Connection Test Passed!
  Step 6: Git Hook Integration: Install into .git/hooks/? [Y/n]
```

---

## 🪝 Git Hooks Integration

To manually install or update Git hooks into your active repository:

```bash
# Standard .git/hooks installation:
secretshield install-hooks

# Or team-shared .githooks directory (configures core.hooksPath):
secretshield install-hooks --githooks-dir
```

When you attempt to commit a file containing a secret:

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🛡️  SECRETSHIELD ALERT: Secret Detected [1/1]                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
  File:       src/services/stripe.ts:14
  Detector:   native (Rule: stripe_secret_key)
  Secret:     sk_live_51M**************************************** (Entropy: 4.82)
  Hint:       STRIPE_SECRET_KEY

  Proposed Code Remediation:
  - const stripeKey = "sk_live_51M0123456789abcdefghijklmnopqrstuvwxyz"; # secretshield:ignore
  + const stripeKey = process.env.STRIPE_SECRET_KEY;

  Choose remediation action:
    [1] Migrate to Google Cloud Secret Manager & Replace in Code (Recommended)
    [2] Encrypt with Google Cloud KMS Envelope & Replace in Code
    [3] Save to Local Env (.env.staging) & Replace in Code
    [4] Replace with Environment Variable reference only (no vault upload)
    [5] Ignore this secret (add to .secretshieldignore)
    [6] Abort Git operation (block commit/push)

  Select option [1-6] (default: 1): 1
  Uploading to Google Cloud Secret Manager as 'STRIPE_SECRET_KEY'...
  ✔ Successfully secured! Reference: gsm://projects/my-prod/secrets/STRIPE_SECRET_KEY/versions/latest
  ✔ Re-staged clean version of src/services/stripe.ts

✔ All secrets remediated! Proceeding with commit.
```

---

## ⚙️ Configuration Reference (`.secretshield.json`)

The `.secretshield.json` file is stored at the root of your project:

```json
{
  "scanner_type": "auto",
  "vault_provider": "google_secret_manager",
  "vault_config": {
    "project_id": "my-gcp-project-id",
    "auto_create": true
  },
  "remediation_mode": "interactive",
  "custom_rules": [
    {
      "id": "internal_jwt_secret",
      "regex": "(?i)jwt_secret\\s*=\\s*['\"]([a-zA-Z0-9_-]{32,})['\"]",
      "hint": "JWT_SECRET",
      "min_entropy": 3.5
    }
  ],
  "entropy_threshold": 4.0,
  "fail_on_detection": true,
  "use_vault_uri_in_code": false
}
```

### Google Cloud KMS Configuration Example
```json
{
  "vault_provider": "google_kms",
  "vault_config": {
    "project_id": "my-gcp-project-id",
    "location": "global",
    "keyring": "secretshield-ring",
    "key": "secretshield-key"
  },
  "use_vault_uri_in_code": true
}
```

### HashiCorp Vault Configuration Example
```json
{
  "vault_provider": "hashicorp_vault",
  "vault_config": {
    "vault_addr": "http://127.0.0.1:8200",
    "mount_path": "secret",
    "kv_version": 2
  }
}
```

---

## 💻 CLI Commands

| Command | Description |
| :--- | :--- |
| `secretshield setup` / `init` | Run the interactive setup and vault onboarding wizard. |
| `secretshield scan --staged` | Scan staged Git changes (what will be committed). |
| `secretshield scan --all` | Scan entire workspace directory recursively. |
| `secretshield scan --path <dir/file>` | Scan a specific file or folder. |
| `secretshield scan --json` | Output detection results in machine-readable JSON format. |
| `secretshield scan --auto-remediate` | Automatically upload detected secrets to vault without prompt. |
| `secretshield test-vault` | Verify connectivity and credentials for the configured vault. |
| `secretshield install-hooks` | Install `pre-commit` and `pre-push` hooks into `.git/hooks/`. |

---

## 🔀 Language Syntax Transformations

SecretShield understands multi-language syntax and produces idiomatically correct replacements:

| File Type | Original Detected Code | Remediated Code |
| :--- | :--- | :--- |
| **TypeScript / JS** | `const token = "AIzaSy..."` | `const token = process.env.GOOGLE_API_KEY;` |
| **Python** | `api_key = "sk-live-..."` | `api_key = os.getenv("STRIPE_API_KEY", "")` |
| **Go** | `key := "ghp_..."` | `key := os.Getenv("GITHUB_TOKEN")` |
| **YAML / Helm** | `apiKey: "AIzaSy..."` | `apiKey: "${GOOGLE_API_KEY}"` |
| **Shell Script** | `AUTH_TOKEN="ghp_..."` | `AUTH_TOKEN="${GITHUB_TOKEN:-}"` |
| **Dotenv (.env)** | `DATABASE_URL=postgres://...` | `DATABASE_URL=  # Migrated to vault` |

---

## 🧪 Running Tests

SecretShield comes with an extensive standard library unit test suite:

```bash
# Run unit tests
python3 -m unittest discover -s tests -v
```

---

## 🤝 Contributing & License

Contributions are warmly welcome! Please open an issue or pull request.
Licensed under the [Apache License 2.0](LICENSE).
