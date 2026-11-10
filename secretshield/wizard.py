"""Interactive shell setup wizard for SecretShield."""

from pathlib import Path
import shutil
import sys
from typing import Any, Dict, Optional

from secretshield.config import (
    ShieldConfig,
    ensure_gitignored,
    get_default_aws_region,
    get_default_gcp_project,
    save_config,
)
from secretshield.hooks.installer import install_git_hooks
from secretshield.vault import VAULT_PROVIDERS, get_vault_provider

# Styling
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RED = "\033[91m"
DIM = "\033[2m"


def _prompt(question: str, default: str = "") -> str:
    """Prompt the user with an optional default value."""
    if default:
        p_str = f"  {BOLD}{question}{RESET} [{CYAN}{default}{RESET}]: "
    else:
        p_str = f"  {BOLD}{question}{RESET}: "

    try:
        if sys.stdin.isatty():
            ans = input(p_str).strip()
        else:
            with open("/dev/tty", "r") as tty_in, open("/dev/tty", "w") as tty_out:
                tty_out.write(p_str)
                tty_out.flush()
                ans = tty_in.readline().strip()
        return ans if ans else default
    except Exception:
        return default


def _prompt_choice(title: str, options: list, default_idx: int = 1) -> int:
    """Prompt user to choose one option from a numbered list."""
    print(f"\n  {BOLD}{title}:{RESET}")
    for i, opt in enumerate(options, start=1):
        is_def = " (Recommended)" if i == default_idx else ""
        print(f"    [{i}] {opt}{GREEN}{is_def}{RESET}")

    while True:
        val = _prompt(f"Select option [1-{len(options)}]", default=str(default_idx))
        try:
            choice = int(val)
            if 1 <= choice <= len(options):
                return choice
        except ValueError:
            pass
        print(f"  {RED}Invalid choice '{val}'. Please enter a number between 1 and {len(options)}.{RESET}")


def run_setup_wizard(repo_root: Optional[Path] = None) -> ShieldConfig:
    """Run interactive setup wizard in the terminal."""
    root = repo_root or Path.cwd()

    print(f"""
{CYAN}{BOLD}========================================================================
   🛡️   SECRETSHIELD SETUP WIZARD — PREVENT EXPOSING HARDCODED SECRETS
========================================================================{RESET}
Welcome to SecretShield! This wizard will configure automated secret detection,
Git hooks, and cloud key vault integrations (Google KMS/GSM, AWS, Azure, HashiCorp).
""")

    # Check installed tools in environment
    has_gitleaks = bool(shutil.which("gitleaks"))
    has_trufflehog = bool(shutil.which("trufflehog"))
    has_gcloud = bool(shutil.which("gcloud"))
    has_aws = bool(shutil.which("aws"))
    has_az = bool(shutil.which("az"))
    has_vault = bool(shutil.which("vault"))

    print(f"  {DIM}Detected Environment Tools:{RESET}")
    print(f"    Gitleaks: {'✔ Found' if has_gitleaks else '✖ Not installed'} | TruffleHog: {'✔ Found' if has_trufflehog else '✖ Not installed'}")
    print(f"    gcloud: {'✔ Found' if has_gcloud else '✖ Not installed'} | AWS CLI: {'✔ Found' if has_aws else '✖ Not installed'} | Azure CLI: {'✔ Found' if has_az else '✖ Not installed'} | Vault: {'✔ Found' if has_vault else '✖ Not installed'}")

    # 1. Scanner engine selection
    scanner_opts = [
        "Auto (Use Gitleaks/TruffleHog if present, native Python fallback)",
        "Gitleaks (CLI)",
        "TruffleHog (CLI)",
        "Native Python (Zero external dependencies)",
    ]
    scanner_choice = _prompt_choice("Step 1: Choose Secret Scanner Engine", scanner_opts, default_idx=1)
    scanner_map = {1: "auto", 2: "gitleaks", 3: "trufflehog", 4: "native"}
    selected_scanner = scanner_map[scanner_choice]

    # 2. Key Vault Provider selection
    vault_opts = [
        "Google Cloud Secret Manager (GSM)",
        "Google Cloud KMS (Envelope Encryption)",
        "HashiCorp Vault KV",
        "AWS Secrets Manager",
        "Azure Key Vault",
        "Local Env File (.env.staging / .env.local)",
    ]
    vault_choice = _prompt_choice("Step 2: Choose Key Vault Provider", vault_opts, default_idx=1)
    vault_map = {
        1: "google_secret_manager",
        2: "google_kms",
        3: "hashicorp_vault",
        4: "aws_secrets_manager",
        5: "azure_keyvault",
        6: "local_env",
    }
    selected_vault = vault_map[vault_choice]
    vault_config: Dict[str, Any] = {}

    # 3. Vault-specific details
    print(f"\n  {BOLD}Step 3: Configure {vault_opts[vault_choice-1]} Parameters{RESET}")

    if selected_vault == "google_secret_manager":
        default_proj = get_default_gcp_project()
        proj = _prompt("Google Cloud Project ID", default=default_proj or "")
        vault_config["project_id"] = proj
        vault_config["auto_create"] = True

    elif selected_vault == "google_kms":
        default_proj = get_default_gcp_project()
        proj = _prompt("Google Cloud Project ID", default=default_proj or "")
        loc = _prompt("KMS Location (e.g. global, us-central1, europe-west1)", default="global")
        ring = _prompt("KMS Keyring Name", default="secretshield-ring")
        key = _prompt("KMS CryptoKey Name", default="secretshield-key")
        vault_config["project_id"] = proj
        vault_config["location"] = loc
        vault_config["keyring"] = ring
        vault_config["key"] = key

    elif selected_vault == "hashicorp_vault":
        addr = _prompt("Vault Server Address (VAULT_ADDR)", default="http://127.0.0.1:8200")
        mount = _prompt("Secret Mount Path", default="secret")
        vault_config["vault_addr"] = addr
        vault_config["mount_path"] = mount
        vault_config["kv_version"] = 2

    elif selected_vault == "aws_secrets_manager":
        def_region = get_default_aws_region()
        region = _prompt("AWS Region", default=def_region or "us-east-1")
        vault_config["region"] = region

    elif selected_vault == "azure_keyvault":
        vname = _prompt("Azure Key Vault Name", default="")
        vault_config["vault_name"] = vname

    elif selected_vault == "local_env":
        target = _prompt("Target Local Env File", default=".env.staging")
        vault_config["target_file"] = target

    # 4. Remediation Mode
    mode_opts = [
        "Interactive Agent (preview colored diff and choose vault/ignore per secret)",
        "Auto-Remediate (automatically upload to vault and replace in code)",
        "Warn Only (display detected secrets but do not modify code)",
    ]
    mode_choice = _prompt_choice("Step 4: Choose Default Remediation Mode", mode_opts, default_idx=1)
    mode_map = {1: "interactive", 2: "auto", 3: "warn"}
    selected_mode = mode_map[mode_choice]

    # Build config object
    config = ShieldConfig(
        scanner_type=selected_scanner,
        vault_provider=selected_vault,
        vault_config=vault_config,
        remediation_mode=selected_mode,
        entropy_threshold=4.0,
        fail_on_detection=True,
    )

    # 5. Test vault connection
    print(f"\n  {BOLD}Step 5: Testing Vault Connection...{RESET}")
    provider = get_vault_provider(selected_vault, config, root)
    avail, avail_msg = provider.is_available()
    if avail:
        print(f"    {GREEN}✔ Prerequisites:{RESET} {avail_msg}")
        ok, test_msg = provider.test_connection()
        if ok:
            print(f"    {GREEN}✔ Connection Test:{RESET} {test_msg}")
        else:
            print(f"    {YELLOW}⚠ Connection Test Warning:{RESET} {test_msg}")
            print(f"    {DIM}(You can proceed and configure credentials later){RESET}")
    else:
        print(f"    {YELLOW}⚠ Prerequisites Note:{RESET} {avail_msg}")

    # 6. Save configuration to .secretshield.json
    cfg_path = save_config(config, root / ".secretshield.json")
    print(f"\n  {GREEN}✔ Configuration saved to {cfg_path}{RESET}")

    # Ensure .secretshield.json is added to .gitignore
    if ensure_gitignored(root, ".secretshield.json", comment="SecretShield local configuration"):
        print(f"  {GREEN}✔ Added .secretshield.json to .gitignore{RESET}")

    # Ensure .secretshieldignore exists
    ignore_path = root / ".secretshieldignore"
    if not ignore_path.exists():
        default_ignore = """# SecretShield Ignore Rules
node_modules/
.git/
*.log
*.lock
package-lock.json
pnpm-lock.yaml
yarn.lock
tests/fixtures/
"""
        ignore_path.write_text(default_ignore, encoding="utf-8")
        print(f"  {GREEN}✔ Created default {ignore_path}{RESET}")

    # 7. Git Hooks Installation
    print(f"\n  {BOLD}Step 6: Git Hook Integration{RESET}")
    install_hooks_choice = _prompt("Install SecretShield Git hooks (pre-commit & pre-push) now? [Y/n]", default="y")
    if install_hooks_choice.lower() in ("y", "yes"):
        res = install_git_hooks(root)
        if res:
            print(f"  {GREEN}✔ Git hooks installed successfully into .git/hooks/ !{RESET}")
        else:
            print(f"  {YELLOW}⚠ Git hooks could not be installed (is this a Git repo?).{RESET}")

    print(f"""
{GREEN}{BOLD}========================================================================
   🎉  SECRETSHIELD CONFIGURED SUCCESSFULLY!
========================================================================{RESET}
Summary:
  • Scanner:      {BOLD}{selected_scanner}{RESET}
  • Vault:        {BOLD}{provider.display_name}{RESET}
  • Mode:         {BOLD}{selected_mode}{RESET}
  • Config File:  {BOLD}.secretshield.json{RESET}

Try running:
  • Scan staged files:    {CYAN}secretshield scan --staged{RESET}
  • Scan full repo:       {CYAN}secretshield scan --all{RESET}
  • Test vault provider:  {CYAN}secretshield test-vault{RESET}
  • Launch setup wizard:  {CYAN}secretshield setup{RESET}
""")
    return config
