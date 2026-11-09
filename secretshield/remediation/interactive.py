"""Interactive remediation agent and terminal UI for SecretShield."""

from pathlib import Path
import sys
from typing import List, Optional, Tuple

from secretshield.config import ShieldConfig
from secretshield.remediation.engine import (
    RemediationPlan,
    apply_remediation_plan,
    create_remediation_plan,
    derive_env_var_name,
)
from secretshield.scanner.base import Finding
from secretshield.vault import get_vault_provider
from secretshield.vault.base import BaseVaultProvider, VaultResult

# ANSI styling constants
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"


def _get_tty_input(prompt: str = "") -> str:
    """Prompt user using /dev/tty if stdin is redirected (e.g. inside Git hooks)."""
    if sys.stdin.isatty():
        return input(prompt)
    try:
        with open("/dev/tty", "r") as tty_in, open("/dev/tty", "w") as tty_out:
            tty_out.write(prompt)
            tty_out.flush()
            line = tty_in.readline()
            return line.strip()
    except Exception:
        # Fallback to standard input
        try:
            return input(prompt)
        except EOFError:
            return ""


def print_finding_banner(idx: int, total: int, finding: Finding) -> None:
    """Print formatted alert box for a secret finding."""
    print(f"\n{RED}{BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{RESET}")
    print(f"{RED}{BOLD}┃ 🛡️  SECRETSHIELD ALERT: Secret Detected [{idx}/{total}]                          ┃{RESET}")
    print(f"{RED}{BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{RESET}")
    print(f"  {BOLD}File:{RESET}       {CYAN}{finding.file_path}{RESET}:{YELLOW}{finding.line_number}{RESET}")
    print(f"  {BOLD}Detector:{RESET}   {MAGENTA}{finding.detector}{RESET} (Rule: {finding.rule_id})")
    print(f"  {BOLD}Secret:{RESET}     {RED}{finding.masked_secret}{RESET} (Entropy: {finding.entropy:.2f})")
    if finding.hint:
        print(f"  {BOLD}Hint:{RESET}       {finding.hint}")


def print_diff_preview(original: str, proposed: str) -> None:
    """Print colored diff preview of the proposed change."""
    print(f"\n  {BOLD}Proposed Code Remediation:{RESET}")
    print(f"  {RED}- {original.strip()}{RESET}")
    print(f"  {GREEN}+ {proposed.strip()}{RESET}\n")


def add_to_secretshieldignore(finding: Finding, repo_root: Path) -> bool:
    """Append the file or line pattern to .secretshieldignore."""
    ignore_file = repo_root / ".secretshieldignore"
    try:
        entry = f"{finding.file_path}  # Ignored rule: {finding.rule_id}"
        prefix = "\n" if ignore_file.exists() and not ignore_file.read_text(encoding="utf-8").endswith("\n") else ""
        with open(ignore_file, "a", encoding="utf-8") as f:
            f.write(f"{prefix}{entry}\n")
        return True
    except Exception:
        return False


def run_interactive_remediation(
    findings: List[Finding],
    config: ShieldConfig,
    repo_root: Optional[Path] = None,
    auto_accept: bool = False,
) -> Tuple[bool, List[RemediationPlan]]:
    """
    Process findings interactively with the user or automatically based on config.
    Returns (all_resolved: bool, plans: List[RemediationPlan]).
    """
    root = repo_root or Path.cwd()
    plans: List[RemediationPlan] = []
    default_vault = get_vault_provider(config.vault_provider, config, root)

    for i, finding in enumerate(findings, start=1):
        print_finding_banner(i, len(findings), finding)
        env_var_name = derive_env_var_name(finding)
        draft_plan = create_remediation_plan(
            finding=finding,
            custom_env_var=env_var_name,
            repo_root=root,
        )
        print_diff_preview(draft_plan.original_line, draft_plan.proposed_line)

        if auto_accept or config.remediation_mode == "auto":
            print(f"  {CYAN}Auto-remediating secret with {default_vault.display_name}...{RESET}")
            vault_res = default_vault.store_secret(
                secret_name=env_var_name,
                secret_value=finding.secret_raw,
                metadata={"file": finding.file_path, "rule": finding.rule_id},
            )
            if not vault_res.success:
                print(f"  {RED}✖ Vault Error:{RESET} {vault_res.error}")
                return False, plans

            plan = create_remediation_plan(
                finding=finding,
                vault_result=vault_res,
                use_vault_uri=config.use_vault_uri_in_code,
                custom_env_var=env_var_name,
                repo_root=root,
            )
            success, err = apply_remediation_plan(plan)
            if success:
                print(f"  {GREEN}✔ Remediated & stored in {vault_res.reference_uri}{RESET}")
                plans.append(plan)
            else:
                print(f"  {RED}✖ Failed to apply remediation:{RESET} {err}")
                return False, plans
            continue

        # Interactive user prompt
        while True:
            print(f"  {BOLD}Choose remediation action:{RESET}")
            print(f"    {GREEN}[1] Migrate to {default_vault.display_name} & Replace in Code (Recommended){RESET}")
            print(f"    {CYAN}[2] Encrypt with Google Cloud KMS Envelope & Replace in Code{RESET}")
            print(f"    {YELLOW}[3] Save to Local Env (.env.staging) & Replace in Code{RESET}")
            print(f"    {BLUE}[4] Replace with Environment Variable reference only (no vault upload){RESET}")
            print(f"    {MAGENTA}[5] Ignore this secret (add to .secretshieldignore){RESET}")
            print(f"    {RED}[6] Abort Git operation (block commit/push){RESET}")

            choice = _get_tty_input(f"  {BOLD}Select option [1-6] (default: 1): {RESET}").strip()
            if not choice:
                choice = "1"

            if choice == "1":
                print(f"  Uploading to {default_vault.display_name} as '{env_var_name}'...")
                vault_res = default_vault.store_secret(
                    secret_name=env_var_name,
                    secret_value=finding.secret_raw,
                    metadata={"file": finding.file_path, "rule": finding.rule_id},
                )
                if not vault_res.success:
                    print(f"  {RED}✖ Vault error:{RESET} {vault_res.error}")
                    retry = _get_tty_input("  Try another option? [Y/n]: ").strip().lower()
                    if retry == "n":
                        return False, plans
                    continue

                plan = create_remediation_plan(
                    finding=finding,
                    vault_result=vault_res,
                    use_vault_uri=config.use_vault_uri_in_code,
                    custom_env_var=env_var_name,
                    repo_root=root,
                )
                ok, err = apply_remediation_plan(plan)
                if ok:
                    print(f"  {GREEN}✔ Successfully secured! Reference: {vault_res.reference_uri}{RESET}")
                    plans.append(plan)
                    break
                else:
                    print(f"  {RED}✖ Failed to update file:{RESET} {err}")
                    return False, plans

            elif choice == "2":
                kms_provider = get_vault_provider("google_kms", config, root)
                print(f"  Encrypting with Google KMS as '{env_var_name}'...")
                vault_res = kms_provider.store_secret(
                    secret_name=env_var_name,
                    secret_value=finding.secret_raw,
                    metadata={"file": finding.file_path},
                )
                if not vault_res.success:
                    print(f"  {RED}✖ KMS error:{RESET} {vault_res.error}")
                    continue

                plan = create_remediation_plan(
                    finding=finding,
                    vault_result=vault_res,
                    use_vault_uri=True,
                    custom_env_var=env_var_name,
                    repo_root=root,
                )
                ok, err = apply_remediation_plan(plan)
                if ok:
                    print(f"  {GREEN}✔ Encrypted with KMS! Reference: {vault_res.reference_uri}{RESET}")
                    plans.append(plan)
                    break
                else:
                    print(f"  {RED}✖ Failed to update file:{RESET} {err}")
                    return False, plans

            elif choice == "3":
                local_provider = get_vault_provider("local_env", config, root)
                vault_res = local_provider.store_secret(
                    secret_name=env_var_name,
                    secret_value=finding.secret_raw,
                    metadata={"file": finding.file_path},
                )
                if not vault_res.success:
                    print(f"  {RED}✖ Error saving to local .env:{RESET} {vault_res.error}")
                    continue

                plan = create_remediation_plan(
                    finding=finding,
                    vault_result=vault_res,
                    custom_env_var=env_var_name,
                    repo_root=root,
                )
                ok, err = apply_remediation_plan(plan)
                if ok:
                    print(f"  {GREEN}✔ Saved to .env.staging and replaced in code!{RESET}")
                    plans.append(plan)
                    break
                else:
                    print(f"  {RED}✖ Failed to update file:{RESET} {err}")
                    return False, plans

            elif choice == "4":
                plan = create_remediation_plan(
                    finding=finding,
                    vault_result=None,
                    custom_env_var=env_var_name,
                    repo_root=root,
                )
                ok, err = apply_remediation_plan(plan)
                if ok:
                    print(f"  {GREEN}✔ Replaced with environment variable reference ${{{env_var_name}}}!{RESET}")
                    plans.append(plan)
                    break
                else:
                    print(f"  {RED}✖ Failed to update file:{RESET} {err}")
                    return False, plans

            elif choice == "5":
                if add_to_secretshieldignore(finding, root):
                    print(f"  {YELLOW}✔ Added {finding.file_path} to .secretshieldignore{RESET}")
                    break
                else:
                    print(f"  {RED}✖ Could not write to .secretshieldignore{RESET}")
                    break

            elif choice == "6":
                print(f"\n{RED}✖ Git operation aborted by user.{RESET}")
                return False, plans

            else:
                print(f"  {RED}Invalid choice '{choice}'. Please select 1-6.{RESET}")

    return True, plans
