"""Pre-commit hook implementation for SecretShield."""

from pathlib import Path
import subprocess
import sys
from typing import Optional

from secretshield.config import ShieldConfig, load_config
from secretshield.remediation.interactive import run_interactive_remediation
from secretshield.scanner import get_scanner


def run_pre_commit_hook(repo_root: Optional[Path] = None, auto_accept: bool = False) -> int:
    """
    Execute pre-commit secret scan on staged git changes.
    Returns 0 if clean/remediated, 1 if secrets detected and unresolved.
    """
    root = repo_root or Path.cwd()
    config = load_config(root / ".secretshield.json")

    scanner = get_scanner(config=config, repo_root=root)
    findings = scanner.scan_staged()

    if not findings:
        return 0

    print(f"\n\033[93m\033[1m[SecretShield]\033[0m Detected {len(findings)} potential secret(s) in staged changes.")

    if config.remediation_mode == "warn":
        for f in findings:
            print(f"  - {f.file_path}:{f.line_number} [{f.rule_id}] {f.masked_secret}")
        return 0

    # Run interactive or auto remediation
    success, plans = run_interactive_remediation(
        findings=findings,
        config=config,
        repo_root=root,
        auto_accept=auto_accept,
    )

    if success and plans:
        # Re-stage modified files so the commit contains the clean code
        for plan in plans:
            if plan.success:
                try:
                    rel_path = plan.file_path.relative_to(root)
                    subprocess.run(["git", "add", str(rel_path)], cwd=root, check=False)
                    print(f"  \033[92m✔ Re-staged clean version of {rel_path}\033[0m")
                except Exception:
                    subprocess.run(["git", "add", str(plan.file_path)], cwd=root, check=False)

        print("\n\033[92m\033[1m✔ All secrets remediated! Proceeding with commit.\033[0m\n")
        return 0

    if not success:
        print("\n\033[91m\033[1m✖ Commit blocked: Hardcoded secrets detected and not resolved.\033[0m")
        print("  Run \033[96msecretshield scan --staged\033[0m to review or remediate manually.\n")
        return 1

    return 0
