"""Pre-push hook implementation for SecretShield."""

from pathlib import Path
import subprocess
import sys
from typing import List, Optional

from secretshield.config import ShieldConfig, load_config
from secretshield.scanner import get_scanner
from secretshield.scanner.base import Finding


def get_unpushed_commit_range(remote_name: str = "origin") -> str:
    """Determine the commit range to scan before pushing."""
    try:
        # Check current branch
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        branch = res.stdout.strip()
        if branch == "HEAD":
            return "HEAD"

        # Check if upstream remote branch exists
        upstream_check = subprocess.run(
            ["git", "rev-parse", "--verify", f"{remote_name}/{branch}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if upstream_check.returncode == 0:
            return f"{remote_name}/{branch}..HEAD"
        return "HEAD"
    except Exception:
        return "HEAD"


def run_pre_push_hook(repo_root: Optional[Path] = None, remote_name: str = "origin") -> int:
    """
    Execute pre-push secret scan on unpushed commits.
    Returns 0 if clean, 1 if secrets found.
    """
    root = repo_root or Path.cwd()
    config = load_config(root / ".secretshield.json")

    scanner = get_scanner(config=config, repo_root=root)
    commit_range = get_unpushed_commit_range(remote_name)

    findings = scanner.scan_git_log(commit_range)

    if not findings:
        return 0

    print(f"\n\033[91m\033[1m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\033[0m")
    print(f"\033[91m\033[1m┃ 🛡️  SECRETSHIELD PRE-PUSH ALERT: Exposed Secrets in Unpushed Commits      ┃\033[0m")
    print(f"\033[91m\033[1m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\033[0m")
    print(f"Detected {len(findings)} secret(s) in commits about to be pushed ({commit_range}):\n")

    for i, f in enumerate(findings, start=1):
        print(f"  [{i}] \033[96m{f.file_path}\033[0m:\033[93m{f.line_number}\033[0m - \033[91m{f.masked_secret}\033[0m ({f.rule_id})")

    if config.remediation_mode == "warn":
        print("\n\033[93mWarning: Pushing despite detected secrets because remediation_mode is set to 'warn'.\033[0m\n")
        return 0

    print("\n\033[91m✖ Push blocked: Unpushed commits contain exposed secrets.\033[0m")
    print("  Please fix the commits or squash/rebase them before pushing to remote.\n")
    return 1
