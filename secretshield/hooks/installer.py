"""Git Hooks installer for SecretShield."""

import os
from pathlib import Path
import stat
import subprocess
from typing import Optional


PRE_COMMIT_SCRIPT = """#!/usr/bin/env bash
# SecretShield Pre-Commit Hook
# Prevents committing plaintext secrets by scanning staged files and auto-migrating to Key Vault.

if command -v secretshield >/dev/null 2>&1; then
    exec secretshield hook pre-commit
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m secretshield hook pre-commit
else
    echo "Warning: Python 3 or secretshield binary not found. Skipping SecretShield hook."
    exit 0
fi
"""

PRE_PUSH_SCRIPT = """#!/usr/bin/env bash
# SecretShield Pre-Push Hook
# Prevents pushing unencrypted secrets to remote repositories.

if command -v secretshield >/dev/null 2>&1; then
    exec secretshield hook pre-push "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m secretshield hook pre-push "$@"
else
    echo "Warning: Python 3 or secretshield binary not found. Skipping SecretShield hook."
    exit 0
fi
"""


def install_git_hooks(repo_root: Optional[Path] = None, use_githooks_dir: bool = False) -> bool:
    """
    Install pre-commit and pre-push hooks into .git/hooks/ or .githooks/.
    Returns True if successful.
    """
    root = repo_root or Path.cwd()
    git_dir = root / ".git"

    if not git_dir.exists():
        return False

    if use_githooks_dir:
        hooks_dir = root / ".githooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=root, check=True)
        except Exception:
            pass
    else:
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

    pre_commit_path = hooks_dir / "pre-commit"
    pre_push_path = hooks_dir / "pre-push"

    try:
        pre_commit_path.write_text(PRE_COMMIT_SCRIPT, encoding="utf-8")
        pre_commit_path.chmod(pre_commit_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        pre_push_path.write_text(PRE_PUSH_SCRIPT, encoding="utf-8")
        pre_push_path.chmod(pre_push_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True
    except Exception as e:
        print(f"Error writing Git hooks: {e}")
        return False
