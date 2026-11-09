"""Git Hooks module for SecretShield."""

from secretshield.hooks.installer import install_git_hooks
from secretshield.hooks.pre_commit import run_pre_commit_hook
from secretshield.hooks.pre_push import run_pre_push_hook

__all__ = [
    "install_git_hooks",
    "run_pre_commit_hook",
    "run_pre_push_hook",
]
