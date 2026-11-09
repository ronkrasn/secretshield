"""Command Line Interface (CLI) entry point for SecretShield."""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from secretshield import __version__
from secretshield.config import ShieldConfig, load_config
from secretshield.hooks.installer import install_git_hooks
from secretshield.hooks.pre_commit import run_pre_commit_hook
from secretshield.hooks.pre_push import run_pre_push_hook
from secretshield.remediation.interactive import run_interactive_remediation
from secretshield.scanner import get_scanner
from secretshield.scanner.base import Finding
from secretshield.vault import get_vault_provider, list_vault_providers
from secretshield.wizard import run_setup_wizard

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
MAGENTA = "\033[95m"


def format_findings_table(findings: List[Finding]) -> str:
    """Produce a formatted ASCII table of findings for terminal output."""
    if not findings:
        return f"{GREEN}✔ No secrets detected. All clean!{RESET}"

    lines = [
        f"\n{RED}{BOLD}🚨 SecretShield: {len(findings)} Exposed Secret(s) Found!{RESET}",
        f"{BOLD}{'#':<3} {'Detector':<12} {'Rule ID':<20} {'File & Line':<35} {'Masked Secret':<25}{RESET}",
        "─" * 95,
    ]
    for i, f in enumerate(findings, start=1):
        loc = f"{f.file_path}:{f.line_number}"
        if len(loc) > 34:
            loc = "..." + loc[-31:]
        lines.append(
            f"{i:<3} {f.detector:<12} {f.rule_id:<20} {loc:<35} {f.masked_secret:<25}"
        )
    lines.append("─" * 95)
    return "\n".join(lines)


def cmd_scan(args: argparse.Namespace, repo_root: Path) -> int:
    """Execute scan command."""
    config = load_config(repo_root / ".secretshield.json")

    if args.vault:
        config.vault_provider = args.vault

    scanner = get_scanner(config=config, repo_root=repo_root)

    findings: List[Finding] = []
    if args.staged:
        findings = scanner.scan_staged()
    elif args.path:
        target = Path(args.path)
        if target.is_file():
            findings = scanner.scan_file(target)
        else:
            findings = scanner.scan_directory(target)
    elif args.all:
        findings = scanner.scan_directory(repo_root)
    else:
        # Default: scan staged if in git repo, else current dir
        if (repo_root / ".git").exists():
            findings = scanner.scan_staged()
        else:
            findings = scanner.scan_directory(repo_root)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 0 if not findings else 1

    print(format_findings_table(findings))

    if not findings:
        return 0

    # Auto-remediation or interactive remediation if requested
    if args.auto_remediate or args.interactive:
        auto_accept = bool(args.auto_remediate)
        ok, plans = run_interactive_remediation(
            findings=findings,
            config=config,
            repo_root=repo_root,
            auto_accept=auto_accept,
        )
        return 0 if ok else 1

    return 1


def cmd_test_vault(args: argparse.Namespace, repo_root: Path) -> int:
    """Test vault provider connectivity and credentials."""
    config = load_config(repo_root / ".secretshield.json")
    provider_name = args.provider or config.vault_provider

    provider = get_vault_provider(provider_name, config, repo_root)
    print(f"\n{BOLD}Testing Vault Provider:{RESET} {CYAN}{provider.display_name}{RESET} ({provider.vault_type})")

    avail, avail_msg = provider.is_available()
    if not avail:
        print(f"  {RED}✖ Prerequisites Check Failed:{RESET} {avail_msg}")
        return 1
    print(f"  {GREEN}✔ Prerequisites:{RESET} {avail_msg}")

    ok, msg = provider.test_connection()
    if ok:
        print(f"  {GREEN}✔ Connection Test Passed:{RESET} {msg}\n")
        return 0
    else:
        print(f"  {RED}✖ Connection Test Failed:{RESET} {msg}\n")
        return 1


def cmd_install_hooks(args: argparse.Namespace, repo_root: Path) -> int:
    """Install git hooks into repo."""
    success = install_git_hooks(repo_root, use_githooks_dir=args.githooks_dir)
    if success:
        print(f"{GREEN}✔ SecretShield Git hooks installed successfully!{RESET}")
        return 0
    else:
        print(f"{RED}✖ Failed to install Git hooks. Make sure this is a Git repository.{RESET}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="secretshield",
        description="🛡️ SecretShield — Open-Source Git Hook & Secret Remediation Engine",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"SecretShield v{__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # setup / init
    setup_parser = subparsers.add_parser("setup", aliases=["init"], help="Run interactive configuration wizard")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan files, directories, or Git commits for exposed secrets")
    scan_parser.add_argument("--staged", action="store_true", help="Scan git staged changes only")
    scan_parser.add_argument("--all", action="store_true", help="Scan entire repository")
    scan_parser.add_argument("--path", type=str, help="Scan a specific file or directory path")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    scan_parser.add_argument("--auto-remediate", action="store_true", help="Automatically migrate detected secrets to key vault")
    scan_parser.add_argument("--interactive", action="store_true", help="Run interactive remediation agent")
    scan_parser.add_argument("--vault", type=str, help="Override key vault provider for remediation")

    # test-vault
    tv_parser = subparsers.add_parser("test-vault", help="Test connection to configured key vault provider")
    tv_parser.add_argument("--provider", type=str, help="Specific vault provider to test")

    # install-hooks
    ih_parser = subparsers.add_parser("install-hooks", help="Install pre-commit and pre-push Git hooks")
    ih_parser.add_argument("--githooks-dir", action="store_true", help="Install into .githooks and set core.hooksPath")

    # hook (internal runner for git hooks)
    hook_parser = subparsers.add_parser("hook", help="Internal runner for Git hooks")
    hook_parser.add_argument("hook_type", choices=["pre-commit", "pre-push"], help="Hook type to run")
    hook_parser.add_argument("--auto-accept", action="store_true", help="Auto-accept remediation without prompt")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint function."""
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)

    repo_root = Path.cwd()

    if not args.command:
        # If no arguments provided, show help
        parser.print_help()
        return 0

    if args.command in ("setup", "init"):
        run_setup_wizard(repo_root)
        return 0

    if args.command == "scan":
        return cmd_scan(args, repo_root)

    if args.command == "test-vault":
        return cmd_test_vault(args, repo_root)

    if args.command == "install-hooks":
        return cmd_install_hooks(args, repo_root)

    if args.command == "hook":
        if args.hook_type == "pre-commit":
            return run_pre_commit_hook(repo_root, auto_accept=args.auto_accept)
        elif args.hook_type == "pre-push":
            return run_pre_push_hook(repo_root)

    return 0


if __name__ == "__main__":
    sys.exit(main())
