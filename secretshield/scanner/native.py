"""Native pure-Python regex and entropy scanner."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Optional, Pattern

from secretshield.config import ShieldConfig
from secretshield.scanner.base import BaseScanner, Finding


class NativeScanner(BaseScanner):
    def __init__(self, config: Optional[Any] = None, repo_root: Optional[Path] = None):
        super().__init__(config or ShieldConfig(), repo_root or Path.cwd())
        self.rules = self._init_rules()

    def is_available(self) -> bool:
        return True  # Native Python is always available

    def _init_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "google_api_key",
                "name": "Google / Gemini API Key",
                "pattern": re.compile(r"\b(AIza[0-9A-Za-z-_]{30,40})\b"),
                "hint": "GOOGLE_API_KEY",
                "group": 1,
            },
            {
                "id": "google_oauth_secret",
                "name": "Google OAuth Client Secret",
                "pattern": re.compile(r"\b(GOCSPX-[0-9a-zA-Z_-]{28})\b"),
                "hint": "GOOGLE_CLIENT_SECRET",
                "group": 1,
            },
            {
                "id": "openai_api_key",
                "name": "OpenAI API Key",
                "pattern": re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|sk-admin-[a-zA-Z0-9_-]{20,})\b"),
                "hint": "OPENAI_API_KEY",
                "group": 1,
            },
            {
                "id": "anthropic_api_key",
                "name": "Anthropic API Key",
                "pattern": re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b"),
                "hint": "ANTHROPIC_API_KEY",
                "group": 1,
            },
            {
                "id": "aws_access_key_id",
                "name": "AWS Access Key ID",
                "pattern": re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
                "hint": "AWS_ACCESS_KEY_ID",
                "group": 1,
            },
            {
                "id": "aws_secret_access_key",
                "name": "AWS Secret Access Key",
                "pattern": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?"),
                "hint": "AWS_SECRET_ACCESS_KEY",
                "group": 1,
            },
            {
                "id": "github_pat",
                "name": "GitHub Token (PAT / OAuth)",
                "pattern": re.compile(r"\b(ghp_[0-9a-zA-Z]{36,40}|github_pat_[0-9a-zA-Z_]{80,90}|gho_[0-9a-zA-Z]{36,40}|ghs_[0-9a-zA-Z]{36,40})\b"),
                "hint": "GITHUB_TOKEN",
                "group": 1,
            },
            {
                "id": "slack_token_or_webhook",
                "name": "Slack Token / Webhook",
                "pattern": re.compile(r"(xox[baprs]-[0-9a-zA-Z]{10,}|https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z_]+\/B[0-9A-Z_]+\/[0-9a-zA-Z]+)"),
                "hint": "SLACK_WEBHOOK_URL",
                "group": 1,
            },
            {
                "id": "stripe_secret_key",
                "name": "Stripe API Key",
                "pattern": re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
                "hint": "STRIPE_API_KEY",
                "group": 1,
            },
            {
                "id": "database_uri_password",
                "name": "Database URI with Credentials",
                "pattern": re.compile(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:\s\"']+:(?P<pass>[^\s\"']+?)@(?=[a-zA-Z0-9_.-]+)"),
                "hint": "DATABASE_PASSWORD",
                "named_val": "pass",
            },
            {
                "id": "private_key_pem",
                "name": "Private Key (PEM Format)",
                "pattern": re.compile(r"(-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----)"),
                "hint": "PRIVATE_KEY",
                "group": 1,
            },
            {
                "id": "jwt_or_crypto_secret",
                "name": "JWT / Encryption Key Assignment",
                "pattern": re.compile(r"(?i)\b(?P<hint>jwt_secret|jwt_key|encryption_key|internal_api_key|auth_secret)\s*[:=]\s*['\"](?P<val>[a-zA-Z0-9!@#$%^&*()_+=\-~`[\]{}|:;<>?,./]{16,})['\"]"),
                "hint": "JWT_SECRET",
                "named_val": "val",
                "named_hint": "hint",
            },
            {
                "id": "generic_secret_assignment",
                "name": "Hardcoded Secret Assignment",
                "pattern": re.compile(r"(?i)\b(?P<hint>[a-z0-9_]*(?:api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|password|passwd|db_password))\s*[:=]\s*['\"](?P<val>[^'\"\s${}]{8,})['\"]"),
                "hint": "SECRET_KEY",
                "named_val": "val",
                "named_hint": "hint",
            },
            {
                "id": "dotenv_secret_assignment",
                "name": ".env Exposed Secret",
                "pattern": re.compile(r"^(?P<hint>[A-Z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|CREDENTIAL|PRIVATE|PASSWD)[A-Z0-9_]*)\s*=\s*['\"]?(?P<val>[^'\"\s#]{8,})['\"]?"),
                "hint": "ENV_SECRET",
                "named_val": "val",
                "named_hint": "hint",
            },
        ]

    def scan_content(self, content: str, file_path: str) -> List[Finding]:
        if self.is_ignored_file(file_path):
            return []

        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if self.is_line_ignored(line):
                continue

            for rule in self.rules:
                pattern: Pattern = rule["pattern"]
                match = pattern.search(line)
                if not match:
                    continue

                if "named_val" in rule:
                    raw_val = match.group(rule["named_val"])
                    named_hint = rule.get("named_hint")
                    if named_hint and named_hint in match.groupdict() and match.group(named_hint):
                        hint = match.group(named_hint).upper().replace("-", "_")
                    else:
                        hint = rule.get("hint", "SECRET_KEY")
                else:
                    raw_val = match.group(rule.get("group", 1))
                    hint = rule.get("hint", "SECRET_KEY")

                if self.is_allowlisted_value(raw_val):
                    continue

                entropy = self.calculate_entropy(raw_val)

                if rule["id"] in ("generic_secret_assignment", "dotenv_secret_assignment"):
                    if entropy < 3.2 and len(raw_val) < 16:
                        continue

                finding = Finding(
                    file_path=file_path,
                    line_number=idx,
                    line_content=line,
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    secret_hint=hint,
                    raw_secret=raw_val,
                    secret_raw=raw_val,
                    masked_secret=self.mask_secret(raw_val),
                    entropy=entropy,
                    suggested_replacement=f"process.env.{hint}",
                    col_start=match.start(),
                    col_end=match.end(),
                    detector_source="native",
                    detector="native",
                    hint=hint,
                )
                findings.append(finding)
                break

        return findings

    def scan_path(self, target_path: Path) -> List[Finding]:
        all_findings: List[Finding] = []
        if target_path.is_file():
            try:
                content = target_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(target_path.relative_to(self.repo_root)) if target_path.is_relative_to(self.repo_root) else str(target_path)
                return self.scan_content(content, rel_path)
            except Exception:
                return []

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not self.is_ignored_file(os.path.join(root, d))]
            for file in files:
                file_full = Path(root) / file
                try:
                    rel_path = str(file_full.relative_to(self.repo_root))
                except ValueError:
                    rel_path = str(file_full)

                if self.is_ignored_file(rel_path):
                    continue

                try:
                    content = file_full.read_text(encoding="utf-8", errors="ignore")
                    findings = self.scan_content(content, rel_path)
                    all_findings.extend(findings)
                except Exception:
                    pass

        return all_findings

    def scan_diff_text(self, diff_text: str) -> List[Finding]:
        findings: List[Finding] = []
        current_file: Optional[str] = None
        current_line_num = 0

        for raw_line in diff_text.splitlines():
            if raw_line.startswith("diff --git"):
                current_file = None
            elif raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip()
            elif raw_line.startswith("@@"):
                m = re.search(r"\+(\d+)", raw_line)
                if m:
                    current_line_num = int(m.group(1)) - 1
            elif raw_line.startswith("+") and not raw_line.startswith("+++"):
                current_line_num += 1
                if not current_file or self.is_ignored_file(current_file):
                    continue

                line_to_check = raw_line[1:]
                line_findings = self.scan_content(line_to_check, current_file)
                for f in line_findings:
                    f.line_number = current_line_num
                    findings.append(f)
            elif not raw_line.startswith("-"):
                current_line_num += 1

        return findings

    def scan_staged(self) -> List[Finding]:
        res = subprocess.run(["git", "diff", "--cached"], cwd=str(self.repo_root), capture_output=True, text=True)
        if res.returncode != 0 or not res.stdout.strip():
            return []
        return self.scan_diff_text(res.stdout)

    def scan_push_diff(self, remote_sha: str, local_sha: str) -> List[Finding]:
        if not remote_sha or remote_sha == "0000000000000000000000000000000000000000":
            diff_args = ["git", "diff", f"{local_sha}^..{local_sha}"]
        else:
            diff_args = ["git", "diff", f"{remote_sha}..{local_sha}"]

        res = subprocess.run(diff_args, cwd=str(self.repo_root), capture_output=True, text=True)
        if res.returncode != 0 or not res.stdout.strip():
            return []
        return self.scan_diff_text(res.stdout)
