"""Gitleaks binary scanner wrapper."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, List, Optional

from secretshield.config import ShieldConfig
from secretshield.scanner.base import BaseScanner, Finding


class GitleaksScanner(BaseScanner):
    def __init__(self, config: Optional[Any] = None, repo_root: Optional[Path] = None):
        super().__init__(config or ShieldConfig(), repo_root or Path.cwd())

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def _parse_gitleaks_json(self, raw_json: str) -> List[Finding]:
        try:
            data = json.loads(raw_json)
        except Exception:
            return []

        if not isinstance(data, list):
            return []

        findings: List[Finding] = []
        for item in data:
            file_path = item.get("File", "")
            if self.is_ignored_file(file_path):
                continue

            raw_secret = item.get("Secret", "")
            if self.is_allowlisted_value(raw_secret):
                continue

            line_num = int(item.get("StartLine", 1))
            rule_id = item.get("RuleID", "gitleaks_secret")
            desc = item.get("Description", "Detected Secret")
            line_match = item.get("Match", "")
            entropy = float(item.get("Entropy", 0.0))

            # Derive clean hint name
            hint = self._derive_hint(rule_id, desc, file_path)

            finding = Finding(
                file_path=file_path,
                line_number=line_num,
                line_content=line_match,
                rule_id=rule_id,
                rule_name=f"Gitleaks: {desc}",
                secret_hint=hint,
                raw_secret=raw_secret,
                secret_raw=raw_secret,
                masked_secret=self.mask_secret(raw_secret),
                entropy=entropy or self.calculate_entropy(raw_secret),
                suggested_replacement=f"process.env.{hint}",
                col_start=int(item.get("StartColumn", 0)),
                col_end=int(item.get("EndColumn", 0)),
                detector_source="gitleaks",
                detector="gitleaks",
                hint=hint,
            )
            findings.append(finding)

        return findings

    def _parse_gitleaks_report(self, report_path: Path) -> List[Finding]:
        if not report_path.exists() or report_path.stat().st_size == 0:
            return []

        try:
            raw_json = report_path.read_text(encoding="utf-8")
            return self._parse_gitleaks_json(raw_json)
        except Exception:
            return []

    def _derive_hint(self, rule_id: str, desc: str, file_path: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9]", "_", rule_id).upper().strip("_")
        if "API_KEY" in clean or "TOKEN" in clean or "SECRET" in clean or "PASSWORD" in clean:
            return clean
        if "GOOGLE" in clean:
            return "GOOGLE_API_KEY"
        if "OPENAI" in clean:
            return "OPENAI_API_KEY"
        if "ANTHROPIC" in clean:
            return "ANTHROPIC_API_KEY"
        if "AWS" in clean:
            return "AWS_SECRET_ACCESS_KEY"
        if "SLACK" in clean:
            return "SLACK_TOKEN"
        if "STRIPE" in clean:
            return "STRIPE_API_KEY"
        if "GITHUB" in clean:
            return "GITHUB_TOKEN"
        return f"{clean}_KEY"

    def scan_staged(self) -> List[Finding]:
        if not self.is_available():
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            cmd = [
                "gitleaks", "protect",
                "--staged",
                "--report-format", "json",
                f"--report-path={tmp_path}",
                "--verbose",
            ]
            config_file = self.repo_root / ".gitleaks.toml"
            if config_file.exists():
                cmd.extend(["--config", str(config_file)])

            subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True)
            return self._parse_gitleaks_report(tmp_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def scan_push_diff(self, remote_sha: str, local_sha: str) -> List[Finding]:
        if not self.is_available():
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            log_opts = f"{remote_sha}..{local_sha}" if remote_sha and remote_sha != "0000000000000000000000000000000000000000" else f"{local_sha}^..{local_sha}"
            cmd = [
                "gitleaks", "git",
                f"--log-opts={log_opts}",
                "--report-format", "json",
                f"--report-path={tmp_path}",
            ]
            subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True)
            return self._parse_gitleaks_report(tmp_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def scan_path(self, target_path: Path) -> List[Finding]:
        if not self.is_available():
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            cmd = [
                "gitleaks", "dir", str(target_path),
                "--report-format", "json",
                f"--report-path={tmp_path}",
            ]
            subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True)
            return self._parse_gitleaks_report(tmp_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
