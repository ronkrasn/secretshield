"""TruffleHog binary scanner wrapper."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, List, Optional

from secretshield.config import ShieldConfig
from secretshield.scanner.base import BaseScanner, Finding


class TruffleHogScanner(BaseScanner):
    def __init__(self, config: Optional[Any] = None, repo_root: Optional[Path] = None):
        super().__init__(config or ShieldConfig(), repo_root or Path.cwd())

    def is_available(self) -> bool:
        return shutil.which("trufflehog") is not None

    def _parse_ndjson_output(self, raw_output: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue

            raw_secret = data.get("Raw", "")
            if not raw_secret or self.is_allowlisted_value(raw_secret):
                continue

            detector_name = data.get("DetectorName", "TruffleHog")
            src_meta = data.get("SourceMetadata", {}).get("Data", {})
            git_data = src_meta.get("Git", {})
            fs_data = src_meta.get("Filesystem", {})

            file_path = git_data.get("file") or fs_data.get("file") or "unknown"
            if self.is_ignored_file(file_path):
                continue

            line_num = int(git_data.get("line") or fs_data.get("line") or 1)
            hint = f"{detector_name.upper().replace(' ', '_')}_KEY"

            finding = Finding(
                file_path=file_path,
                line_number=line_num,
                line_content=f"Secret: {raw_secret}",
                rule_id=detector_name,
                rule_name=f"TruffleHog: {detector_name}",
                secret_hint=hint,
                raw_secret=raw_secret,
                secret_raw=raw_secret,
                masked_secret=self.mask_secret(raw_secret),
                entropy=self.calculate_entropy(raw_secret),
                suggested_replacement=f"process.env.{hint}",
                detector_source="trufflehog",
                detector="trufflehog",
                hint=hint,
            )
            findings.append(finding)

        return findings

    _parse_trufflehog_ndjson = _parse_ndjson_output

    def scan_staged(self) -> List[Finding]:
        if not self.is_available():
            return []
        cmd = ["trufflehog", "git", f"file://{self.repo_root}", "--json", "--since-commit", "HEAD"]
        res = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True, text=True)
        return self._parse_ndjson_output(res.stdout)

    def scan_push_diff(self, remote_sha: str, local_sha: str) -> List[Finding]:
        if not self.is_available():
            return []
        since = remote_sha if remote_sha and remote_sha != "0000000000000000000000000000000000000000" else f"{local_sha}^"
        cmd = ["trufflehog", "git", f"file://{self.repo_root}", "--json", "--since-commit", since]
        res = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True, text=True)
        return self._parse_ndjson_output(res.stdout)

    def scan_path(self, target_path: Path) -> List[Finding]:
        if not self.is_available():
            return []
        cmd = ["trufflehog", "filesystem", str(target_path), "--json"]
        res = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True, text=True)
        return self._parse_ndjson_output(res.stdout)
