"""Composite scanner routing between Gitleaks, TruffleHog, and Native."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, List, Optional

from secretshield.config import ShieldConfig
from secretshield.scanner.base import BaseScanner, Finding
from secretshield.scanner.gitleaks import GitleaksScanner
from secretshield.scanner.native import NativeScanner
from secretshield.scanner.trufflehog import TruffleHogScanner


class CompositeScanner(BaseScanner):
    def __init__(self, config: Optional[Any] = None, repo_root: Optional[Path] = None):
        cfg = config or ShieldConfig()
        root = repo_root or Path.cwd()
        super().__init__(cfg, root)
        self.native = NativeScanner(cfg, root)
        self.gitleaks = GitleaksScanner(cfg, root)
        self.trufflehog = TruffleHogScanner(cfg, root)

    def is_available(self) -> bool:
        return True

    def _select_engine(self) -> BaseScanner:
        pref = getattr(self.config, "scanner", "auto").lower()

        if pref == "gitleaks":
            if self.gitleaks.is_available():
                return self.gitleaks
            print("Notice: Gitleaks preferred but not found on PATH. Falling back to Native scanner.", file=sys.stderr)
            return self.native

        elif pref == "trufflehog":
            if self.trufflehog.is_available():
                return self.trufflehog
            print("Notice: TruffleHog preferred but not found on PATH. Falling back to Native scanner.", file=sys.stderr)
            return self.native

        elif pref == "native":
            return self.native

        else:  # "auto"
            if self.gitleaks.is_available():
                return self.gitleaks
            if self.trufflehog.is_available():
                return self.trufflehog
            return self.native

    def scan_staged(self) -> List[Finding]:
        engine = self._select_engine()
        findings = engine.scan_staged()
        if engine != self.native:
            native_findings = self.native.scan_staged()
            findings = self._merge_findings(findings, native_findings)
        return findings

    def scan_push_diff(self, remote_sha: str, local_sha: str) -> List[Finding]:
        engine = self._select_engine()
        findings = engine.scan_push_diff(remote_sha, local_sha)
        if engine != self.native:
            native_findings = self.native.scan_push_diff(remote_sha, local_sha)
            findings = self._merge_findings(findings, native_findings)
        return findings

    def scan_path(self, target_path: Path) -> List[Finding]:
        engine = self._select_engine()
        findings = engine.scan_path(target_path)
        if engine != self.native:
            native_findings = self.native.scan_path(target_path)
            findings = self._merge_findings(findings, native_findings)
        return findings

    @staticmethod
    def _merge_findings(primary: List[Finding], secondary: Optional[List[Finding]] = None) -> List[Finding]:
        seen = set()
        merged: List[Finding] = []

        for f in primary:
            key = (f.file_path, f.line_number, f.secret_raw)
            if key not in seen:
                seen.add(key)
                merged.append(f)

        if secondary:
            for f in secondary:
                key = (f.file_path, f.line_number, f.secret_raw)
                if key not in seen:
                    seen.add(key)
                    merged.append(f)

        return merged
