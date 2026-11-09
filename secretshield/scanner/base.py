"""Base scanner interfaces and finding data models."""

from __future__ import annotations

import fnmatch
import math
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def mask_secret(secret: str) -> str:
    """Mask a secret for safe display (e.g. AIza...x91Z or *****)."""
    if len(secret) <= 8:
        return "*****"
    prefix = secret[:11] if len(secret) > 20 else secret[:4]
    suffix = "****"
    return f"{prefix}{suffix}"


def is_line_ignored(line: str) -> bool:
    """Check if line contains ignore directives or allowlist pragma."""
    if any(marker in line for marker in [
        "secret-shield:ignore",
        "secretshield:ignore",
        "secretshield: allow",
        "nosec",
        "pragma: allowlist secret",
        "gitleaks:allow",
        "detect-secrets:not-a-secret",
    ]):
        return True

    trimmed = line.strip()
    if trimmed.startswith("#") or trimmed.startswith("//") or trimmed.startswith("/*") or trimmed.startswith("*"):
        if not any(k in trimmed for k in ["API_KEY", "SECRET", "PASSWORD", "TOKEN", "AIza", "sk-", "ghp_"]):
            return True

    return False


@dataclass
class Finding:
    """Represents a single detected secret finding in a file or git diff."""

    file_path: str
    line_number: int
    line_content: str
    rule_id: str
    rule_name: str = ""
    secret_hint: str = ""
    raw_secret: str = ""
    secret_raw: str = ""
    masked_secret: str = ""
    entropy: float = 0.0
    suggested_replacement: str = ""
    col_start: int = 0
    col_end: int = 0
    detector_source: str = "native"
    detector: str = "native"
    hint: str = ""

    def __post_init__(self):
        # Harmonize aliases
        if self.raw_secret and not self.secret_raw:
            self.secret_raw = self.raw_secret
        elif self.secret_raw and not self.raw_secret:
            self.raw_secret = self.secret_raw

        if self.secret_hint and not self.hint:
            self.hint = self.secret_hint
        elif self.hint and not self.secret_hint:
            self.secret_hint = self.hint

        if self.detector_source and not self.detector:
            self.detector = self.detector_source
        elif self.detector and not self.detector_source:
            self.detector_source = self.detector

        if not self.masked_secret and self.secret_raw:
            self.masked_secret = mask_secret(self.secret_raw)

        if not self.entropy and self.secret_raw:
            self.entropy = calculate_shannon_entropy(self.secret_raw)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "hint": self.hint,
            "masked_secret": self.masked_secret,
            "entropy": self.entropy,
            "detector": self.detector,
            "suggested_replacement": self.suggested_replacement,
        }


class BaseScanner(ABC):
    """Abstract Base Class for secret scanners."""

    def __init__(self, config: Optional[Any] = None, repo_root: Optional[Path] = None):
        from secretshield.config import ShieldConfig
        self.config = config or ShieldConfig()
        self.repo_root = repo_root or Path.cwd()

    @abstractmethod
    def scan_path(self, target_path: Path) -> List[Finding]:
        """Scan a file or directory on disk."""
        pass

    @abstractmethod
    def scan_staged(self) -> List[Finding]:
        """Scan staged files / git index for pre-commit hook."""
        pass

    @abstractmethod
    def scan_push_diff(self, remote_sha: str, local_sha: str) -> List[Finding]:
        """Scan commit range for pre-push hook."""
        pass

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file."""
        return self.scan_path(file_path)

    def scan_directory(self, dir_path: Path) -> List[Finding]:
        """Scan a directory recursively."""
        return self.scan_path(dir_path)

    def scan_git_log(self, commit_range: str) -> List[Finding]:
        """Scan a commit range (e.g. origin/main..HEAD)."""
        if ".." in commit_range:
            parts = commit_range.split("..", 1)
            return self.scan_push_diff(parts[0], parts[1])
        return self.scan_push_diff("", commit_range)

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the required binary/runtime is available."""
        pass

    @staticmethod
    def calculate_entropy(data: str) -> float:
        return calculate_shannon_entropy(data)

    @staticmethod
    def mask_secret(secret: str) -> str:
        return mask_secret(secret)

    def is_ignored_file(self, file_path: str) -> bool:
        norm_path = file_path.replace("\\", "/")
        basename = os.path.basename(norm_path)

        if "__pycache__" in norm_path or norm_path.endswith(".pyc"):
            return True

        for pattern in self.config.ignore_patterns:
            pat = pattern.rstrip("/")
            if (
                fnmatch.fnmatch(norm_path, pattern)
                or fnmatch.fnmatch(basename, pattern)
                or fnmatch.fnmatch(norm_path, pat)
                or fnmatch.fnmatch(norm_path, f"*/{pat}/*")
                or fnmatch.fnmatch(norm_path, f"{pat}/*")
                or fnmatch.fnmatch(norm_path, f"*/{pat}")
            ):
                return True
        return False

    def is_line_ignored(self, line: str) -> bool:
        return is_line_ignored(line)

    def is_allowlisted_value(self, val: str) -> bool:
        if not val or len(val) < 6:
            return True

        for allow in self.config.allowlist_strings:
            if allow in val:
                return True

        val_lower = val.lower()
        if any(d in val_lower for d in ["dummy", "mock", "placeholder", "changeme", "example", "secret_here", "localhost"]):
            return True

        # UUID check (e.g. 123e4567-e89b-12d3-a456-426614174000)
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", val, re.IGNORECASE):
            return True

        return False
