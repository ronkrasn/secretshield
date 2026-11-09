"""Scanner package exports and factory."""

from pathlib import Path
from typing import Any, Optional

from secretshield.config import ShieldConfig
from secretshield.scanner.base import BaseScanner, Finding
from secretshield.scanner.composite import CompositeScanner
from secretshield.scanner.gitleaks import GitleaksScanner
from secretshield.scanner.native import NativeScanner
from secretshield.scanner.trufflehog import TruffleHogScanner


def get_scanner(config: Optional[Any] = None, repo_root: Optional[Path] = None) -> BaseScanner:
    """Returns the configured scanner backend."""
    cfg = config or ShieldConfig()
    root = repo_root or Path.cwd()
    scanner_type = getattr(cfg, "scanner_type", "auto")
    if scanner_type == "native":
        return NativeScanner(cfg, root)
    elif scanner_type == "gitleaks":
        return GitleaksScanner(cfg, root)
    elif scanner_type == "trufflehog":
        return TruffleHogScanner(cfg, root)
    return CompositeScanner(cfg, root)


__all__ = [
    "BaseScanner",
    "Finding",
    "NativeScanner",
    "GitleaksScanner",
    "TruffleHogScanner",
    "CompositeScanner",
    "get_scanner",
]
