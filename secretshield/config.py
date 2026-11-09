"""Configuration management for SecretShield."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

CONFIG_FILENAME = ".secretshield.json"
IGNORE_FILENAME = ".secretshieldignore"

DEFAULT_IGNORE_PATTERNS = [
    "*.example",
    "*.sample",
    "*.template",
    "*.test.ts",
    "*.spec.ts",
    "*.test.js",
    "*.spec.js",
    "*_test.go",
    "test_*.py",
    "*mock*",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "go.work.sum",
    ".git/*",
    ".gitignore",
    "node_modules/*",
    "vendor/*",
    "dist/*",
    "build/*",
    "tmp/*",
    ".idea/*",
    ".vscode/*",
    "*.pyc",
    "__pycache__/*",
    "__pycache__",
    ".pytest_cache/*",
    ".coverage",
    "htmlcov/*",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.svg",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
]

DEFAULT_ALLOWLIST_STRINGS = [
    "YOUR_API_KEY",
    "YOUR_SECRET_KEY",
    "YOUR_PASSWORD",
    "CHANGEME",
    "TODO",
    "EXAMPLE",
    "DUMMY",
    "PLACEHOLDER",
    "SECRET_GOES_HERE",
    "MOCK_KEY",
    "TEST_KEY",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "true",
    "false",
    "null",
    "undefined",
    "${",
    "process.env.",
    "os.getenv(",
    "os.Getenv(",
    "gsm://",
    "kms://",
    "vault://",
    "aws-sm://",
    "azure-kv://",
    "local-env://",
]


@dataclass
class GoogleSecretManagerConfig:
    project_id: str = ""
    auto_create: bool = True
    labels: Dict[str, str] = field(default_factory=lambda: {"managed-by": "secretshield"})


@dataclass
class GoogleKMSConfig:
    project_id: str = ""
    keyring: str = "secretshield-ring"
    key: str = "secretshield-key"
    location: str = "global"


@dataclass
class HashiCorpVaultConfig:
    vault_addr: str = "http://127.0.0.1:8200"
    vault_token: str = ""
    mount_path: str = "secret"
    kv_version: int = 2


@dataclass
class AWSSecretsManagerConfig:
    region: str = "us-east-1"
    kms_key_id: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=lambda: {"ManagedBy": "SecretShield"})


@dataclass
class AzureKeyVaultConfig:
    vault_name: str = ""


@dataclass
class LocalEnvConfig:
    target_file: str = ".env.staging"


@dataclass
class ShieldConfig:
    version: str = "1.0.0"
    scanner: str = "auto"  # "auto", "gitleaks", "trufflehog", "native"
    default_vault: str = "google_secret_manager"  # "google_secret_manager", "google_kms", "hashicorp_vault", "aws_secrets_manager", "azure_keyvault", "local_env"
    remediation_mode: str = "interactive"  # "interactive", "auto", "warn"
    secret_prefix: str = "secretshield"
    entropy_threshold: float = 4.0
    fail_on_detection: bool = True
    use_vault_uri_in_code: bool = False
    vault_config: Dict[str, Any] = field(default_factory=dict)
    google_secret_manager: GoogleSecretManagerConfig = field(default_factory=GoogleSecretManagerConfig)
    google_kms: GoogleKMSConfig = field(default_factory=GoogleKMSConfig)
    hashicorp_vault: HashiCorpVaultConfig = field(default_factory=HashiCorpVaultConfig)
    aws_secrets_manager: AWSSecretsManagerConfig = field(default_factory=AWSSecretsManagerConfig)
    azure_keyvault: AzureKeyVaultConfig = field(default_factory=AzureKeyVaultConfig)
    local_env: LocalEnvConfig = field(default_factory=LocalEnvConfig)
    ignore_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATTERNS))
    allowlist_strings: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST_STRINGS))
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)

    def __init__(
        self,
        version: str = "1.0.0",
        scanner: Optional[str] = None,
        scanner_type: Optional[str] = None,
        default_vault: Optional[str] = None,
        vault_provider: Optional[str] = None,
        remediation_mode: str = "interactive",
        secret_prefix: str = "secretshield",
        entropy_threshold: float = 4.0,
        fail_on_detection: bool = True,
        use_vault_uri_in_code: bool = False,
        vault_config: Optional[Dict[str, Any]] = None,
        google_secret_manager: Optional[GoogleSecretManagerConfig] = None,
        google_kms: Optional[GoogleKMSConfig] = None,
        hashicorp_vault: Optional[HashiCorpVaultConfig] = None,
        aws_secrets_manager: Optional[AWSSecretsManagerConfig] = None,
        azure_keyvault: Optional[AzureKeyVaultConfig] = None,
        local_env: Optional[LocalEnvConfig] = None,
        ignore_patterns: Optional[List[str]] = None,
        allowlist_strings: Optional[List[str]] = None,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
    ):
        self.version = version
        self.scanner = scanner or scanner_type or "auto"
        self.default_vault = default_vault or vault_provider or "google_secret_manager"
        self.remediation_mode = remediation_mode
        self.secret_prefix = secret_prefix
        self.entropy_threshold = entropy_threshold
        self.fail_on_detection = fail_on_detection
        self.use_vault_uri_in_code = use_vault_uri_in_code
        self.vault_config = vault_config or {}
        self.google_secret_manager = google_secret_manager or GoogleSecretManagerConfig()
        self.google_kms = google_kms or GoogleKMSConfig()
        self.hashicorp_vault = hashicorp_vault or HashiCorpVaultConfig()
        self.aws_secrets_manager = aws_secrets_manager or AWSSecretsManagerConfig()
        self.azure_keyvault = azure_keyvault or AzureKeyVaultConfig()
        self.local_env = local_env or LocalEnvConfig()
        self.ignore_patterns = ignore_patterns if ignore_patterns is not None else list(DEFAULT_IGNORE_PATTERNS)
        self.allowlist_strings = allowlist_strings if allowlist_strings is not None else list(DEFAULT_ALLOWLIST_STRINGS)
        self.custom_rules = custom_rules or []

        # Sync vault_config dict with typed configs if present
        if self.vault_config:
            if "project_id" in self.vault_config:
                self.google_secret_manager.project_id = self.vault_config["project_id"]
                self.google_kms.project_id = self.vault_config["project_id"]
            if "location" in self.vault_config:
                self.google_kms.location = self.vault_config["location"]
            if "keyring" in self.vault_config:
                self.google_kms.keyring = self.vault_config["keyring"]
            if "key" in self.vault_config:
                self.google_kms.key = self.vault_config["key"]
            if "vault_addr" in self.vault_config:
                self.hashicorp_vault.vault_addr = self.vault_config["vault_addr"]
            if "mount_path" in self.vault_config:
                self.hashicorp_vault.mount_path = self.vault_config["mount_path"]
            if "region" in self.vault_config:
                self.aws_secrets_manager.region = self.vault_config["region"]
            if "vault_name" in self.vault_config:
                self.azure_keyvault.vault_name = self.vault_config["vault_name"]
            if "target_file" in self.vault_config:
                self.local_env.target_file = self.vault_config["target_file"]

    @property
    def scanner_type(self) -> str:
        return self.scanner

    @scanner_type.setter
    def scanner_type(self, value: str) -> None:
        self.scanner = value

    @property
    def vault_provider(self) -> str:
        return self.default_vault

    @vault_provider.setter
    def vault_provider(self, value: str) -> None:
        self.default_vault = value

    @classmethod
    def load(cls, repo_root: Path) -> ShieldConfig:
        config_path = repo_root if repo_root.name.endswith(".json") else repo_root / CONFIG_FILENAME
        return load_config(config_path)

    def save(self, repo_root: Path) -> Path:
        config_path = repo_root if repo_root.name.endswith(".json") else repo_root / CONFIG_FILENAME
        return save_config(self, config_path)


def get_default_gcp_project() -> Optional[str]:
    """Detect default Google Cloud project ID from environment or gcloud config."""
    env_p = (
        os.environ.get("GCP_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("CLOUDSDK_CORE_PROJECT")
    )
    if env_p:
        return env_p
    if shutil.which("gcloud"):
        try:
            res = subprocess.run(
                ["gcloud", "config", "get-value", "project"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                val = res.stdout.strip()
                if val and "(unset)" not in val:
                    return val
        except Exception:
            pass
    return None


def get_default_aws_region() -> str:
    """Detect default AWS region from environment."""
    return os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"


def load_ignore_patterns(repo_root: Path) -> List[str]:
    """Load ignore patterns from .secretshieldignore in repo_root."""
    ignore_path = repo_root / IGNORE_FILENAME
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    if ignore_path.exists():
        try:
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line not in patterns:
                            patterns.append(line)
        except Exception:
            pass
    return patterns


def load_config(config_path_or_root: Optional[Path] = None) -> ShieldConfig:
    """Load ShieldConfig from file path or directory."""
    if config_path_or_root is None:
        target = Path.cwd() / CONFIG_FILENAME
        root = Path.cwd()
    elif config_path_or_root.is_dir():
        target = config_path_or_root / CONFIG_FILENAME
        root = config_path_or_root
    else:
        target = config_path_or_root
        root = config_path_or_root.parent

    config = ShieldConfig()

    if target.exists():
        try:
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)
                config.version = data.get("version", config.version)
                config.scanner = data.get("scanner_type") or data.get("scanner") or config.scanner
                config.default_vault = data.get("vault_provider") or data.get("default_vault") or config.default_vault
                config.remediation_mode = data.get("remediation_mode", config.remediation_mode)
                config.secret_prefix = data.get("secret_prefix", config.secret_prefix)
                config.entropy_threshold = float(data.get("entropy_threshold", config.entropy_threshold))
                config.fail_on_detection = bool(data.get("fail_on_detection", config.fail_on_detection))
                config.use_vault_uri_in_code = bool(data.get("use_vault_uri_in_code", config.use_vault_uri_in_code))

                v_conf = data.get("vault_config", {})
                config.vault_config = v_conf

                if "ignore_patterns" in data:
                    for p in data["ignore_patterns"]:
                        if p not in config.ignore_patterns:
                            config.ignore_patterns.append(p)

                if "allowlist_strings" in data:
                    for a in data["allowlist_strings"]:
                        if a not in config.allowlist_strings:
                            config.allowlist_strings.append(a)

                if "custom_rules" in data:
                    config.custom_rules = data["custom_rules"]
        except Exception as e:
            print(f"Warning: Failed to parse config {target}: {e}", file=sys.stderr)

    # Load ignore patterns
    for p in load_ignore_patterns(root):
        if p not in config.ignore_patterns:
            config.ignore_patterns.append(p)

    return config


def save_config(config: ShieldConfig, config_path: Optional[Path] = None) -> Path:
    """Save ShieldConfig to JSON file."""
    target = config_path or Path.cwd() / CONFIG_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "version": config.version,
        "scanner_type": config.scanner,
        "vault_provider": config.default_vault,
        "remediation_mode": config.remediation_mode,
        "entropy_threshold": config.entropy_threshold,
        "fail_on_detection": config.fail_on_detection,
        "use_vault_uri_in_code": config.use_vault_uri_in_code,
        "vault_config": config.vault_config,
        "custom_rules": config.custom_rules,
    }

    with open(target, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    return target
