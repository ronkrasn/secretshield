"""Base abstractions and data structures for SecretShield Vault Providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, Optional, Tuple

from secretshield.config import ShieldConfig


@dataclass
class VaultResult:
    """Result of attempting to store or encrypt a secret in a vault."""

    success: bool
    vault_type: str
    secret_name: str
    reference_uri: str
    env_var_name: str
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "vault_type": self.vault_type,
            "secret_name": self.secret_name,
            "reference_uri": self.reference_uri,
            "env_var_name": self.env_var_name,
            "error": self.error,
            "metadata": self.metadata,
        }


class BaseVaultProvider(ABC):
    """Abstract base class for all SecretShield vault integrations."""

    vault_type: str = "base"
    display_name: str = "Base Vault Provider"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        self.config = config
        self.repo_root = repo_root or Path.cwd()
        self.vault_config = config.vault_config or {}

    @abstractmethod
    def is_available(self) -> Tuple[bool, str]:
        """Check if prerequisites (CLI binary, environment variables, credentials) exist."""
        pass

    @abstractmethod
    def store_secret(
        self,
        secret_name: str,
        secret_value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VaultResult:
        """Store secret in remote vault or encrypt via KMS."""
        pass

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """Test authentication and connectivity to the vault service."""
        pass

    def get_creation_command(self, secret_name: str, secret_value: str) -> str:
        """Generate shell/CLI command to store secret in this vault provider."""
        norm_name = self.normalize_secret_name(secret_name)
        return f"# Store '{norm_name}' in {self.display_name}"

    def get_access_snippet(self, env_var_name: str, file_path: str = "") -> str:
        """Generate code snippet showing how application code reads the secret at runtime."""
        ext = Path(file_path).suffix.lower() if file_path else ""
        if ext in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            return f"process.env.{env_var_name}"
        elif ext in (".py",):
            return f'os.getenv("{env_var_name}", "")'
        elif ext in (".go",):
            return f'os.Getenv("{env_var_name}")'
        elif ext in (".sh", ".bash", ".zsh"):
            return f'"${{{env_var_name}:-}}"'
        return f"${{{env_var_name}}}"

    def normalize_secret_name(self, raw_hint: str, file_path: str = "") -> str:
        """
        Produce a clean, alphanumeric/kebab/underscore secret identifier.
        Example: 'stripe_secret_key' from 'src/services/stripe.ts' -> 'STRIPE_SECRET_KEY' or 'stripe-secret-key'.
        """
        clean = raw_hint.strip()
        if not clean:
            if file_path:
                stem = Path(file_path).stem.upper()
                clean = f"{stem}_SECRET"
            else:
                clean = "APP_SECRET"

        # Replace non-alphanumeric with underscores or dashes
        clean = re.sub(r"[^a-zA-Z0-9_-]+", "_", clean)
        clean = re.sub(r"_+", "_", clean).strip("_")
        return clean.upper()

    def normalize_env_var_name(self, raw_name: str) -> str:
        """Ensure valid shell/language environment variable name (e.g. UPPER_SNAKE_CASE)."""
        clean = re.sub(r"[^a-zA-Z0-9_]+", "_", raw_name)
        clean = re.sub(r"_+", "_", clean).strip("_").upper()
        if clean and clean[0].isdigit():
            clean = f"SECRET_{clean}"
        return clean or "APP_SECRET"
