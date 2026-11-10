"""Local environment file provider for SecretShield."""

from pathlib import Path
import re
from typing import Any, Dict, Optional, Tuple

from secretshield.config import ShieldConfig, ensure_gitignored
from secretshield.vault.base import BaseVaultProvider, VaultResult


class LocalEnvProvider(BaseVaultProvider):
    """
    Stores extracted secrets locally in an uncommitted .env file (e.g. .env.local / .env.staging).
    Ensures the target file is added to .gitignore.
    """

    vault_type: str = "local_env"
    display_name: str = "Local Env File (.env.staging / .env.local)"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        super().__init__(config, repo_root)
        self.target_file = self.vault_config.get("target_file", ".env.staging")

    def get_creation_command(self, secret_name: str, secret_value: str) -> str:
        """Generate shell command to store secret in local uncommitted .env file."""
        env_var = self.normalize_env_var_name(secret_name)
        val_escaped = secret_value.replace('"', '\\"')
        return f"echo '{env_var}=\"{val_escaped}\"' >> {self.target_file}"

    def is_available(self) -> Tuple[bool, str]:
        return True, f"Local env file provider ready (Target: {self.target_file})"

    def test_connection(self) -> Tuple[bool, str]:
        try:
            target_path = self.repo_root / self.target_file
            if not target_path.exists():
                target_path.touch()
            return True, f"Successfully verified local target file '{self.target_file}'"
        except Exception as e:
            return False, f"Cannot write to local file '{self.target_file}': {e}"

    def _ensure_gitignored(self, filename: str) -> None:
        """Ensure the secret file is listed in .gitignore."""
        ensure_gitignored(self.repo_root, filename, comment="SecretShield local secrets file")

    def store_secret(
        self,
        secret_name: str,
        secret_value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VaultResult:
        env_var_name = self.normalize_env_var_name(secret_name)
        norm_secret_name = env_var_name

        try:
            target_path = self.repo_root / self.target_file
            self._ensure_gitignored(self.target_file)

            lines = []
            if target_path.exists():
                lines = target_path.read_text(encoding="utf-8").splitlines()

            # Check if key already exists
            key_pattern = re.compile(rf"^\s*{re.escape(norm_secret_name)}\s*=", re.IGNORECASE)
            updated = False
            new_lines = []
            
            # Format value safely (quote if contains spaces or special characters)
            val_escaped = secret_value.replace('"', '\\"')
            formatted_val = f'"{val_escaped}"' if (" " in secret_value or "\n" in secret_value) else secret_value

            for line in lines:
                if key_pattern.match(line):
                    new_lines.append(f"{norm_secret_name}={formatted_val}")
                    updated = True
                else:
                    new_lines.append(line)

            if not updated:
                new_lines.append(f"{norm_secret_name}={formatted_val}")

            target_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

            ref_uri = f"local-env://{self.target_file}#{norm_secret_name}"
            return VaultResult(
                success=True,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri=ref_uri,
                env_var_name=norm_secret_name,
                metadata={"file": str(self.target_file), "updated": updated},
            )
        except Exception as e:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Failed to write secret to local env file: {e}",
            )
