"""Azure Key Vault provider for SecretShield."""

import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

from secretshield.config import ShieldConfig
from secretshield.vault.base import BaseVaultProvider, VaultResult


class AzureKeyVaultProvider(BaseVaultProvider):
    """Integrates with Azure Key Vault."""

    vault_type: str = "azure_keyvault"
    display_name: str = "Azure Key Vault"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        super().__init__(config, repo_root)
        self.vault_name = (
            self.vault_config.get("vault_name")
            or os.environ.get("AZURE_KEYVAULT_NAME")
            or ""
        )

    def is_available(self) -> Tuple[bool, str]:
        az_bin = shutil.which("az")
        if not az_bin:
            return False, "Azure CLI ('az') not found on PATH."
        if not self.vault_name:
            return False, "Azure Key Vault name not configured."
        return True, f"Azure CLI ready (Vault: {self.vault_name})"

    def test_connection(self) -> Tuple[bool, str]:
        is_avail, msg = self.is_available()
        if not is_avail:
            return False, msg

        cmd = [
            "az",
            "keyvault",
            "secret",
            "list",
            "--vault-name",
            self.vault_name,
            "--maxresults",
            "1",
            "--output",
            "json",
        ]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if res.returncode == 0:
                return True, f"Successfully authenticated to Azure Key Vault '{self.vault_name}'"
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Failed to connect to Azure Key Vault: {err}"
        except Exception as e:
            return False, f"Error testing Azure Key Vault connection: {e}"

    def normalize_secret_name(self, raw_hint: str, file_path: str = "") -> str:
        """
        Azure Key Vault secret names must be alphanumeric and hyphens only (1-127 chars).
        """
        clean = super().normalize_secret_name(raw_hint, file_path)
        clean = clean.replace("_", "-")
        clean = re.sub(r"[^a-zA-Z0-9-]+", "-", clean)
        clean = re.sub(r"-+", "-", clean).strip("-")
        return clean[:127] or "app-secret"

    def store_secret(
        self,
        secret_name: str,
        secret_value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VaultResult:
        is_avail, msg = self.is_available()
        env_var_name = self.normalize_env_var_name(secret_name)
        norm_secret_name = self.normalize_secret_name(secret_name)

        if not is_avail:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=msg,
            )

        cmd = [
            "az",
            "keyvault",
            "secret",
            "set",
            "--vault-name",
            self.vault_name,
            "--name",
            norm_secret_name,
            "--value",
            secret_value,
            "--output",
            "json",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                err = res.stderr.strip() or res.stdout.strip()
                return VaultResult(
                    success=False,
                    vault_type=self.vault_type,
                    secret_name=norm_secret_name,
                    reference_uri="",
                    env_var_name=env_var_name,
                    error=f"Azure Key Vault error: {err}",
                )

            ref_uri = f"azure-kv://{self.vault_name}.vault.azure.net/secrets/{norm_secret_name}"
            return VaultResult(
                success=True,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri=ref_uri,
                env_var_name=env_var_name,
                metadata={"vault_name": self.vault_name},
            )
        except Exception as e:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Exception writing to Azure Key Vault: {e}",
            )
