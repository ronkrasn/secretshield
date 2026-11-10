"""HashiCorp Vault provider for SecretShield."""

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple
import urllib.error
import urllib.request

from secretshield.config import ShieldConfig
from secretshield.vault.base import BaseVaultProvider, VaultResult


class HashiCorpVaultProvider(BaseVaultProvider):
    """Integrates with HashiCorp Vault KV Secret Engine."""

    vault_type: str = "hashicorp_vault"
    display_name: str = "HashiCorp Vault"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        super().__init__(config, repo_root)
        self.vault_addr = (
            self.vault_config.get("vault_addr")
            or os.environ.get("VAULT_ADDR")
            or "http://127.0.0.1:8200"
        ).rstrip("/")
        self.vault_token = (
            self.vault_config.get("vault_token")
            or os.environ.get("VAULT_TOKEN")
            or self._read_vault_token_file()
            or ""
        )
        self.mount_path = self.vault_config.get("mount_path", "secret").strip("/")
        self.kv_version = int(self.vault_config.get("kv_version", 2))

    def _read_vault_token_file(self) -> Optional[str]:
        token_path = Path.home() / ".vault-token"
        if token_path.exists():
            try:
                return token_path.read_text(encoding="utf-8").strip()
            except Exception:
                return None
        return None

    def normalize_secret_name(self, raw_hint: str, file_path: str = "") -> str:
        name = super().normalize_secret_name(raw_hint, file_path)
        return name.lower().replace("_", "-")

    def get_creation_command(self, secret_name: str, secret_value: str) -> str:
        """Generate Vault CLI command to store secret in HashiCorp Vault KV."""
        norm_name = self.normalize_secret_name(secret_name).lower().replace("_", "-")
        val_escaped = secret_value.replace('"', '\\"')
        return f"vault kv put {self.mount_path}/{norm_name} value=\"{val_escaped}\""

    def is_available(self) -> Tuple[bool, str]:
        if shutil.which("vault"):
            return True, f"HashiCorp Vault CLI found (Address: {self.vault_addr})"
        if self.vault_addr:
            return True, f"HashiCorp Vault HTTP API ready (Address: {self.vault_addr})"
        return False, "Vault CLI not found and VAULT_ADDR not configured."

    def test_connection(self) -> Tuple[bool, str]:
        try:
            req = urllib.request.Request(
                f"{self.vault_addr}/v1/sys/health",
                headers={"X-Vault-Token": self.vault_token} if self.vault_token else {},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                status = response.getcode()
                if status in (200, 429, 472, 473):
                    return True, f"Connected to Vault at {self.vault_addr} (Status {status})"
                return False, f"Vault health check returned status {status}"
        except urllib.error.HTTPError as e:
            if e.code in (200, 429, 472, 473):
                return True, f"Connected to Vault at {self.vault_addr} (Status {e.code})"
            return False, f"Vault HTTP error {e.code}: {e.reason}"
        except Exception as e:
            # Fall back to CLI if available
            if shutil.which("vault"):
                try:
                    res = subprocess.run(
                        ["vault", "status", "-format=json"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        env={**os.environ, "VAULT_ADDR": self.vault_addr},
                        check=False,
                    )
                    if res.returncode in (0, 2):  # 0 = unsealed, 2 = sealed
                        return True, f"Connected to Vault CLI at {self.vault_addr}"
                except Exception:
                    pass
            return False, f"Could not reach HashiCorp Vault at {self.vault_addr}: {e}"

    def store_secret(
        self,
        secret_name: str,
        secret_value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VaultResult:
        env_var_name = self.normalize_env_var_name(secret_name)
        norm_secret_name = self.normalize_secret_name(secret_name).lower().replace("_", "-")

        if not self.vault_token:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error="VAULT_TOKEN not found in environment or config.",
            )

        # Use REST API directly (works without vault binary)
        try:
            if self.kv_version == 2:
                api_url = f"{self.vault_addr}/v1/{self.mount_path}/data/{norm_secret_name}"
                payload = json.dumps({"data": {"value": secret_value}}).encode("utf-8")
                ref_uri = f"vault://{self.mount_path}/data/{norm_secret_name}#value"
            else:
                api_url = f"{self.vault_addr}/v1/{self.mount_path}/{norm_secret_name}"
                payload = json.dumps({"value": secret_value}).encode("utf-8")
                ref_uri = f"vault://{self.mount_path}/{norm_secret_name}#value"

            req = urllib.request.Request(
                api_url,
                data=payload,
                headers={
                    "X-Vault-Token": self.vault_token,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 204):
                    return VaultResult(
                        success=True,
                        vault_type=self.vault_type,
                        secret_name=norm_secret_name,
                        reference_uri=ref_uri,
                        env_var_name=env_var_name,
                        metadata={"mount": self.mount_path, "kv_version": self.kv_version},
                    )
                return VaultResult(
                    success=False,
                    vault_type=self.vault_type,
                    secret_name=norm_secret_name,
                    reference_uri="",
                    env_var_name=env_var_name,
                    error=f"Vault returned HTTP status {resp.status}",
                )
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Vault API error {e.code}: {body}",
            )
        except Exception as e:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Exception writing to Vault: {e}",
            )
