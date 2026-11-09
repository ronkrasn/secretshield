"""Google Cloud KMS Envelope Encryption provider for SecretShield."""

import base64
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

from secretshield.config import ShieldConfig, get_default_gcp_project
from secretshield.vault.base import BaseVaultProvider, VaultResult


class GoogleKMSProvider(BaseVaultProvider):
    """Encrypts secrets using Google Cloud Key Management Service (KMS)."""

    vault_type: str = "google_kms"
    display_name: str = "Google Cloud KMS"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        super().__init__(config, repo_root)
        self.project_id = (
            self.vault_config.get("project_id")
            or get_default_gcp_project()
            or ""
        )
        self.location = self.vault_config.get("location", "global")
        self.keyring = self.vault_config.get("keyring", "secretshield-ring")
        self.key = self.vault_config.get("key", "secretshield-key")

    def is_available(self) -> Tuple[bool, str]:
        gcloud_bin = shutil.which("gcloud")
        if not gcloud_bin:
            return False, "Google Cloud SDK ('gcloud') CLI not found on PATH."
        if not self.project_id:
            return False, "GCP Project ID not configured."
        if not self.keyring or not self.key:
            return False, "KMS keyring or key name not configured."
        return True, f"Google KMS ready ({self.keyring}/{self.key} in {self.location}, Project: {self.project_id})"

    def test_connection(self) -> Tuple[bool, str]:
        is_avail, msg = self.is_available()
        if not is_avail:
            return False, msg

        cmd = [
            "gcloud",
            "kms",
            "keys",
            "describe",
            self.key,
            f"--keyring={self.keyring}",
            f"--location={self.location}",
            f"--project={self.project_id}",
            "--format=json",
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
                return True, f"Successfully verified Google KMS Key '{self.key}' in '{self.keyring}' ({self.location})"
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Failed to access Google KMS Key: {err}"
        except Exception as e:
            return False, f"Error testing KMS connection: {e}"

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
            "gcloud",
            "kms",
            "encrypt",
            f"--project={self.project_id}",
            f"--location={self.location}",
            f"--keyring={self.keyring}",
            f"--key={self.key}",
            "--plaintext-file=-",
            "--ciphertext-file=-",
        ]
        try:
            # secret_value as bytes to stdin, ciphertext binary output from stdout
            res = subprocess.run(
                cmd,
                input=secret_value.encode("utf-8"),
                capture_output=True,
                check=False,
            )
            if res.returncode != 0:
                err = res.stderr.decode("utf-8", errors="replace").strip()
                return VaultResult(
                    success=False,
                    vault_type=self.vault_type,
                    secret_name=norm_secret_name,
                    reference_uri="",
                    env_var_name=env_var_name,
                    error=f"Google KMS encryption failed: {err}",
                )

            ciphertext_b64 = base64.b64encode(res.stdout).decode("ascii")
            key_resource_id = f"projects/{self.project_id}/locations/{self.location}/keyRings/{self.keyring}/cryptoKeys/{self.key}"
            reference_uri = f"kms://{key_resource_id}?ciphertext={ciphertext_b64}"

            return VaultResult(
                success=True,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri=reference_uri,
                env_var_name=env_var_name,
                metadata={
                    "key_resource_id": key_resource_id,
                    "ciphertext": ciphertext_b64,
                    "location": self.location,
                },
            )
        except Exception as e:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Exception during KMS encryption: {e}",
            )
