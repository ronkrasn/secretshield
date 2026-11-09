"""Google Cloud Secret Manager provider for SecretShield."""

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

from secretshield.config import ShieldConfig, get_default_gcp_project
from secretshield.vault.base import BaseVaultProvider, VaultResult


class GoogleSecretManagerProvider(BaseVaultProvider):
    """Integrates with Google Cloud Secret Manager (GSM)."""

    vault_type: str = "google_secret_manager"
    display_name: str = "Google Cloud Secret Manager"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        super().__init__(config, repo_root)
        self.project_id = (
            self.vault_config.get("project_id")
            or get_default_gcp_project()
            or ""
        )
        self.auto_create = self.vault_config.get("auto_create", True)
        self.labels = self.vault_config.get("labels", {"managed-by": "secretshield"})

    def is_available(self) -> Tuple[bool, str]:
        gcloud_bin = shutil.which("gcloud")
        if not gcloud_bin:
            return False, "Google Cloud SDK ('gcloud') CLI not found on PATH."
        if not self.project_id:
            return False, "GCP Project ID not configured and no default found in gcloud config."
        return True, f"Google Cloud SDK ready (Project: {self.project_id})"

    def test_connection(self) -> Tuple[bool, str]:
        is_avail, msg = self.is_available()
        if not is_avail:
            return False, msg

        cmd = [
            "gcloud",
            "secrets",
            "list",
            f"--project={self.project_id}",
            "--limit=1",
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
                return True, f"Successfully authenticated to Google Secret Manager (Project: {self.project_id})"
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Failed to connect to Google Secret Manager: {err}"
        except Exception as e:
            return False, f"Error testing GSM connection: {e}"

    def normalize_secret_name(self, raw_hint: str, file_path: str = "") -> str:
        """
        GSM secret names must match [a-zA-Z0-9_-]+ and be between 1 and 255 characters.
        Example: STRIPE_API_KEY or stripe-api-key.
        """
        name = super().normalize_secret_name(raw_hint, file_path)
        # Convert to lowercase with hyphens or uppercase with underscores depending on preference.
        # GSM accepts both, uppercase underscores is standard for env vars.
        return name[:255]

    def _secret_exists(self, secret_name: str) -> bool:
        cmd = [
            "gcloud",
            "secrets",
            "describe",
            secret_name,
            f"--project={self.project_id}",
            "--format=json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return res.returncode == 0

    def _create_secret_if_missing(self, secret_name: str) -> Tuple[bool, Optional[str]]:
        if self._secret_exists(secret_name):
            return True, None

        cmd = [
            "gcloud",
            "secrets",
            "create",
            secret_name,
            f"--project={self.project_id}",
            "--replication-policy=automatic",
        ]
        if self.labels:
            label_str = ",".join(f"{k}={v}" for k, v in self.labels.items())
            cmd.append(f"--labels={label_str}")

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Failed to create secret '{secret_name}' in GSM: {err}"
        return True, None

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

        # 1. Ensure secret exists in GSM
        created, err = self._create_secret_if_missing(norm_secret_name)
        if not created:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=err,
            )

        # 2. Add secret version via stdin
        cmd = [
            "gcloud",
            "secrets",
            "versions",
            "add",
            norm_secret_name,
            f"--project={self.project_id}",
            "--data-file=-",
        ]
        try:
            res = subprocess.run(
                cmd,
                input=secret_value,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                err = res.stderr.strip() or res.stdout.strip()
                return VaultResult(
                    success=False,
                    vault_type=self.vault_type,
                    secret_name=norm_secret_name,
                    reference_uri="",
                    env_var_name=env_var_name,
                    error=f"Failed to add secret version: {err}",
                )

            reference_uri = f"gsm://projects/{self.project_id}/secrets/{norm_secret_name}/versions/latest"
            return VaultResult(
                success=True,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri=reference_uri,
                env_var_name=env_var_name,
                metadata={
                    "project_id": self.project_id,
                    "version": "latest",
                },
            )
        except Exception as e:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Exception adding version to GSM: {e}",
            )
