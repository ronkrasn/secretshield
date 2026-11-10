"""AWS Secrets Manager provider for SecretShield."""

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

from secretshield.config import ShieldConfig, get_default_aws_region
from secretshield.vault.base import BaseVaultProvider, VaultResult


class AWSSecretsManagerProvider(BaseVaultProvider):
    """Integrates with AWS Secrets Manager."""

    vault_type: str = "aws_secrets_manager"
    display_name: str = "AWS Secrets Manager"

    def __init__(self, config: ShieldConfig, repo_root: Optional[Path] = None):
        super().__init__(config, repo_root)
        self.region = (
            self.vault_config.get("region")
            or get_default_aws_region()
            or "us-east-1"
        )
        self.kms_key_id = self.vault_config.get("kms_key_id")
        self.tags = self.vault_config.get("tags", {"ManagedBy": "SecretShield"})

    def is_available(self) -> Tuple[bool, str]:
        aws_bin = shutil.which("aws")
        if not aws_bin:
            return False, "AWS CLI ('aws') not found on PATH."
        return True, f"AWS CLI ready (Region: {self.region})"

    def test_connection(self) -> Tuple[bool, str]:
        is_avail, msg = self.is_available()
        if not is_avail:
            return False, msg

        cmd = [
            "aws",
            "secretsmanager",
            "list-secrets",
            "--max-items",
            "1",
            "--region",
            self.region,
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
                return True, f"Successfully authenticated to AWS Secrets Manager ({self.region})"
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Failed to connect to AWS Secrets Manager: {err}"
        except Exception as e:
            return False, f"Error testing AWS Secrets Manager connection: {e}"

    def get_creation_command(self, secret_name: str, secret_value: str) -> str:
        """Generate AWS CLI command to create or update secret in AWS Secrets Manager."""
        norm_name = self.normalize_secret_name(secret_name)
        val_escaped = secret_value.replace('"', '\\"')
        return (
            f"aws secretsmanager create-secret --name \"{norm_name}\" --secret-string \"{val_escaped}\" --region {self.region} 2>/dev/null || \\\n"
            f"aws secretsmanager put-secret-value --secret-id \"{norm_name}\" --secret-string \"{val_escaped}\" --region {self.region}"
        )

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

        # 1. Try create-secret
        cmd = [
            "aws",
            "secretsmanager",
            "create-secret",
            "--name",
            norm_secret_name,
            "--secret-string",
            secret_value,
            "--region",
            self.region,
            "--output",
            "json",
        ]
        if self.kms_key_id:
            cmd.extend(["--kms-key-id", self.kms_key_id])
        if self.tags:
            tag_list = [{"Key": k, "Value": v} for k, v in self.tags.items()]
            cmd.extend(["--tags", json.dumps(tag_list)])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                arn = ""
                try:
                    data = json.loads(res.stdout)
                    arn = data.get("ARN", "")
                except Exception:
                    pass
                ref_uri = arn or f"aws-sm://{self.region}/{norm_secret_name}"
                return VaultResult(
                    success=True,
                    vault_type=self.vault_type,
                    secret_name=norm_secret_name,
                    reference_uri=ref_uri,
                    env_var_name=env_var_name,
                    metadata={"region": self.region, "arn": arn},
                )

            # If already exists, update with put-secret-value
            if "ResourceExistsException" in res.stderr:
                put_cmd = [
                    "aws",
                    "secretsmanager",
                    "put-secret-value",
                    "--secret-id",
                    norm_secret_name,
                    "--secret-string",
                    secret_value,
                    "--region",
                    self.region,
                    "--output",
                    "json",
                ]
                put_res = subprocess.run(put_cmd, capture_output=True, text=True, check=False)
                if put_res.returncode == 0:
                    ref_uri = f"aws-sm://{self.region}/{norm_secret_name}"
                    return VaultResult(
                        success=True,
                        vault_type=self.vault_type,
                        secret_name=norm_secret_name,
                        reference_uri=ref_uri,
                        env_var_name=env_var_name,
                        metadata={"region": self.region, "action": "updated"},
                    )
                err = put_res.stderr.strip()
                return VaultResult(
                    success=False,
                    vault_type=self.vault_type,
                    secret_name=norm_secret_name,
                    reference_uri="",
                    env_var_name=env_var_name,
                    error=f"Failed to update existing AWS secret: {err}",
                )

            err = res.stderr.strip() or res.stdout.strip()
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Failed to create secret in AWS Secrets Manager: {err}",
            )
        except Exception as e:
            return VaultResult(
                success=False,
                vault_type=self.vault_type,
                secret_name=norm_secret_name,
                reference_uri="",
                env_var_name=env_var_name,
                error=f"Exception writing to AWS Secrets Manager: {e}",
            )
