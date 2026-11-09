"""SecretShield Vault Providers factory and exports."""

from pathlib import Path
from typing import Dict, List, Optional, Type

from secretshield.config import ShieldConfig
from secretshield.vault.aws_secrets_manager import AWSSecretsManagerProvider
from secretshield.vault.azure_keyvault import AzureKeyVaultProvider
from secretshield.vault.base import BaseVaultProvider, VaultResult
from secretshield.vault.google_kms import GoogleKMSProvider
from secretshield.vault.google_secret_manager import GoogleSecretManagerProvider
from secretshield.vault.hashicorp_vault import HashiCorpVaultProvider
from secretshield.vault.local_env import LocalEnvProvider

VAULT_PROVIDERS: Dict[str, Type[BaseVaultProvider]] = {
    "google_secret_manager": GoogleSecretManagerProvider,
    "google_kms": GoogleKMSProvider,
    "hashicorp_vault": HashiCorpVaultProvider,
    "aws_secrets_manager": AWSSecretsManagerProvider,
    "azure_keyvault": AzureKeyVaultProvider,
    "local_env": LocalEnvProvider,
}

__all__ = [
    "BaseVaultProvider",
    "VaultResult",
    "GoogleSecretManagerProvider",
    "GoogleKMSProvider",
    "HashiCorpVaultProvider",
    "AWSSecretsManagerProvider",
    "AzureKeyVaultProvider",
    "LocalEnvProvider",
    "VAULT_PROVIDERS",
    "get_vault_provider",
    "list_vault_providers",
]


def list_vault_providers() -> List[Dict[str, str]]:
    """Return available vault providers and their human-readable labels."""
    return [
        {"id": "google_secret_manager", "name": "Google Cloud Secret Manager (GSM)"},
        {"id": "google_kms", "name": "Google Cloud Key Management Service (KMS Envelope Encryption)"},
        {"id": "hashicorp_vault", "name": "HashiCorp Vault KV"},
        {"id": "aws_secrets_manager", "name": "AWS Secrets Manager"},
        {"id": "azure_keyvault", "name": "Azure Key Vault"},
        {"id": "local_env", "name": "Local Env File (.env.staging / .env.local)"},
    ]


def get_vault_provider(
    provider_type: Optional[str] = None,
    config: Optional[ShieldConfig] = None,
    repo_root: Optional[Path] = None,
) -> BaseVaultProvider:
    """Instantiate the configured or requested vault provider."""
    if config is None:
        config = ShieldConfig()

    ptype = provider_type or config.vault_provider
    provider_cls = VAULT_PROVIDERS.get(ptype, LocalEnvProvider)
    return provider_cls(config=config, repo_root=repo_root)
