"""Unit tests for SecretShield vault providers."""

from pathlib import Path
import tempfile
import unittest

from secretshield.config import ShieldConfig
from secretshield.vault import (
    AWSSecretsManagerProvider,
    AzureKeyVaultProvider,
    GoogleKMSProvider,
    GoogleSecretManagerProvider,
    HashiCorpVaultProvider,
    LocalEnvProvider,
    get_vault_provider,
    list_vault_providers,
)


class TestVaultProviders(unittest.TestCase):

    def test_list_vault_providers(self):
        providers = list_vault_providers()
        ids = [p["id"] for p in providers]
        self.assertIn("google_secret_manager", ids)
        self.assertIn("google_kms", ids)
        self.assertIn("hashicorp_vault", ids)
        self.assertIn("aws_secrets_manager", ids)
        self.assertIn("azure_keyvault", ids)
        self.assertIn("local_env", ids)

    def test_local_env_provider(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = ShieldConfig(
                vault_provider="local_env",
                vault_config={"target_file": ".env.test"},
            )
            provider = LocalEnvProvider(cfg, repo_root=root)

            is_avail, _ = provider.is_available()
            self.assertTrue(is_avail)

            ok, _ = provider.test_connection()
            self.assertTrue(ok)

            # Store secret
            res = provider.store_secret("STRIPE_KEY", "sk_live_123456789")
            self.assertTrue(res.success)
            self.assertEqual(res.env_var_name, "STRIPE_KEY")
            self.assertEqual(res.reference_uri, "local-env://.env.test#STRIPE_KEY")

            # Check .env.test content
            env_file = root / ".env.test"
            self.assertTrue(env_file.exists())
            self.assertIn("STRIPE_KEY=sk_live_123456789", env_file.read_text(encoding="utf-8"))

            # Check .gitignore was updated
            gitignore_file = root / ".gitignore"
            self.assertTrue(gitignore_file.exists())
            self.assertIn(".env.test", gitignore_file.read_text(encoding="utf-8"))

            # Update existing secret in .env.test
            res_update = provider.store_secret("STRIPE_KEY", "sk_live_999999999")
            self.assertTrue(res_update.success)
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("STRIPE_KEY=sk_live_999999999", content)
            self.assertNotIn("sk_live_123456789", content)

    def test_google_secret_manager_normalization(self):
        cfg = ShieldConfig(
            vault_provider="google_secret_manager",
            vault_config={"project_id": "my-gcp-project"},
        )
        provider = GoogleSecretManagerProvider(cfg)
        norm_name = provider.normalize_secret_name("stripe.live.key!@#")
        self.assertEqual(norm_name, "STRIPE_LIVE_KEY")
        self.assertEqual(provider.normalize_env_var_name("stripe.live.key"), "STRIPE_LIVE_KEY")

    def test_google_kms_provider_configuration(self):
        cfg = ShieldConfig(
            vault_provider="google_kms",
            vault_config={
                "project_id": "my-gcp-project",
                "location": "us-central1",
                "keyring": "my-ring",
                "key": "my-key",
            },
        )
        provider = GoogleKMSProvider(cfg)
        self.assertEqual(provider.location, "us-central1")
        self.assertEqual(provider.keyring, "my-ring")
        self.assertEqual(provider.key, "my-key")

    def test_hashicorp_vault_configuration(self):
        cfg = ShieldConfig(
            vault_provider="hashicorp_vault",
            vault_config={
                "vault_addr": "https://vault.example.com:8200",
                "mount_path": "custom-secrets",
                "kv_version": 2,
            },
        )
        provider = HashiCorpVaultProvider(cfg)
        self.assertEqual(provider.vault_addr, "https://vault.example.com:8200")
        self.assertEqual(provider.mount_path, "custom-secrets")
        self.assertEqual(provider.kv_version, 2)
        norm = provider.normalize_secret_name("stripe_key")
        self.assertEqual(norm.lower(), "stripe-key")

    def test_azure_keyvault_normalization(self):
        cfg = ShieldConfig(
            vault_provider="azure_keyvault",
            vault_config={"vault_name": "my-vault"},
        )
        provider = AzureKeyVaultProvider(cfg)
        norm = provider.normalize_secret_name("stripe_secret_key_123")
        self.assertEqual(norm, "STRIPE-SECRET-KEY-123")
        self.assertNotIn("_", norm)

    def test_get_vault_provider_factory(self):
        cfg_gsm = ShieldConfig(vault_provider="google_secret_manager")
        p_gsm = get_vault_provider(config=cfg_gsm)
        self.assertIsInstance(p_gsm, GoogleSecretManagerProvider)

        cfg_kms = ShieldConfig(vault_provider="google_kms")
        p_kms = get_vault_provider(config=cfg_kms)
        self.assertIsInstance(p_kms, GoogleKMSProvider)

        cfg_aws = ShieldConfig(vault_provider="aws_secrets_manager")
        p_aws = get_vault_provider(config=cfg_aws)
        self.assertIsInstance(p_aws, AWSSecretsManagerProvider)

        cfg_az = ShieldConfig(vault_provider="azure_keyvault")
        p_az = get_vault_provider(config=cfg_az)
        self.assertIsInstance(p_az, AzureKeyVaultProvider)


if __name__ == "__main__":
    unittest.main()
