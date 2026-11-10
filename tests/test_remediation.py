"""Unit tests for SecretShield auto-remediation engine."""

from pathlib import Path
import tempfile
import unittest

from secretshield.remediation.engine import (
    RemediationPlan,
    apply_remediation_plan,
    create_remediation_plan,
    derive_env_var_name,
    generate_syntax_replacement,
)
from secretshield.scanner.base import Finding
from secretshield.vault.base import VaultResult


class TestRemediation(unittest.TestCase):

    def test_derive_env_var_name(self):
        f1 = Finding(
            rule_id="stripe_secret_key",
            file_path="src/billing.ts",
            line_number=1,
            line_content="",
            secret_raw="sk_live_123",
            masked_secret="sk_live_***",
            hint="STRIPE_SECRET_KEY",
        )
        self.assertEqual(derive_env_var_name(f1), "STRIPE_SECRET_KEY")

        f2 = Finding(
            rule_id="generic_secret",
            file_path="src/auth.ts",
            line_number=1,
            line_content="",
            secret_raw="12345",
            masked_secret="*****",
        )
        self.assertEqual(derive_env_var_name(f2), "AUTH_SECRET")

    def test_syntax_replacement_typescript(self):
        line = 'const apiKey = "sk_live_1234567890abcdef";'
        token, proposed = generate_syntax_replacement(
            file_path="src/index.ts",
            raw_secret="sk_live_1234567890abcdef",
            env_var_name="STRIPE_KEY",
            original_line=line,
        )
        self.assertEqual(token, "process.env.STRIPE_KEY")
        self.assertEqual(proposed, "const apiKey = process.env.STRIPE_KEY;")

    def test_syntax_replacement_python(self):
        line = 'api_key = "sk_live_1234567890abcdef"'
        token, proposed = generate_syntax_replacement(
            file_path="config.py",
            raw_secret="sk_live_1234567890abcdef",
            env_var_name="STRIPE_KEY",
            original_line=line,
        )
        self.assertEqual(token, 'os.getenv("STRIPE_KEY", "")')
        self.assertEqual(proposed, 'api_key = os.getenv("STRIPE_KEY", "")')

    def test_syntax_replacement_go(self):
        line = 'apiKey := "ghp_1234567890abcdef"'
        token, proposed = generate_syntax_replacement(
            file_path="main.go",
            raw_secret="ghp_1234567890abcdef",
            env_var_name="GITHUB_TOKEN",
            original_line=line,
        )
        self.assertEqual(token, 'os.Getenv("GITHUB_TOKEN")')
        self.assertEqual(proposed, 'apiKey := os.Getenv("GITHUB_TOKEN")')

    def test_syntax_replacement_yaml(self):
        line = '  apiKey: "sk_live_1234567890abcdef"'
        token, proposed = generate_syntax_replacement(
            file_path="values.yaml",
            raw_secret="sk_live_1234567890abcdef",
            env_var_name="STRIPE_KEY",
            original_line=line,
        )
        self.assertEqual(token, "${STRIPE_KEY}")
        self.assertEqual(proposed, '  apiKey: "${STRIPE_KEY}"')

    def test_syntax_replacement_dotenv(self):
        line = "STRIPE_KEY=sk_live_1234567890abcdef"
        vault_res = VaultResult(
            success=True,
            vault_type="google_secret_manager",
            secret_name="STRIPE_KEY",
            reference_uri="gsm://projects/p/secrets/STRIPE_KEY/versions/latest",
            env_var_name="STRIPE_KEY",
        )
        token, proposed = generate_syntax_replacement(
            file_path=".env",
            raw_secret="sk_live_1234567890abcdef",
            env_var_name="STRIPE_KEY",
            original_line=line,
            vault_result=vault_res,
        )
        self.assertIn("Migrated by SecretShield", proposed)

    def test_apply_remediation_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_file = root / "src" / "api.py"
            target_file.parent.mkdir(parents=True)
            target_file.write_text(
                'import os\n\nAPI_KEY = "AIzaSyD-8472948294729482947294829482948294"\n\ndef call():\n    pass\n',
                encoding="utf-8",
            )

            finding = Finding(
                rule_id="google_api_key",
                file_path="src/api.py",
                line_number=3,
                line_content='API_KEY = "AIzaSyD-8472948294729482947294829482948294"',
                secret_raw="AIzaSyD-8472948294729482947294829482948294",
                masked_secret="AIzaSyD-8472948294729482947294829482948294",
                hint="GOOGLE_API_KEY",
            )

            plan = create_remediation_plan(
                finding=finding,
                repo_root=root,
            )
            success, err = apply_remediation_plan(plan)
            self.assertTrue(success)
            self.assertIsNone(err)

            # Check modified file
            new_content = target_file.read_text(encoding="utf-8")
            self.assertIn('API_KEY = os.getenv("GOOGLE_API_KEY", "")', new_content)
            self.assertNotIn("AIzaSyD-8472948294729482947294829482948294", new_content)

    def test_remediation_suggestion_and_script(self):
        from secretshield.config import ShieldConfig
        from secretshield.vault import get_vault_provider
        from secretshield.remediation.engine import (
            format_all_suggestions,
            format_remediation_suggestion,
            generate_remediation_script,
        )

        config = ShieldConfig(vault_provider="google_secret_manager")
        config.vault_config["project_id"] = "test-project"
        provider = get_vault_provider("google_secret_manager", config)

        finding = Finding(
            rule_id="stripe_secret_key",
            file_path="services/billing.ts",
            line_number=5,
            line_content='const key = "sk_live_1234567890abcdef";',
            secret_raw="sk_live_1234567890abcdef",
            masked_secret="sk_live_*****",
            hint="STRIPE_SECRET_KEY",
        )

        plan = create_remediation_plan(
            finding=finding,
            vault_provider=provider,
        )

        self.assertIn("gcloud secrets create STRIPE_SECRET_KEY", plan.vault_command)
        self.assertIn("test-project", plan.vault_command)
        self.assertEqual(plan.access_snippet, "process.env.STRIPE_SECRET_KEY")

        suggestion = format_remediation_suggestion(plan)
        self.assertIn("STRIPE_SECRET_KEY", suggestion)
        self.assertIn("gcloud secrets", suggestion)
        self.assertIn("- const key =", suggestion)
        self.assertIn("+ const key =", suggestion)

        all_sugg = format_all_suggestions([plan])
        self.assertIn("REMEDIATION PLAYBOOK", all_sugg)

        script = generate_remediation_script([plan], "Google Cloud Secret Manager")
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("gcloud secrets create STRIPE_SECRET_KEY", script)



if __name__ == "__main__":
    unittest.main()
