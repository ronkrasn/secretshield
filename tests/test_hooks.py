"""Unit tests for SecretShield Git hooks."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from secretshield.config import ShieldConfig, save_config
from secretshield.hooks.installer import install_git_hooks
from secretshield.hooks.pre_commit import run_pre_commit_hook
from secretshield.hooks.pre_push import run_pre_push_hook


class TestGitHooks(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        # Initialize test git repository
        subprocess.run(["git", "init"], cwd=self.root, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.root, check=True)

        # Write default config
        cfg = ShieldConfig(scanner_type="native", vault_provider="local_env", remediation_mode="interactive")
        save_config(cfg, self.root / ".secretshield.json")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_install_git_hooks(self):
        success = install_git_hooks(self.root)
        self.assertTrue(success)

        pre_commit = self.root / ".git" / "hooks" / "pre-commit"
        pre_push = self.root / ".git" / "hooks" / "pre-push"

        self.assertTrue(pre_commit.exists())
        self.assertTrue(pre_push.exists())
        self.assertTrue(pre_commit.stat().st_mode & 0o111)  # executable
        self.assertTrue(pre_push.stat().st_mode & 0o111)

    def test_pre_commit_hook_clean(self):
        # Stage a clean file
        clean_file = self.root / "README.md"
        clean_file.write_text("# Clean repository\nNo secrets here.\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.root, check=True)

        exit_code = run_pre_commit_hook(self.root)
        self.assertEqual(exit_code, 0)

    def test_pre_commit_hook_auto_remediate(self):
        # Configure auto-remediation with local_env
        cfg = ShieldConfig(scanner_type="native", vault_provider="local_env", remediation_mode="auto")
        save_config(cfg, self.root / ".secretshield.json")

        # Stage a file with a secret
        secret_file = self.root / "app.py"
        secret_file.write_text('API_KEY = "AIzaSyD-8472948294729482948294829482948294"\n', encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=self.root, check=True)

        exit_code = run_pre_commit_hook(self.root, auto_accept=True)
        self.assertEqual(exit_code, 0)

        # Check that file was remediated on disk
        new_content = secret_file.read_text(encoding="utf-8")
        self.assertIn('API_KEY = os.getenv("GOOGLE_API_KEY", "")', new_content)
        self.assertNotIn("AIzaSyD-8472948294729482948294829482948294", new_content)


if __name__ == "__main__":
    unittest.main()
