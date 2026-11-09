"""Unit tests for SecretShield configuration module."""

import json
from pathlib import Path
import tempfile
import unittest

from secretshield.config import (
    ShieldConfig,
    load_config,
    load_ignore_patterns,
    save_config,
)


class TestConfig(unittest.TestCase):

    def test_default_config(self):
        config = ShieldConfig()
        self.assertEqual(config.scanner_type, "auto")
        self.assertEqual(config.vault_provider, "google_secret_manager")
        self.assertEqual(config.remediation_mode, "interactive")
        self.assertEqual(config.entropy_threshold, 4.0)
        self.assertTrue(config.fail_on_detection)

    def test_save_and_load_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".secretshield.json"
            cfg = ShieldConfig(
                scanner_type="native",
                vault_provider="google_kms",
                vault_config={"project_id": "test-p", "location": "us-central1"},
                remediation_mode="auto",
                entropy_threshold=3.8,
            )
            saved_path = save_config(cfg, cfg_path)
            self.assertEqual(saved_path, cfg_path)
            self.assertTrue(cfg_path.exists())

            loaded = load_config(cfg_path)
            self.assertEqual(loaded.scanner_type, "native")
            self.assertEqual(loaded.vault_provider, "google_kms")
            self.assertEqual(loaded.vault_config.get("project_id"), "test-p")
            self.assertEqual(loaded.vault_config.get("location"), "us-central1")
            self.assertEqual(loaded.remediation_mode, "auto")
            self.assertAlmostEqual(loaded.entropy_threshold, 3.8)

    def test_load_ignore_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ignore_path = root / ".secretshieldignore"
            ignore_path.write_text(
                "# comments to ignore\n"
                "node_modules/\n"
                "*.lock\n"
                "\n"
                "tests/fixtures/secret.py\n",
                encoding="utf-8",
            )

            patterns = load_ignore_patterns(root)
            self.assertIn("node_modules/", patterns)
            self.assertIn("*.lock", patterns)
            self.assertIn("tests/fixtures/secret.py", patterns)
            self.assertNotIn("# comments to ignore", patterns)


if __name__ == "__main__":
    unittest.main()
