"""Unit tests for SecretShield CLI interface."""

import json
from pathlib import Path
import tempfile
import unittest

from secretshield.cli import build_parser, format_findings_table, main
from secretshield.scanner.base import Finding


class TestCLI(unittest.TestCase):

    def test_parser_setup(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--staged"])
        self.assertEqual(args.command, "scan")
        self.assertTrue(args.staged)

        args = parser.parse_args(["scan", "--path", "src/"])
        self.assertEqual(args.path, "src/")

        args = parser.parse_args(["test-vault", "--provider", "local_env"])
        self.assertEqual(args.command, "test-vault")
        self.assertEqual(args.provider, "local_env")

        args = parser.parse_args(["install-hooks", "--githooks-dir"])
        self.assertEqual(args.command, "install-hooks")
        self.assertTrue(args.githooks_dir)

        args = parser.parse_args(["remediate", "--all", "--vault", "aws_secrets_manager", "--export-script", "migrate.sh"])
        self.assertEqual(args.command, "remediate")
        self.assertTrue(args.all)
        self.assertEqual(args.vault, "aws_secrets_manager")
        self.assertEqual(args.export_script, "migrate.sh")

        args = parser.parse_args(["scan", "--suggest"])
        self.assertEqual(args.command, "scan")
        self.assertTrue(args.suggest)

    def test_format_findings_table(self):
        # Empty findings
        empty_msg = format_findings_table([])
        self.assertIn("No secrets detected", empty_msg)

        # With findings
        f = Finding(
            rule_id="stripe_secret_key",
            file_path="src/index.ts",
            line_number=10,
            line_content='const s = "sk_live_12345";',
            secret_raw="sk_live_12345",
            masked_secret="sk_live_*****",
            detector="native",
        )
        table = format_findings_table([f])
        self.assertIn("SecretShield", table)
        self.assertIn("stripe_secret_key", table)
        self.assertIn("src/index.ts:10", table)

    def test_cli_main_help(self):
        exit_code = main([])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
