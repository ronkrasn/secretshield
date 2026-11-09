"""Unit tests for SecretShield scanners."""

from pathlib import Path
import tempfile
import unittest

from secretshield.config import ShieldConfig
from secretshield.scanner import get_scanner
from secretshield.scanner.base import (
    calculate_shannon_entropy,
    is_line_ignored,
    mask_secret,
)
from secretshield.scanner.composite import CompositeScanner
from secretshield.scanner.gitleaks import GitleaksScanner
from secretshield.scanner.native import NativeScanner
from secretshield.scanner.trufflehog import TruffleHogScanner


class TestScanners(unittest.TestCase):

    def test_shannon_entropy(self):
        low_entropy = calculate_shannon_entropy("aaaaaaaaaaaa")
        self.assertAlmostEqual(low_entropy, 0.0)

        high_entropy = calculate_shannon_entropy("a8F#9xL2!zQ0@vN$")
        self.assertGreater(high_entropy, 3.5)

    def test_mask_secret(self):
        short_masked = mask_secret("short")
        self.assertEqual(short_masked, "*****")

        long_sec = "sk_live_51M0123456789abcdefghijklmnopqrstuvwxyz"
        long_masked = mask_secret(long_sec)
        self.assertTrue(long_masked.startswith("sk_live_51M"))
        self.assertTrue(long_masked.endswith("****"))
        self.assertNotIn("cdefghijkl", long_masked)

    def test_is_line_ignored(self):
        self.assertTrue(is_line_ignored("key = 'secret123'  # secretshield:ignore"))
        self.assertTrue(is_line_ignored("key = 'secret123'  # nosec"))
        self.assertTrue(is_line_ignored("key = 'secret123'  # pragma: allowlist secret"))
        self.assertFalse(is_line_ignored("key = 'secret123'  # regular comment"))

    def test_native_scanner_detection(self):
        scanner = NativeScanner()

        # Test Google API Key
        content_gcp = 'const key = "AIzaSyD-8472948294729482947294829482948294";'
        findings = scanner.scan_content(content_gcp, "app.ts")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "google_api_key")
        self.assertEqual(findings[0].hint, "GOOGLE_API_KEY")

        # Test OpenAI API Key
        content_openai = 'openai_api_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP"'
        findings = scanner.scan_content(content_openai, "config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "openai_api_key")
        self.assertEqual(findings[0].hint, "OPENAI_API_KEY")

        # Test Anthropic API Key
        content_anthropic = 'ANTHROPIC_KEY="sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-AA"'
        findings = scanner.scan_content(content_anthropic, ".env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "anthropic_api_key")

        # Test Stripe Key
        content_stripe = 'stripe_key = "sk_live_51M0123456789abcdefghijklmnopqrstuvwxyz"'
        findings = scanner.scan_content(content_stripe, "billing.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "stripe_secret_key")

        # Test GitHub Personal Access Token
        content_gh = 'gh_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"'
        findings = scanner.scan_content(content_gh, "deploy.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "github_pat")

        # Test Database URI with password
        content_db = 'db_url = "postgres://admin:SuperSecretPassword123@db.prod.internal:5432/mydb"'
        findings = scanner.scan_content(content_db, "db.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "database_uri_password")

    def test_native_scanner_scan_file_and_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            code_file = root / "src" / "index.js"
            code_file.parent.mkdir(parents=True)
            code_file.write_text(
                'const apiKey = "AIzaSyD-8472948294729482947294829482948294";\n',
                encoding="utf-8",
            )

            scanner = NativeScanner(repo_root=root)
            findings = scanner.scan_file(code_file)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].line_number, 1)

            dir_findings = scanner.scan_directory(root)
            self.assertEqual(len(dir_findings), 1)

    def test_gitleaks_output_parser(self):
        gitleaks = GitleaksScanner()
        raw_json = """[
          {
            "Description": "Stripe API Key",
            "File": "src/stripe.ts",
            "StartLine": 12,
            "Secret": "sk_live_51M0123456789abcdefghijklmnopqrstuvwxyz",
            "Match": "sk_live_51M0123456789abcdefghijklmnopqrstuvwxyz",
            "RuleID": "stripe-api-key",
            "Entropy": 4.5
          }
        ]"""
        findings = gitleaks._parse_gitleaks_json(raw_json)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "stripe-api-key")
        self.assertEqual(findings[0].file_path, "src/stripe.ts")
        self.assertEqual(findings[0].line_number, 12)
        self.assertEqual(findings[0].detector, "gitleaks")

    def test_trufflehog_output_parser(self):
        trufflehog = TruffleHogScanner()
        ndjson = '{"SourceMetadata":{"Data":{"Git":{"file":"config.py","line":5}}},"DetectorName":"Slack","Raw":"xoxb-1234567890-1234567890-abcdefghijklmnop"}\n'
        findings = trufflehog._parse_trufflehog_ndjson(ndjson)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "Slack")
        self.assertEqual(findings[0].file_path, "config.py")
        self.assertEqual(findings[0].line_number, 5)
        self.assertEqual(findings[0].detector, "trufflehog")

    def test_composite_scanner_deduplication(self):
        composite = CompositeScanner()
        scanner = NativeScanner()
        content = 'const token = "AIzaSyD-8472948294729482947294829482948294";'
        f1 = scanner.scan_content(content, "app.ts")
        f2 = scanner.scan_content(content, "app.ts")
        f2[0].detector = "gitleaks"

        merged = composite._merge_findings(f1 + f2)
        self.assertEqual(len(merged), 1)

    def test_get_scanner_factory(self):
        cfg = ShieldConfig(scanner_type="native")
        scanner = get_scanner(cfg)
        self.assertIsInstance(scanner, NativeScanner)


if __name__ == "__main__":
    unittest.main()
