import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from persisthunt.cli import (
    main,
    EXIT_SUCCESS,
    EXIT_ERROR,
    EXIT_THREAT_DETECTED,
)
from persisthunt import __version__, Severity, Finding, FindingCollection

class TestCLI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_cli_help(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            with self.assertRaises(SystemExit) as cm:
                main(["--help"])
            self.assertEqual(cm.exception.code, 0)
            self.assertIn("PersistHunt", out.getvalue())

    def test_cli_no_arguments_shows_help(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            code = main([])
            self.assertEqual(code, EXIT_SUCCESS)
            self.assertIn("PersistHunt", err.getvalue())

    def test_cli_version_flag(self):
        with patch("sys.stdout", new=io.StringIO()) as out:
            code = main(["--version"])
            self.assertEqual(code, EXIT_SUCCESS)
            self.assertIn(f"PersistHunt {__version__}", out.getvalue())

    def test_cli_version_subcommand(self):
        with patch("sys.stdout", new=io.StringIO()) as out:
            code = main(["version"])
            self.assertEqual(code, EXIT_SUCCESS)
            self.assertIn(f"PersistHunt {__version__}", out.getvalue())

    def test_cli_scan_json_output(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            code = main(["scan", "--category", "cron", "--json", "--quiet"])
            # Validate output on stdout is valid JSON
            stdout_str = out.getvalue().strip()
            data = json.loads(stdout_str)
            self.assertEqual(data["tool"], "PersistHunt")
            self.assertEqual(data["version"], __version__)
            self.assertIn("statistics", data)
            self.assertIn("findings", data)

    def test_cli_category_filter(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            code = main(["scan", "--category", "cron", "--category", "systemd", "--json", "--quiet"])
            self.assertEqual(code, EXIT_SUCCESS)
            data = json.loads(out.getvalue())
            # Ensure findings only contain cron or systemd
            for f in data["findings"]:
                self.assertIn(f["category"], ("cron", "systemd"))

    def test_cli_comma_separated_categories(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            code = main(["scan", "--category", "ssh,shell", "--json", "--quiet"])
            self.assertEqual(code, EXIT_SUCCESS)
            data = json.loads(out.getvalue())
            for f in data["findings"]:
                self.assertIn(f["category"], ("ssh", "shell"))

    def test_cli_invalid_category_returns_error(self):
        with patch("sys.stderr", new=io.StringIO()) as err:
            code = main(["scan", "--category", "nonexistent_module"])
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("Unknown category 'nonexistent_module'", err.getvalue())

    def test_cli_severity_filter(self):
        class MockDetector:
            def scan(self):
                c = FindingCollection()
                c.add(Finding("PH-L", "cron", Severity.LOW, "Low", "Desc"))
                c.add(Finding("PH-M", "cron", Severity.MEDIUM, "Med", "Desc"))
                c.add(Finding("PH-H", "cron", Severity.HIGH, "High", "Desc"))
                return c

        with patch.dict("persisthunt.cli.DETECTOR_REGISTRY", {"cron": MockDetector}):
            # Filter for HIGH or above
            with patch("sys.stdout", new=io.StringIO()) as out, \
                 patch("sys.stderr", new=io.StringIO()):
                code = main(["scan", "-c", "cron", "--severity", "high", "--json", "--quiet"])
                self.assertEqual(code, EXIT_THREAT_DETECTED)
                data = json.loads(out.getvalue())
                self.assertEqual(len(data["findings"]), 1)
                self.assertEqual(data["findings"][0]["id"], "PH-H")

    def test_cli_exit_zero_flag(self):
        class ThreatDetector:
            def scan(self):
                c = FindingCollection()
                c.add(Finding("PH-CRIT", "cron", Severity.CRITICAL, "Critical Backdoor", "Desc"))
                return c

        with patch.dict("persisthunt.cli.DETECTOR_REGISTRY", {"cron": ThreatDetector}):
            with patch("sys.stdout", new=io.StringIO()), \
                 patch("sys.stderr", new=io.StringIO()):
                # Without --exit-zero: returns 2
                code_threat = main(["scan", "-c", "cron", "--quiet"])
                self.assertEqual(code_threat, EXIT_THREAT_DETECTED)

                # With --exit-zero: returns 0
                code_zero = main(["scan", "-c", "cron", "--exit-zero", "--quiet"])
                self.assertEqual(code_zero, EXIT_SUCCESS)

    def test_cli_save_output_json_and_html(self):
        json_file = self.tmp / "scan.json"
        html_file = self.tmp / "scan.html"

        with patch("sys.stdout", new=io.StringIO()), \
             patch("sys.stderr", new=io.StringIO()):
            code_json = main(["scan", "-c", "cron", "-o", str(json_file), "--quiet"])
            self.assertEqual(code_json, EXIT_SUCCESS)
            self.assertTrue(json_file.exists())

            code_html = main(["scan", "-c", "cron", "-o", str(html_file), "--quiet"])
            self.assertEqual(code_html, EXIT_SUCCESS)
            self.assertTrue(html_file.exists())
            self.assertIn("<!DOCTYPE html>", html_file.read_text())

    def test_cli_progress_messages_to_stderr(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            main(["scan", "-c", "cron", "--json"])
            # Stderr has progress message
            self.assertIn("[+] Scanning cron persistence...", err.getvalue())
            # Stdout has only JSON
            parsed = json.loads(out.getvalue())
            self.assertEqual(parsed["tool"], "PersistHunt")

if __name__ == "__main__":
    unittest.main()
