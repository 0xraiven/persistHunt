import json
import tempfile
import unittest
from pathlib import Path
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.reporting import ScanReport, Reporter, generate_report, TOOL_NAME, TOOL_VERSION

class TestReporting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def _create_sample_findings(self) -> FindingCollection:
        collection = FindingCollection()
        # 1 CRITICAL
        collection.add(Finding(
            id="PH-ACCT-001",
            category="account",
            severity=Severity.CRITICAL,
            title="Non-root user account with UID 0",
            description="Account 'toor' possesses UID 0.",
            evidence="Username: toor, UID: 0",
            location="/etc/passwd:toor",
            recommendation="Remove unauthorized UID 0 accounts.",
        ))
        # 2 HIGH
        collection.add(Finding(
            id="PH-PROC-001",
            category="process",
            severity=Severity.HIGH,
            title="Process executing from temporary directory",
            description="Process executing from /tmp/backdoor.",
            evidence="exe: /tmp/backdoor",
            location="PID 100",
            recommendation="Terminate process and remove binary.",
        ))
        collection.add(Finding(
            id="PH-SHELL-001",
            category="shell",
            severity=Severity.HIGH,
            title="Reverse shell in startup script",
            description="Raw socket redirection in .bashrc.",
            evidence=">& /dev/tcp/10.0.0.1/4444",
            location="/home/victim/.bashrc:3",
            recommendation="Remove reverse shell line.",
        ))
        # 3 MEDIUM
        for i in range(3):
            collection.add(Finding(
                id=f"PH-CRON-00{i+1}",
                category="cron",
                severity=Severity.MEDIUM,
                title=f"Medium cron issue {i+1}",
                description="Suspicious cron schedule.",
                evidence=f"/etc/cron.d/job{i+1}",
                location=f"/etc/cron.d/job{i+1}",
                recommendation="Audit cron job.",
            ))
        # 2 LOW
        for i in range(2):
            collection.add(Finding(
                id=f"PH-SYSTEMD-00{i+1}",
                category="systemd",
                severity=Severity.LOW,
                title=f"Low systemd issue {i+1}",
                description="Minor systemd service warning.",
                evidence="Standard warning",
                location=f"/etc/systemd/system/svc{i+1}.service",
                recommendation="Review service file.",
            ))
        return collection

    def test_json_schema_structure(self):
        findings = self._create_sample_findings()
        report = generate_report(
            findings,
            host="audit-target-01",
            timestamp="2026-09-08T12:00:00Z"
        )
        data = report.to_dict()

        # 1. Top-level required keys
        self.assertEqual(data["tool"], TOOL_NAME)
        self.assertEqual(data["version"], TOOL_VERSION)
        self.assertEqual(data["timestamp"], "2026-09-08T12:00:00Z")
        self.assertEqual(data["host"], "audit-target-01")
        self.assertIsInstance(data["risk_score"], float)
        self.assertIn("statistics", data)
        self.assertIn("findings", data)

        # 2. Statistics schema
        stats = data["statistics"]
        self.assertEqual(stats["total_findings"], 8)
        self.assertEqual(stats["highest_severity"], "CRITICAL")
        self.assertIn("severity_counts", stats)
        self.assertEqual(stats["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(stats["severity_counts"]["HIGH"], 2)
        self.assertEqual(stats["severity_counts"]["MEDIUM"], 3)
        self.assertEqual(stats["severity_counts"]["LOW"], 2)
        self.assertIn("category_counts", stats)
        self.assertEqual(stats["category_counts"]["account"], 1)
        self.assertEqual(stats["category_counts"]["process"], 1)
        self.assertEqual(stats["category_counts"]["shell"], 1)
        self.assertEqual(stats["category_counts"]["cron"], 3)
        self.assertEqual(stats["category_counts"]["systemd"], 2)

        # 3. Findings array
        self.assertEqual(len(data["findings"]), 8)
        first_finding = data["findings"][0]
        self.assertEqual(first_finding["id"], "PH-ACCT-001")
        self.assertEqual(first_finding["severity"], "CRITICAL")
        self.assertIn("title", first_finding)
        self.assertIn("description", first_finding)
        self.assertIn("evidence", first_finding)
        self.assertIn("location", first_finding)
        self.assertIn("recommendation", first_finding)

        # 4. JSON string serializability
        json_str = report.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["tool"], "PersistHunt")
        self.assertEqual(parsed["statistics"]["total_findings"], 8)

    def test_terminal_summary_output_exact_layout(self):
        """Verifies terminal output matches the requested layout:

        PersistHunt
        Linux Persistence Detection Framework

        Scan complete.

        Findings: 8

        CRITICAL: 1
        HIGH: 2
        MEDIUM: 3
        LOW: 2

        Risk Score: 7.2/10 (or calculated score)
        """
        findings = self._create_sample_findings()
        report = generate_report(findings)
        terminal_text = report.to_terminal(show_details=False)

        expected_header = (
            "PersistHunt\n"
            "Linux Persistence Detection Framework\n\n"
            "Scan complete.\n\n"
            "Findings: 8\n\n"
            "CRITICAL: 1\n"
            "HIGH: 2\n"
            "MEDIUM: 3\n"
            "LOW: 2\n\n"
            f"Risk Score: {report.risk_score:.1f}/10"
        )
        self.assertEqual(terminal_text, expected_header)

    def test_terminal_summary_with_details(self):
        findings = self._create_sample_findings()
        report = generate_report(findings)
        detailed_text = report.to_terminal(show_details=True)

        self.assertIn("=== Finding Summaries ===", detailed_text)
        self.assertIn("[CRITICAL] PH-ACCT-001 - Non-root user account with UID 0", detailed_text)
        self.assertIn("Location: /etc/passwd:toor", detailed_text)
        self.assertIn("Evidence: Username: toor, UID: 0", detailed_text)
        self.assertIn("Action: Remove unauthorized UID 0 accounts.", detailed_text)

    def test_empty_findings_report(self):
        empty_collection = FindingCollection()
        report = generate_report(empty_collection, host="clean-host")

        data = report.to_dict()
        self.assertEqual(data["statistics"]["total_findings"], 0)
        self.assertIsNone(data["statistics"]["highest_severity"])
        self.assertEqual(data["risk_score"], 0.0)
        self.assertEqual(len(data["findings"]), 0)

        terminal_text = report.to_terminal(show_details=False)
        self.assertIn("Findings: 0", terminal_text)
        self.assertIn("Risk Score: 0.0/10", terminal_text)

    def test_sensitive_information_handling(self):
        # Even if a finding contains sanitized credentials, ensure no unmasked secrets
        collection = FindingCollection()
        collection.add(Finding(
            id="PH-PROC-001",
            category="process",
            severity=Severity.HIGH,
            title="Process with sanitized credentials",
            description="Process run with token",
            evidence="cmd: /bin/agent --token ***REDACTED***",
            location="PID 100",
        ))

        report = generate_report(collection)
        json_output = report.to_json()
        term_output = report.to_terminal()
        html_output = report.to_html()

        self.assertIn("***REDACTED***", json_output)
        self.assertIn("***REDACTED***", term_output)
        self.assertIn("***REDACTED***", html_output)

    def test_html_report_generation(self):
        findings = self._create_sample_findings()
        report = generate_report(findings, host="web-server-01")
        html_content = report.to_html()

        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("<title>PersistHunt Audit Report - web-server-01</title>", html_content)
        self.assertIn("PH-ACCT-001", html_content)
        self.assertIn("PH-PROC-001", html_content)
        self.assertIn("CRITICAL", html_content)
        # Verify self-contained (no external CDNs or unneeded network links)
        self.assertNotIn('src="http', html_content)
        self.assertNotIn('href="http', html_content)

    def test_save_json_and_save_html(self):
        findings = self._create_sample_findings()
        report = generate_report(findings)

        json_file = self.tmp / "reports" / "scan.json"
        html_file = self.tmp / "reports" / "scan.html"

        saved_json = report.save_json(json_file)
        saved_html = report.save_html(html_file)

        self.assertTrue(saved_json.exists())
        self.assertTrue(saved_html.exists())

        loaded = json.loads(saved_json.read_text(encoding="utf-8"))
        self.assertEqual(loaded["tool"], "PersistHunt")
        self.assertIn("<!DOCTYPE html>", saved_html.read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
