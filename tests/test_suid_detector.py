import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from persisthunt.detectors.suid import SuidDetector
from persisthunt.findings import FindingCollection, Finding, Severity

class TestSuidDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Directory layout
        self.usr_bin = self.root / "usr" / "bin"
        self.usr_bin.mkdir(parents=True)

        self.tmp = self.root / "tmp"
        self.tmp.mkdir(parents=True)

        self.home_alice = self.root / "home" / "alice"
        self.home_alice.mkdir(parents=True)

        self.opt = self.root / "opt" / "tools"
        self.opt.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_detector(self):
        return SuidDetector(
            root_prefix=self.root,
            search_paths=[self.usr_bin, self.tmp, self.home_alice, self.opt],
        )

    def test_empty_system_returns_empty_collection(self):
        detector = self._get_detector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_missing_directories_do_not_crash(self):
        detector = SuidDetector(
            search_paths=[self.root / "nonexistent_bin", self.root / "nonexistent_tmp"]
        )
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 0)

    def test_normal_non_suid_binary_is_ignored(self):
        bin_file = self.usr_bin / "ls"
        bin_file.write_bytes(b"\x7fELF\x02\x01\x01")
        bin_file.chmod(0o755)

        detector = self._get_detector()
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_standard_system_suid_binary(self):
        passwd_file = self.usr_bin / "passwd"
        passwd_file.write_bytes(b"\x7fELF\x02\x01\x01")
        passwd_file.chmod(0o4755)  # SUID bit set

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(findings.count(), 1)
        finding = list(findings)[0]
        self.assertEqual(finding.id, "PH-SUID-005")
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertIn("Standard system SUID/SGID", finding.title)
        self.assertIn("SUID: True", finding.evidence)

    def test_sgid_detection_works(self):
        wall_file = self.usr_bin / "wall"
        wall_file.write_bytes(b"\x7fELF\x02\x01\x01")
        wall_file.chmod(0o2755)  # SGID bit set

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(findings.count(), 1)
        finding = list(findings)[0]
        self.assertEqual(finding.id, "PH-SUID-005")
        self.assertIn("SGID: True", finding.evidence)

    def test_suid_binary_in_tmp_directory(self):
        backdoor = self.tmp / "backdoor"
        backdoor.write_bytes(b"\x7fELF\x02\x01\x01")
        backdoor.chmod(0o4755)

        detector = self._get_detector()
        findings = detector.scan()

        tmp_findings = [f for f in findings if f.id == "PH-SUID-001"]
        self.assertEqual(len(tmp_findings), 1)
        self.assertEqual(tmp_findings[0].severity, Severity.HIGH)
        self.assertIn("temporary or world-writable directory", tmp_findings[0].title)

    def test_suid_binary_in_user_home_directory(self):
        user_agent = self.home_alice / "stealth_agent"
        user_agent.write_bytes(b"\x7fELF\x02\x01\x01")
        user_agent.chmod(0o4755)

        detector = self._get_detector()
        findings = detector.scan()

        home_findings = [f for f in findings if f.id == "PH-SUID-001"]
        self.assertEqual(len(home_findings), 1)
        self.assertEqual(home_findings[0].severity, Severity.HIGH)
        self.assertIn("user directory", home_findings[0].title)

    def test_insecure_world_writable_suid_binary(self):
        vuln_binary = self.usr_bin / "vuln_tool"
        vuln_binary.write_bytes(b"\x7fELF\x02\x01\x01")
        vuln_binary.chmod(0o4777)  # SUID + world-writable

        detector = self._get_detector()
        findings = detector.scan()

        crit_findings = [f for f in findings if f.id == "PH-SUID-002"]
        self.assertEqual(len(crit_findings), 1)
        self.assertEqual(crit_findings[0].severity, Severity.CRITICAL)
        self.assertIn("world-writable", crit_findings[0].description)

    def test_insecure_group_writable_suid_binary(self):
        vuln_binary = self.usr_bin / "group_vuln"
        vuln_binary.write_bytes(b"\x7fELF\x02\x01\x01")
        vuln_binary.chmod(0o4770)  # SUID + group-writable

        detector = self._get_detector()
        findings = detector.scan()

        crit_findings = [f for f in findings if f.id == "PH-SUID-002"]
        self.assertEqual(len(crit_findings), 1)
        self.assertEqual(crit_findings[0].severity, Severity.CRITICAL)

    def test_suid_shell_or_interpreter(self):
        suid_bash = self.usr_bin / "bash"
        suid_bash.write_bytes(b"\x7fELF\x02\x01\x01")
        suid_bash.chmod(0o4755)

        detector = self._get_detector()
        findings = detector.scan()

        shell_findings = [f for f in findings if f.id == "PH-SUID-003"]
        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0].severity, Severity.HIGH)
        self.assertIn("Shell or script interpreter", shell_findings[0].title)

    def test_suid_in_non_standard_location(self):
        custom_bin = self.opt / "custom_helper"
        custom_bin.write_bytes(b"\x7fELF\x02\x01\x01")
        custom_bin.chmod(0o4755)

        detector = self._get_detector()
        findings = detector.scan()

        opt_findings = [f for f in findings if f.id == "PH-SUID-004"]
        self.assertEqual(len(opt_findings), 1)
        self.assertEqual(opt_findings[0].severity, Severity.MEDIUM)
        self.assertIn("non-standard system directory", opt_findings[0].title)

    def test_symlinks_are_skipped(self):
        target = self.usr_bin / "real_suid"
        target.write_bytes(b"\x7fELF\x02\x01\x01")
        target.chmod(0o4755)

        symlink = self.usr_bin / "suid_link"
        symlink.symlink_to(target)

        detector = self._get_detector()
        findings = detector.scan()

        # Only the real file should produce a finding, not the symlink
        locations = [f.location for f in findings]
        self.assertIn(str(target), locations)
        self.assertNotIn(str(symlink), locations)

    def test_permission_denied_directory_handling(self):
        with patch("os.scandir", side_effect=PermissionError("Permission denied")):
            detector = self._get_detector()
            findings = detector.scan()

            perm_findings = [f for f in findings if f.id == "PH-SUID-090"]
            self.assertGreaterEqual(len(perm_findings), 1)
            self.assertEqual(perm_findings[0].severity, Severity.INFO)

    def test_read_only_safety_preserves_files(self):
        binary = self.usr_bin / "safe_suid"
        original_bytes = b"\x7fELF\x02\x01\x01\x00"
        binary.write_bytes(original_bytes)
        binary.chmod(0o4755)

        mode_before = binary.stat().st_mode
        mtime_before = binary.stat().st_mtime_ns

        detector = self._get_detector()
        findings = detector.scan()

        self.assertEqual(binary.read_bytes(), original_bytes)
        self.assertEqual(binary.stat().st_mode, mode_before)
        self.assertEqual(binary.stat().st_mtime_ns, mtime_before)

    def test_real_system_scan_does_not_crash(self):
        detector = SuidDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.category, "suid")
            self.assertTrue(f.id.startswith("PH-SUID-"))
            self.assertIsInstance(f.severity, Severity)

if __name__ == "__main__":
    unittest.main()
