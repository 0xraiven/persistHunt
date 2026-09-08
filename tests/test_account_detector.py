import os
import time
import tempfile
import unittest
from pathlib import Path
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.account import AccountDetector

class TestAccountDetector(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.test_dir.name)
        self.etc = self.root / "etc"
        self.etc.mkdir(parents=True)

        self.passwd_path = self.etc / "passwd"
        self.shadow_path = self.etc / "shadow"
        self.group_path = self.etc / "group"

        # Baseline empty files
        self.passwd_path.write_text("")
        self.shadow_path.write_text("")
        self.group_path.write_text("")

    def tearDown(self):
        self.test_dir.cleanup()

    def _get_detector(self) -> AccountDetector:
        return AccountDetector(
            root_prefix=self.root,
            passwd_path=self.passwd_path,
            shadow_path=self.shadow_path,
            group_path=self.group_path,
        )

    def test_empty_database_returns_empty_collection(self):
        detector = self._get_detector()
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_normal_standard_accounts_produce_zero_findings(self):
        self.passwd_path.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        )
        self.group_path.write_text(
            "root:x:0:\n"
            "daemon:x:1:\n"
            "alice:x:1000:\n"
        )
        # Passwords set long ago (over 100 days)
        old_days = int(time.time() / 86400) - 200
        self.shadow_path.write_text(
            f"root:$6$saltsalt$hashedpasswordblob12345:{old_days}:0:99999:7:::\n"
            f"daemon:*:{old_days}:0:99999:7:::\n"
            f"nobody:*:{old_days}:0:99999:7:::\n"
            f"alice:$6$saltsalt$hashedpasswordblob67890:{old_days}:0:99999:7:::\n"
        )

        detector = self._get_detector()
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_non_root_uid_0_account(self):
        self.passwd_path.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "toor:x:0:0:Backdoor Admin:/root:/bin/bash\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        self.assertGreaterEqual(findings.count(), 1)
        uid0_findings = [f for f in findings if f.id == "PH-ACCT-001"]
        self.assertEqual(len(uid0_findings), 1)
        self.assertEqual(uid0_findings[0].severity, Severity.CRITICAL)
        self.assertIn("toor", uid0_findings[0].evidence)

    def test_service_account_with_interactive_login_shell(self):
        self.passwd_path.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "www-data:x:33:33:www-data:/var/www:/bin/bash\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        shell_findings = [f for f in findings if f.id == "PH-ACCT-002"]
        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0].severity, Severity.HIGH)
        self.assertIn("www-data", shell_findings[0].evidence)

    def test_account_with_suspicious_tmp_home_directory(self):
        self.passwd_path.write_text(
            "backdoor_user:x:1001:1001:Evil:/tmp/backdoor_home:/bin/bash\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        home_findings = [f for f in findings if f.id == "PH-ACCT-003"]
        self.assertEqual(len(home_findings), 1)
        self.assertEqual(home_findings[0].severity, Severity.HIGH)
        self.assertIn("/tmp/backdoor_home", home_findings[0].evidence)

    def test_account_with_hidden_home_directory(self):
        self.passwd_path.write_text(
            "stealth:x:1002:1002:Stealth:/home/.hidden_stealth:/bin/bash\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        hidden_findings = [f for f in findings if f.id == "PH-ACCT-003"]
        self.assertEqual(len(hidden_findings), 1)
        self.assertEqual(hidden_findings[0].severity, Severity.HIGH)

    def test_empty_password_in_shadow(self):
        self.passwd_path.write_text(
            "insecure_user:x:1005:1005::/home/insecure:/bin/bash\n"
        )
        self.shadow_path.write_text(
            "insecure_user::19500:0:99999:7:::\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        empty_findings = [f for f in findings if f.id == "PH-ACCT-004"]
        self.assertEqual(len(empty_findings), 1)
        self.assertEqual(empty_findings[0].severity, Severity.CRITICAL)

    def test_account_with_non_standard_shell_binary(self):
        self.passwd_path.write_text(
            "custom_user:x:1006:1006::/home/custom:/tmp/custom_shell.sh\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        shell_findings = [f for f in findings if f.id == "PH-ACCT-005"]
        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0].severity, Severity.HIGH)
        self.assertIn("/tmp/custom_shell.sh", shell_findings[0].evidence)

    def test_non_standard_account_in_admin_group(self):
        self.passwd_path.write_text(
            "guest:x:1007:1007:Guest:/home/guest:/bin/bash\n"
        )
        self.group_path.write_text(
            "sudo:x:27:guest\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        group_findings = [f for f in findings if f.id == "PH-ACCT-006"]
        self.assertEqual(len(group_findings), 1)
        self.assertEqual(group_findings[0].severity, Severity.MEDIUM)
        self.assertIn("sudo", group_findings[0].evidence)

    def test_recently_created_account(self):
        self.passwd_path.write_text(
            "new_user:x:1008:1008:New User:/home/new_user:/bin/bash\n"
        )
        # Modified 2 days ago
        recent_days = int(time.time() / 86400) - 2
        self.shadow_path.write_text(
            f"new_user:$6$saltsalt$hashedval:{recent_days}:0:99999:7:::\n"
        )

        detector = self._get_detector()
        findings = detector.scan()

        recent_findings = [f for f in findings if f.id == "PH-ACCT-007"]
        self.assertEqual(len(recent_findings), 1)
        self.assertEqual(recent_findings[0].severity, Severity.LOW)

    def test_missing_passwd_file_handled_safely(self):
        non_existent = self.root / "etc" / "missing_passwd"
        detector = AccountDetector(
            passwd_path=non_existent,
            shadow_path=self.shadow_path,
            group_path=self.group_path,
        )
        findings = detector.scan()

        self.assertEqual(findings.count(), 1)
        finding = list(findings)[0]
        self.assertEqual(finding.id, "PH-ACCT-090")
        self.assertEqual(finding.severity, Severity.INFO)

    def test_password_hash_privacy_shielding(self):
        raw_hash = "$6$supersecretcryptohashstring$unpredictablesecretdata12345"
        self.passwd_path.write_text("alice:x:1000:1000::/home/alice:/bin/bash\n")
        self.shadow_path.write_text(f"alice:{raw_hash}:18000:0:99999:7:::\n")

        detector = self._get_detector()
        findings = detector.scan()

        for f in findings:
            self.assertNotIn(raw_hash, str(f.evidence))
            self.assertNotIn(raw_hash, str(f.description))

    def test_read_only_safety_preserves_account_files(self):
        passwd_content = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
        self.passwd_path.write_text(passwd_content)
        shadow_content = "root:*:19000:0:99999:7:::\nalice:*:19000:0:99999:7:::\n"
        self.shadow_path.write_text(shadow_content)

        detector = self._get_detector()
        detector.scan()

        self.assertEqual(self.passwd_path.read_text(), passwd_content)
        self.assertEqual(self.shadow_path.read_text(), shadow_content)

    def test_real_system_account_scan_does_not_crash(self):
        detector = AccountDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.category, "account")
            self.assertTrue(f.id.startswith("PH-ACCT-"))

if __name__ == "__main__":
    unittest.main()
