import sys
from pathlib import Path

# Ensure repository root is in sys.path when running example directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from persisthunt import (
    CronDetector,
    SystemdDetector,
    SSHDetector,
    ShellDetector,
    SuidDetector,
    ProcessDetector,
    AccountDetector,
    FindingCollection,
    generate_report,
)


def main():
    print("Initializing PersistHunt persistence audit...")

    all_findings = FindingCollection()
    detectors = [
        CronDetector(),
        SystemdDetector(),
        SSHDetector(),
        ShellDetector(),
        SuidDetector(),
        ProcessDetector(),
        AccountDetector(),
    ]

    for detector in detectors:
        print(f"[*] Running {detector.name}...")
        findings = detector.scan()
        all_findings.extend(findings)

    print(f"\nAudit complete. Collected {len(all_findings)} finding(s). Generating report...\n")
    report = generate_report(all_findings)
    print(report.to_terminal(show_details=True))


if __name__ == "__main__":
    main()
