import sys
import json
from pathlib import Path

# Ensure repository root is in sys.path when running example directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from persisthunt import CronDetector, SSHDetector, FindingCollection, generate_report


def main():
    findings = FindingCollection()

    # Run targeted detectors (e.g. Cron and SSH)
    cron_findings = CronDetector().scan()
    ssh_findings = SSHDetector().scan()

    findings.extend(cron_findings)
    findings.extend(ssh_findings)

    # Generate report with custom hostname metadata
    report = generate_report(findings, host="security-audit-node-01")

    # Serialize to JSON string
    json_output = report.to_json(indent=2)
    print("Generated JSON Report:")
    print(json_output[:400] + "\n... [truncated] ...\n")

    # Save to disk
    output_path = Path("audit_report.json")
    saved_file = report.save_json(output_path)
    print(f"Full JSON report saved to: {saved_file} ({saved_file.stat().st_size} bytes)")

    # Clean up example file
    output_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
