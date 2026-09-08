# PersistHunt

PersistHunt is a Linux persistence detection framework written in Python.

---

## Developer Documentation

### Stage 1: Finding Engine

The finding engine provides a standardized representation for security findings. All PersistHunt detection modules use this engine to normalize findings across different persistence mechanisms.

#### Finding Model

A `Finding` represents a single security issue detected on the system:

- `id`: A unique identifier for the finding type (e.g., `PH-CRON-001`, `PH-SYSTEMD-001`).
- `category`: The security category (e.g., `cron`, `systemd`).
- `severity`: Severity level, one of `Severity` enum values (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `title`: Short human-readable summary.
- `description`: Detailed explanation of the detected condition.
- `evidence`: (Optional) The raw line, file reference, or diagnostic triggering detection.
- `location`: (Optional) The filesystem path and line number (e.g., `/etc/systemd/system/updater.service:4`).
- `recommendation`: (Optional) Actionable remediation advice.

#### Available Severity Levels

- `INFO`: Informational or diagnostic observations (e.g., access denied due to permissions).
- `LOW`: Minor anomalies, syntax issues, or broken references.
- `MEDIUM`: Suspicious characteristics that warrant investigation (e.g., execution from `/tmp`, inline interpreter commands).
- `HIGH`: Strong indicators of malicious activity or persistence (e.g., reverse shells, remote download piped to shell, encoded payloads).
- `CRITICAL`: Confirmed high-impact threats.

---

### Stage 2: Detector Architecture & Cron Persistence

Stage 2 establishes the reusable detector architecture and the first production detector: `CronDetector`.

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

##### Indicator Rules & Finding IDs (Cron)

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

---

### Stage 3: Systemd Persistence Detection

Stage 3 introduces `SystemdDetector` (`persisthunt.detectors.systemd`), auditing systemd service units, timers, drop-ins, and user units for persistence mechanisms.

#### Supported Locations

The detector inspects:
- **System administrator units**: `/etc/systemd/system/` (including `*.d/*.conf` drop-ins and `*.wants`/`*.requires` symlinks)
- **Runtime units**: `/run/systemd/system/`
- **Packaged vendor units**: `/usr/lib/systemd/system/` and `/lib/systemd/system/`
- **User-level units**: `~/.config/systemd/user/`, `/etc/systemd/user/`, `/usr/lib/systemd/user/`

#### Safe Unit Parsing

- **Pure Read-Only**: Unit files are read as text data without executing any directives.
- **Directive Awareness**: Audits `ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecReload`, `ExecStop`, and `ExecStopPost`.
- **Systemd Prefix Handling**: Safely parses command lines with systemd execution modifiers (`-`, `@`, `+`, `!`, `!!`, `:`).
- **Line Continuation**: Supports multi-line directives with backslash line continuations (`\`).
- **Permissions Audit**: Flags world-writable system unit files (`chmod 666`/`777`) that present local privilege escalation vulnerabilities.

#### Indicator Rules & Finding IDs (Systemd)

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-SYSTEMD-001` | systemd | `HIGH` | Interactive network utility or raw socket | `/dev/tcp`, `/dev/udp`, `nc`, `ncat`, `netcat`, `socat`, `mkfifo` in `Exec*` |
| `PH-SYSTEMD-002` | systemd | `HIGH` / `MEDIUM` | Remote download utility or piped execution | `curl ... \| bash`, `wget ... \| sh` (`HIGH`); standalone `curl`/`wget` (`MEDIUM`) |
| `PH-SYSTEMD-003` | systemd | `HIGH` | Service binary in temporary/writable directory | Binaries executing from `/tmp/`, `/var/tmp/`, `/dev/shm/` |
| `PH-SYSTEMD-004` | systemd | `MEDIUM` | Executable in hidden directory or hidden unit | Binary path containing hidden folder (e.g. `/.secret/`) or unit file starting with `.` |
| `PH-SYSTEMD-005` | systemd | `MEDIUM` | Inline interpreter command execution | `python -c`, `perl -e`, `bash -c`, `sh -c` in `Exec*` directives |
| `PH-SYSTEMD-006` | systemd | `HIGH` | Insecure unit file permissions | Unit file is world-writable in system directories |
| `PH-SYSTEMD-007` | systemd | `LOW` | System service executing from user home | System service executing binaries from `/home/<user>/` |
| `PH-SYSTEMD-090` | systemd | `INFO` | Unreadable systemd directory or file | `PermissionError` (diagnostic finding) |
| `PH-SYSTEMD-091` | systemd | `LOW` | Broken symlink in unit directory | Target unit missing in `*.wants` or service link |
| `PH-SYSTEMD-092` | systemd | `LOW` | Malformed systemd unit directive | Line does not follow standard `Key=Value` syntax |

#### Safety Model

PersistHunt adheres strictly to non-invasive, auditing-only operation:
- **No Service Management**: Never calls `systemctl start`, `stop`, `enable`, `disable`, or `daemon-reload`.
- **No Command Execution**: Never executes commands defined in `Exec*` directives.
- **No File Modifications**: Never creates, alters, or removes unit files or symlinks.
- **No Privilege Escalation**: Respects Linux permissions and records diagnostic findings when access is restricted.

#### Usage Example

```python
from persisthunt import SystemdDetector, Severity

# Initialize and scan
detector = SystemdDetector()
findings = detector.scan()

# Filter and analyze
print(f"Total findings: {findings.count()}")
print(f"Severity breakdown: {findings.severity_counts()}")

for finding in findings.by_severity(Severity.HIGH):
    print(f"[{finding.id}] {finding.title}")
    print(f"  Location: {finding.location}")
    print(f"  Evidence: {finding.evidence}")
    print(f"  Recommendation: {finding.recommendation}")
```

#### Example Finding Output

```json
{
  "id": "PH-SYSTEMD-003",
  "category": "systemd",
  "severity": "HIGH",
  "title": "Executable or script in temporary directory in systemd unit",
  "description": "ExecStart references or executes binaries from world-writable directories (/tmp, /var/tmp, /dev/shm). Attackers frequently stage persistence payloads in these locations.",
  "evidence": "/tmp/backdoor_daemon",
  "location": "/etc/systemd/system/backdoor.service:5",
  "recommendation": "Ensure service binaries are installed in standard protected directories (e.g. /usr/bin, /usr/local/bin) owned by root."
}
```

---

## Running Tests

Run the full test suite using `pytest`:

```bash
pytest
```

Run the demonstration script:

```bash
python demo.py
```
