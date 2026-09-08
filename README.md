# PersistHunt

PersistHunt is a Linux persistence detection framework written in Python.

---

## Developer Documentation

### Stage 1: Finding Engine

The finding engine provides a standardized representation for security findings. All PersistHunt detection modules use this engine to normalize findings across different persistence mechanisms.

#### Finding Model

A `Finding` represents a single security issue detected on the system:

- `id`: A unique identifier for the finding type (e.g., `PH-CRON-001`, `PH-SYSTEMD-001`, `PH-SSH-001`, `PH-SHELL-001`, `PH-SUID-001`, `PH-PROC-001`, `PH-ACCT-001`).
- `category`: The security category (e.g., `cron`, `systemd`, `ssh`, `shell`, `suid`, `process`, `account`).
- `severity`: Severity level, one of `Severity` enum values (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `title`: Short human-readable summary.
- `description`: Detailed explanation of the detected condition.
- `evidence`: (Optional) The raw line, file reference, or diagnostic triggering detection.
- `location`: (Optional) The filesystem path and line number (e.g., `/home/victim/.bashrc:3`).
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

---

### Stage 4: SSH Persistence Detection

Stage 4 introduces `SSHDetector` (`persisthunt.detectors.ssh`), auditing SSH authentication keys, key options, filesystem permissions, and daemon configurations for persistence mechanisms.

#### Supported Locations

The detector inspects:
- **Root authorized keys**: `/root/.ssh/authorized_keys`, `/root/.ssh/authorized_keys2`
- **User authorized keys**: `/home/*/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys2`
- **Service account homes**: `/var/www/.ssh/`, `/var/lib/*/.ssh/`, `/srv/.ssh/`
- **SSH daemon configuration**: `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*.conf`

#### Indicator Rules & Finding IDs (SSH)

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-SSH-001` | ssh | `LOW` | Root authorized keys present | Presence of active authorized keys allowing direct root SSH login |
| `PH-SSH-002` | ssh | `HIGH` / `MEDIUM` | Forced command in authorized key | `command="..."` option enforcing execution; `HIGH` if matching suspicious indicators (`/tmp`, `curl`, reverse shell) |
| `PH-SSH-003` | ssh | `HIGH` | Service account authorized keys | Non-login daemon accounts (`www-data`, `nobody`, `apache`) with SSH keys |
| `PH-SSH-004` | ssh | `HIGH` / `MEDIUM` | Insecure permissions on SSH path | World-writable (`HIGH`) or group-writable (`MEDIUM`) `.ssh/` or `authorized_keys` |
| `PH-SSH-005` | ssh | `HIGH` | Private key material in authorized keys | Private key header found inside authorized_keys file (redacted) |
| `PH-SSH-006` | ssh | `HIGH` / `MEDIUM` | Dangerous SSH daemon configuration | `PermitEmptyPasswords yes` (`HIGH`), `AuthorizedKeysFile /tmp/...` (`HIGH`), `PermitRootLogin yes` (`MEDIUM`), `AuthorizedKeysCommand` (`MEDIUM`) |
| `PH-SSH-090` | ssh | `INFO` | Unreadable SSH location | `PermissionError` (diagnostic finding) |
| `PH-SSH-091` | ssh | `LOW` | Broken symlink in SSH directory | Symlink pointing to missing key target |
| `PH-SSH-092` | ssh | `LOW` | Malformed authorized_keys line | Line fails OpenSSH public key syntax |

---

### Stage 5: Shell Startup Persistence Detection

Stage 5 introduces `ShellDetector` (`persisthunt.detectors.shell`), auditing shell initialization scripts for unauthorized commands, reverse shells, downloaders, and credential-harvesting aliases.

#### Supported Locations

The detector inspects:
- **System-wide shell startup files**:
  - `/etc/profile`
  - `/etc/profile.d/*.sh`
  - `/etc/bash.bashrc`, `/etc/bashrc`
  - `/etc/zsh/zprofile`, `/etc/zsh/zshrc`, `/etc/zshrc`
  - `/etc/environment`
- **User-level shell startup files**:
  - Root: `/root/.bashrc`, `/root/.profile`, `/root/.bash_profile`, `/root/.bash_login`, `/root/.zshrc`, `/root/.bash_aliases`
  - Users: `/home/*/.bashrc`, `/home/*/.profile`, `/home/*/.bash_profile`, `/home/*/.bash_login`, `/home/*/.zshrc`, `/home/*/.bash_aliases`

#### Safe Inspection Model

- **Never Sourced or Executed**: Shell scripts are never executed, sourced (`.`), or evaluated in a shell.
- **Untrusted Plaintext**: Content is parsed strictly as untrusted text line-by-line.
- **Concise Evidence**: Limits evidence strictly to the offending line and line number without dumping full files.

#### Indicator Rules & Finding IDs (Shell)

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-SHELL-001` | shell | `HIGH` | Interactive network utility or raw socket | `/dev/tcp`, `/dev/udp`, `nc`, `ncat`, `netcat`, `socat`, `mkfifo` |
| `PH-SHELL-002` | shell | `HIGH` / `MEDIUM` | Remote download utility or piped execution | `curl ... \| bash`, `wget ... \| sh` (`HIGH`); standalone `curl`/`wget` (`MEDIUM`) |
| `PH-SHELL-003` | shell | `HIGH` | Reference or execution from temporary directory | Paths referencing or executing from `/tmp/`, `/var/tmp/`, `/dev/shm/` |
| `PH-SHELL-004` | shell | `HIGH` / `MEDIUM` | Anomalous hidden path or binary executable | Execution from non-standard hidden folder (`MEDIUM`); binary file in startup path (`HIGH`) |
| `PH-SHELL-005` | shell | `MEDIUM` | Inline interpreter command execution | `python -c`, `perl -e`, `bash -c`, `sh -c` |
| `PH-SHELL-006` | shell | `HIGH` | Encoded payload execution | `base64 -d`, `base64 --decode` in pipeline |
| `PH-SHELL-007` | shell | `HIGH` | Privilege utility alias hijacking | `alias sudo=...`, `alias su=...`, `alias ssh=...` |
| `PH-SHELL-008` | shell | `HIGH` | Insecure world-writable startup file | Startup script is world-writable (`chmod 666`/`777`) |
| `PH-SHELL-090` | shell | `INFO` | Unreadable startup file or directory | `PermissionError` (diagnostic finding) |
| `PH-SHELL-091` | shell | `LOW` | Broken symlink in startup directory | Dangling symlink in `/etc/profile.d` |

#### Usage Example

```python
from persisthunt import ShellDetector, Severity

# Initialize and scan
detector = ShellDetector()
findings = detector.scan()

# Inspect high-severity shell findings
for finding in findings.by_severity(Severity.HIGH):
    print(f"[{finding.id}] {finding.title}")
    print(f"  Location: {finding.location}")
    print(f"  Evidence: {finding.evidence}")
    print(f"  Recommendation: {finding.recommendation}")
```

#### Example Finding Output

```json
{
  "id": "PH-SHELL-007",
  "category": "shell",
  "severity": "HIGH",
  "title": "Privilege or authentication utility alias defined in shell startup",
  "description": "Line defines an alias overriding a critical authentication or privilege utility (sudo, su, ssh). This technique is frequently used for credential theft or command interception.",
  "evidence": "alias sudo='/tmp/.sudo_logger'",
  "location": "/home/victim/.bashrc:5",
  "recommendation": "Audit the alias definition to ensure it does not intercept or log user credentials."
}
```

---

### Stage 6: SUID/SGID Persistence Detection

Stage 6 implements `SuidDetector` for discovering and auditing binaries possessing elevated SUID (`chmod u+s`) and SGID (`chmod g+s`) privilege bits.

#### Detection Scope & Strategy

`SuidDetector` performs safe, read-only enumeration of filesystem paths using pure Python filesystem APIs (`os.scandir` and `stat()` with `follow_symlinks=False`):

- **Standard Binary Paths**: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/usr/lib`, `/usr/libexec`.
- **Staging / Temporary Directories**: `/tmp`, `/var/tmp`, `/dev/shm`.
- **User / Home Directories**: `/home`, `/root`.
- **Third-Party / Non-Standard Directories**: `/opt`.

#### Safety & Performance Architecture

- **Strict Read-Only Execution**: Discovered binaries are never executed. No attempts are made to exploit binaries, escalate privileges, or alter file permissions.
- **Symlink Protection**: Linux kernels ignore SUID/SGID bits on symlinks. `SuidDetector` strictly inspects `is_symlink()` and avoids following symlinks to prevent redundant evaluations and infinite traversal loops.
- **Virtual Filesystem Exclusion**: Traversal automatically skips pseudo/virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`) and developer cache trees (`.git`, `.cache`, `node_modules`).
- **Calibrated Risk Model**: Normal system binaries (e.g., `/usr/bin/passwd`, `/usr/bin/sudo`) are cataloged as `INFO` rather than false-positive `CRITICAL` alerts. Critical and high severities are reserved for writable SUID files, SUID shells, and binaries placed in temporary or user directories.

#### Indicator Rules & Finding IDs (SUID/SGID)

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-SUID-001` | suid | `HIGH` | SUID/SGID binary in temporary or user directory | Binary with SUID/SGID in `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/home/`, `/root/` |
| `PH-SUID-002` | suid | `CRITICAL` | Insecure writable permissions on SUID/SGID binary | SUID/SGID binary is world-writable (`0o002`) or group-writable (`0o020`) |
| `PH-SUID-003` | suid | `HIGH` | Shell or script interpreter possessing SUID/SGID bits | `bash`, `sh`, `dash`, `zsh`, `python`, `perl`, `ruby`, `busybox`, etc. |
| `PH-SUID-004` | suid | `MEDIUM` | SUID/SGID binary located in non-standard system directory | SUID/SGID binary residing outside standard system paths (e.g., `/opt/`) |
| `PH-SUID-005` | suid | `INFO` | Standard system SUID/SGID binary inventory | Standard administrative utility (`/usr/bin/passwd`, `/usr/bin/sudo`, etc.) |
| `PH-SUID-090` | suid | `INFO` | Unreadable directory during SUID scan | `PermissionError` (diagnostic finding) |

#### Usage Example

```python
from persisthunt import SuidDetector, Severity

# Initialize detector
detector = SuidDetector()

# Scan filesystem for SUID/SGID binaries
findings = detector.scan()

# Inspect high and critical findings
for finding in findings.filter(lambda f: f.severity in (Severity.HIGH, Severity.CRITICAL)):
    print(f"[{finding.severity.value}] {finding.id} - {finding.title}")
    print(f"  Location: {finding.location}")
    print(f"  Evidence: {finding.evidence}")
    print(f"  Recommendation: {finding.recommendation}")
```

#### Example Finding Output

```json
{
  "id": "PH-SUID-002",
  "category": "suid",
  "severity": "CRITICAL",
  "title": "Insecure writable permissions on SUID/SGID binary",
  "description": "Binary at /opt/legacy_tool has SUID/SGID bits set and is world-writable (0o4777). Any local user can overwrite the binary to execute arbitrary code with elevated privileges.",
  "evidence": "Permissions: 0o4777, Owner: root:root, SUID: True, SGID: False",
  "location": "/opt/legacy_tool",
  "recommendation": "Remove write permissions immediately: chmod go-w /opt/legacy_tool."
}
```

---

### Stage 7: Process and Account Persistence Detection

Stage 7 implements runtime process persistence auditing (`ProcessDetector`) and local account persistence auditing (`AccountDetector`).

---

#### 1. Process Persistence Detector (`ProcessDetector`)

`ProcessDetector` inspects active Linux processes via `/proc` to detect runtime persistence anomalies, memory-resident deleted payloads, reverse shells, and unauthorized child processes.

##### Safety & Privacy Architecture
- **Strict Read-Only Inspection**: Never signals or kills processes (`os.kill`), never attaches debuggers (`ptrace`), never injects code, and never accesses process memory (`/proc/[pid]/mem`).
- **Credential & Secret Sanitization**: Automatically masks passwords, authentication tokens, and API keys (`***REDACTED***`) in command line arguments. Never accesses or dumps `/proc/[pid]/environ`.
- **Transient Process Resiliency**: Gracefully handles short-lived processes that exit during inspection (`ProcessLookupError`, `FileNotFoundError`).

##### Indicator Rules & Finding IDs (Process)

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-PROC-001` | process | `HIGH` | Process executing from temporary or staging directory | Executable or cmdline in `/tmp/`, `/var/tmp/`, `/dev/shm/` |
| `PH-PROC-002` | process | `HIGH` | Process executing from hidden directory path | Executable path contains hidden folders (e.g., `.../.hidden/...`) |
| `PH-PROC-003` | process | `HIGH` | Running process with deleted binary on disk | `/proc/[pid]/exe` target ends with `(deleted)` |
| `PH-PROC-004` | process | `HIGH` | Suspicious command line execution | Reverse shell (`/dev/tcp`, `/dev/udp`), `nc -e`, `curl ... \| sh`, `base64 -d \| sh` |
| `PH-PROC-005` | process | `HIGH` | Web server or service daemon spawned interactive shell | Server parent (`nginx`, `apache2`, `httpd`, `mysqld`, etc.) spawned shell child (`sh`, `bash`) |
| `PH-PROC-006` | process | `MEDIUM` | Inline interpreter command execution | `python -c`, `perl -e`, `ruby -e`, `php -r` |
| `PH-PROC-090` | process | `INFO` | Process directory unavailable or unreadable | `PermissionError` (diagnostic finding) |

##### Usage Example (Process)

```python
from persisthunt import ProcessDetector, Severity

detector = ProcessDetector()
findings = detector.scan()

for finding in findings.filter(lambda f: f.severity in (Severity.HIGH, Severity.CRITICAL)):
    print(f"[{finding.severity.value}] {finding.id} - {finding.title}")
    print(f"  Location: {finding.location}")
    print(f"  Evidence: {finding.evidence}")
    print(f"  Recommendation: {finding.recommendation}")
```

---

#### 2. Account Persistence Detector (`AccountDetector`)

`AccountDetector` audits local authentication and identity databases (`/etc/passwd`, `/etc/shadow`, `/etc/group`) for backdoor accounts and privilege escalation vectors.

##### Safety & Privacy Architecture
- **Strict Read-Only Inspection**: Never modifies `/etc/passwd`, `/etc/shadow`, or `/etc/group`. Never alters passwords or locks accounts.
- **Hash Privacy Shielding**: Never displays, logs, or exports raw password hash strings from `/etc/shadow`. Only reports hash algorithm types or empty/locked status.
- **Permission Resiliency**: Handles unreadable `/etc/shadow` gracefully via diagnostic finding `PH-ACCT-090`.

##### Indicator Rules & Finding IDs (Account)

| Finding ID | Category | Severity | Description | Indicators |
|---|---|---|---|---|
| `PH-ACCT-001` | account | `CRITICAL` | Non-root account with UID 0 | Account other than `root` has `UID == 0` |
| `PH-ACCT-002` | account | `HIGH` | Service account with interactive login shell | System/service account configured with `/bin/bash`, `/bin/sh`, etc. |
| `PH-ACCT-003` | account | `HIGH` | Account configured with suspicious home directory | Home directory in `/tmp/`, `/var/tmp/`, `/dev/shm/`, or hidden directory |
| `PH-ACCT-004` | account | `CRITICAL` | Account configured with empty password | Empty password hash field in `/etc/shadow` |
| `PH-ACCT-005` | account | `HIGH` | User account with non-standard login shell | Shell pointing to non-standard or unusual binary path |
| `PH-ACCT-006` | account | `MEDIUM` | Non-standard account in administrative group | User account granted `sudo` or `wheel` membership |
| `PH-ACCT-007` | account | `LOW` | Recently created or modified local account | Shadow `last_change` timestamp modified within last 7 days |
| `PH-ACCT-090` | account | `INFO` | Account database unreadable | `PermissionError` on `/etc/shadow` or `/etc/passwd` |

##### Usage Example (Account)

```python
from persisthunt import AccountDetector, Severity

detector = AccountDetector()
findings = detector.scan()

for finding in findings.filter(lambda f: f.severity in (Severity.HIGH, Severity.CRITICAL)):
    print(f"[{finding.severity.value}] {finding.id} - {finding.title}")
    print(f"  Location: {finding.location}")
    print(f"  Evidence: {finding.evidence}")
    print(f"  Recommendation: {finding.recommendation}")
```

---

### Stage 8: Risk Scoring Engine

Stage 8 implements the deterministic, explainable, and detector-independent risk-scoring engine (`RiskScorer`, `RiskReport`, and `calculate_risk`).

#### Mathematical Model & Severity Weights

The scoring engine aggregates findings without naive averaging (which would artificially dilute severe threats when many benign or informational findings exist) and without unbounded sums:

##### Severity Weights

| Severity Level | Weight | Description |
|---|---|---|
| `INFO` | `0` | Informational or diagnostic observations |
| `LOW` | `1` | Minor anomalies or configuration warnings |
| `MEDIUM` | `3` | Suspicious characteristics or non-standard paths |
| `HIGH` | `6` | Strong indicators of persistence or reverse shells |
| `CRITICAL` | `10` | High-impact backdoors, UID 0 accounts, writable SUID |

##### Aggregation Formula

$$\text{Raw Score} = \sum_{f \in \text{findings}} \text{Weight}(f.\text{severity})$$

$$\text{Risk Score} = \min\left(10.0, \text{round}\left(\frac{\text{Raw Score}}{\text{divisor}}, 1\right)\right) \quad (\text{default } \text{divisor} = 5.0)$$

For example, a security audit discovering:
- 1 Critical (10 pts)
- 2 High (12 pts)
- 4 Medium (12 pts)
- 3 Low (3 pts)
- 1 Info (0 pts)

Yields a raw score of $10 + 12 + 12 + 3 + 0 = 37.0$.
$$\text{Risk Score} = \frac{37.0}{5.0} = 7.4 / 10.0$$

#### Output & Explainability

`RiskReport` exposes the overall score, severity counts, highest severity, raw score, breakdown by severity, and prioritized list of contributing findings:

##### Formatted Summary (`report.summary()`)

```text
Risk Score: 7.4/10

Critical: 1
High: 2
Medium: 4
Low: 3
Info: 1
```

##### Detailed Explanation (`report.explain()`)

```text
=== Risk Score Explanation ===
Overall Risk Score: 7.4 / 10 (Raw Weight: 37.0)
Total Findings: 11
Highest Severity Detected: CRITICAL

Severity Breakdown:
  - CRITICAL:  1 finding(s) x 10.0 weight =  10.0 pts
  - HIGH    :  2 finding(s) x  6.0 weight =  12.0 pts
  - MEDIUM  :  4 finding(s) x  3.0 weight =  12.0 pts
  - LOW     :  3 finding(s) x  1.0 weight =   3.0 pts
  - INFO    :  1 finding(s) x  0.0 weight =   0.0 pts

Top Contributing Findings:
  1. [CRITICAL] PH-ACCT-001 - Non-root user account with UID 0 at /etc/passwd:toor
  ...
```

#### Usage Example

```python
from persisthunt import CronDetector, SystemdDetector, calculate_risk

# Collect findings across detectors
findings = CronDetector().scan()
findings.extend(SystemdDetector().scan())

# Calculate risk report
report = calculate_risk(findings)

# Print standard summary
print(report.summary())

# Access structured attributes
print(f"Overall Score: {report.score}/{report.max_score}")
print(f"Highest Severity: {report.highest_severity}")
```

---

### Stage 9: Reporting and JSON Output

Stage 9 implements machine-readable and human-readable audit reporting (`ScanReport`, `Reporter`, and `generate_report`).

#### Supported Formats

1. **Terminal Output**: Clean console summary with finding totals, severity breakdown, risk score, and detailed remediation steps.
2. **JSON Schema**: Stable, machine-readable format suitable for SIEM, CI/CD pipelines, and automated security ingestion.
3. **HTML Report**: Clean, self-contained, responsive HTML report with embedded styling, designed for offline viewing in air-gapped environments without external dependencies.

#### Stable JSON Schema

```json
{
  "tool": "PersistHunt",
  "version": "0.1.0",
  "timestamp": "2026-09-08T07:31:12.331573+00:00",
  "host": "linux-prod-node-01",
  "risk_score": 6.6,
  "statistics": {
    "total_findings": 8,
    "highest_severity": "CRITICAL",
    "severity_counts": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 3,
      "LOW": 2,
      "INFO": 0
    },
    "category_counts": {
      "account": 1,
      "process": 1,
      "shell": 1,
      "cron": 3,
      "systemd": 2
    },
    "raw_score": 33.0
  },
  "findings": [
    {
      "id": "PH-ACCT-001",
      "category": "account",
      "severity": "CRITICAL",
      "title": "Non-root user account with UID 0 (root privileges)",
      "description": "Account 'toor' possesses UID 0.",
      "evidence": "Username: toor, UID: 0",
      "location": "/etc/passwd:toor",
      "recommendation": "Remove unauthorized UID 0 accounts immediately."
    }
  ]
}
```

#### Terminal Summary Format

```text
PersistHunt
Linux Persistence Detection Framework

Scan complete.

Findings: 8

CRITICAL: 1
HIGH: 2
MEDIUM: 3
LOW: 2

Risk Score: 7.2/10

=== Finding Summaries ===

1. [CRITICAL] PH-ACCT-001 - Non-root user account with UID 0 (root privileges)
   Location: /etc/passwd:toor
   Evidence: Username: toor, UID: 0
   Action: Remove unauthorized UID 0 accounts immediately.
...
```

#### Usage Example

```python
from persisthunt import (
    CronDetector,
    SystemdDetector,
    SSHDetector,
    ShellDetector,
    SuidDetector,
    ProcessDetector,
    AccountDetector,
    generate_report,
)

# 1. Run detectors
findings = CronDetector().scan()
findings.extend(SystemdDetector().scan())
findings.extend(SSHDetector().scan())
findings.extend(ShellDetector().scan())
findings.extend(SuidDetector().scan())
findings.extend(ProcessDetector().scan())
findings.extend(AccountDetector().scan())

# 2. Generate report
report = generate_report(findings, host="web-node-01")

# 3. Print terminal output
print(report.to_terminal())

# 4. Save JSON and HTML reports
report.save_json("audit_report.json")
report.save_html("audit_report.html")
```

---

### Stage 10: Command-Line Interface (CLI)

Stage 10 introduces the production command-line interface for PersistHunt (`persisthunt` / `python -m persisthunt`).

#### CLI Commands

| Command | Description |
|---|---|
| `persisthunt scan` | Run full system audit across all detectors and print terminal summary |
| `persisthunt scan --json` | Output scan results in machine-readable JSON format |
| `persisthunt scan --category cron` | Audit only cron persistence |
| `persisthunt scan -c cron,systemd,ssh` | Audit multiple comma-separated categories |
| `persisthunt scan --severity high` | Filter findings to only HIGH and CRITICAL severities |
| `persisthunt scan -o report.json` | Save scan report to JSON file |
| `persisthunt scan -o report.html` | Save scan report to self-contained HTML file |
| `persisthunt scan --exit-zero` | Return exit code 0 even if HIGH or CRITICAL threats are found |
| `persisthunt version` / `persisthunt -V` | Display PersistHunt version |
| `persisthunt --help` / `persisthunt scan --help` | Show command documentation and options |

#### Command-Line Options (`persisthunt scan`)

| Flag | Description |
|---|---|
| `--json` | Output scan results in machine-readable JSON to `stdout` |
| `-c`, `--category` | Filter detector execution by category (`cron`, `systemd`, `ssh`, `shell`, `suid`, `process`, `account`, or `all`). Can be repeated or comma-separated. |
| `-s`, `--severity` | Minimum severity threshold filter (`info`, `low`, `medium`, `high`, `critical`) |
| `-o`, `--output` | Save report to specified file path (`.json` or `.html` extension) |
| `-q`, `--quiet` | Suppress scan progress messages on `stderr` |
| `--exit-zero` | Enforce exit code 0 regardless of threats detected (useful for non-blocking CI) |
| `--root-prefix` | Target filesystem root prefix for offline container, disk image, or forensic mount inspection |

#### Exit Codes

| Code | Constant | Meaning |
|---|---|---|
| `0` | `EXIT_SUCCESS` | Scan completed successfully with no HIGH or CRITICAL threats detected (or `--exit-zero` used). |
| `1` | `EXIT_ERROR` | Operational error (e.g. invalid arguments or bad category name). |
| `2` | `EXIT_THREAT_DETECTED` | Scan completed and detected one or more HIGH or CRITICAL persistence threats. |

#### Stream Separation & Scripting

The CLI cleanly separates progress indicators and diagnostic messages from structured output:
- **`stderr`**: Progress updates (e.g. `[+] Scanning cron persistence...`) and operational error warnings.
- **`stdout`**: Scan reports (Terminal summary or JSON).

This guarantees that standard Unix piping works seamlessly without corrupting stdout streams:

```bash
# Pipe pure JSON directly to jq
persisthunt scan --json -q | jq '.findings[] | select(.severity == "CRITICAL")'

# Run in CI/CD pipeline and block builds on threats
persisthunt scan --severity high
if [ $? -eq 2 ]; then
    echo "High-severity persistence threats detected! Failing build."
    exit 1
fi
```

---

### Stage 11: Security Testing and Hardening

Stage 11 enforces comprehensive security, reliability, safety verification, detector isolation, and resource protection across the framework.

#### Safety Guarantees

PersistHunt adheres to strict read-only and non-interfering operational rules:

1. **Zero Command Execution**: PersistHunt never executes discovered commands, scripts, binaries, or suspicious payloads (`subprocess`, `os.system`, `os.popen`, `exec`, and `eval` are never invoked on inspected artifacts).
2. **Zero Filesystem or State Modifications**: PersistHunt never alters permissions (`chmod`), ownership (`chown`), persistence configurations, accounts, passwords, or systemd services. Discovered files are never deleted or modified.
3. **Zero External Network Transmissions**: PersistHunt never initiates outbound network connections or transmits telemetry/credentials. All scans are purely local and offline-safe.
4. **Secret & Credential Masking**: Password hashes (`/etc/shadow`), private SSH keys, and command-line authorization tokens are automatically sanitized or redacted before being recorded in findings.

#### Detector Isolation & Fault Tolerance

Detectors run with process-level isolation in the audit engine. A fatal exception or unhandled crash in one detector will never abort the remaining audit:

- Individual detector outcomes are tracked and reported in terminal summaries, JSON reports, and HTML badges:
  - **`successful`**: Detector executed completely without unhandled errors or permission restrictions.
  - **`permission-limited`**: Detector encountered permission barriers on one or more inspection paths (e.g. unprivileged user inspecting `/root/.ssh` or `/etc/shadow`), recording non-fatal diagnostic findings (`PH-*-090`).
  - **`failed`**: Detector experienced an unexpected runtime failure. The error is safely caught and logged without compromising the broader scan.

#### Filesystem & Resource Hardening

- **Special File / FIFO Protection**: Configuration readers verify `stat.S_ISREG` before opening files, preventing hangs or deadlocks caused by named pipes (`mkfifo`), character devices, or UNIX domain sockets placed in persistence paths.
- **Huge File & DoS Prevention**: Enforces a strict 10 MB maximum file size ceiling on configuration and startup scripts (`safe_read_lines`, `safe_read_text`), preventing memory exhaustion or denial-of-service attacks.
- **Circular Symlink & Traversal Bounds**: The SUID/SGID traversal engine enforces cycle detection using `(st_dev, st_ino)` tracking and a maximum recursion depth of 15, preventing infinite loops or runaway filesystem traversal.
- **Untrusted Character Handling**: Unicode filenames with emojis, non-ASCII characters, null bytes, and control characters are normalized with `errors="replace"` and serialized safely in JSON reports.

#### Safety Limitations

While PersistHunt provides extensive persistence detection, operators should understand the following boundaries:

- **Privilege Boundaries**: Unprivileged scans (`non-root`) cannot audit restricted files such as `/etc/shadow`, `/root/.ssh`, or user crontabs belonging to other accounts. For complete system visibility, run PersistHunt with root privileges.
- **Kernel-Level Persistence**: PersistHunt audits userland configurations, filesystem structures, and process trees. Kernel-level persistence (such as direct kernel memory tampering or malicious loadable kernel modules) requires dedicated kernel integrity or eBPF tooling.
- **Forensic Environment**: For offline container or disk image analysis, use the `--root-prefix` parameter to target mounted forensic images without risking interaction with the live host.

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


