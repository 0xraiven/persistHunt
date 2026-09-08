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

## Running Tests

Run the full test suite using `pytest`:

```bash
pytest
```

Run the demonstration script:

```bash
python demo.py
```

