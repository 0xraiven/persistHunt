# Security Policy

The PersistHunt project takes security and responsible disclosure seriously. Because PersistHunt is an auditing framework designed to inspect potentially compromised or adversarial Linux systems, its safety, read-only guarantees, and robustness against malicious payloads are critical.

---

## Supported Versions

Only the latest active minor release receives security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability in PersistHunt, please report it through responsible, coordinated disclosure. **Do not create public issues or pull requests for undisclosed vulnerabilities.**

### Preferred Reporting Method

1. **GitHub Private Vulnerability Advisory**:
   - Go to [PersistHunt Security Advisories](https://github.com/0xraiven/persistHunt/security/advisories).
   - Click **"Report a vulnerability"** to open a private advisory draft.

2. **Email Security Contact**:
   - If GitHub Advisories are unavailable, email **security@0xraiven.dev** with:
     - Component / Detector affected.
     - Type of issue (e.g. arbitrary command execution, parser DoS, unsafe file write).
     - Step-by-step reproduction steps and proof-of-concept (PoC).
     - Impact analysis.

### Response Timelines

- **Initial Response**: Within 48 hours acknowledging receipt of your report.
- **Triage & Reproduction**: Within 5 business days confirming validity and assigning severity.
- **Patch & Advisory Release**: Coordinated fix release within 14–30 days depending on severity.

---

## What Constitutes a Security Vulnerability in PersistHunt?

PersistHunt enforces strict invariants. Violations of these invariants represent reportable security vulnerabilities:

1. **Arbitrary Code Execution (ACE)**:
   - Any scenario where PersistHunt executes commands, scripts, binaries, or interpreters found within target persistence files (e.g., cron jobs, systemd directives, `.bashrc`, authorized keys forced commands).
2. **Filesystem Mutation**:
   - Any scenario where PersistHunt modifies, overwrites, or deletes files or directories on the target system (with the exception of user-specified `-o` / `--output` report destination files).
3. **Denial of Service (DoS)**:
   - Any input structure (symlink loop, named pipe FIFO deadlock, deeply nested tree, huge file) that causes PersistHunt to hang indefinitely, deadlock, or exhaust system memory.
4. **Credential / Sensitive Data Leakage**:
   - PersistHunt printing raw SSH private keys, password hashes, or transmission of collected findings over external network sockets.
5. **Unauthorized Privilege Modification**:
   - Any attempt or vulnerability allowing PersistHunt or audited binaries to escalate privileges or alter security policies.

---

## Non-Vulnerabilities (Out of Scope)

The following behaviors are expected by design and do not qualify as security vulnerabilities:

- **Linux Discretionary Access Control (DAC) Restrictions**: Running `persisthunt` as an unprivileged user cannot inspect files strictly restricted to `root` (e.g. `/etc/shadow`, root-only `crontabs`). PersistHunt handles this by reporting informational `permission-limited` findings.
- **False Positives or Negatives**: Legitimate administrative scripts flagged as suspicious, or an esoteric persistence technique not yet detected by an existing detector. Please open a regular issue or detector proposal for these.
- **Vulnerabilities on the Audited Host**: Malicious configurations discovered on the host system are findings produced by the audit, not defects in PersistHunt itself.
