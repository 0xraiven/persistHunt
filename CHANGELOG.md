# Changelog

All notable changes to **PersistHunt** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Native Wazuh agent integration decoders and rule templates.
- eBPF-based real-time runtime persistence monitoring.
- High-frequency systemd timer heuristic analysis.
- Automated Auditd rule generator matching discovered persistence vectors.

---

## [0.1.0] - 2026-09-08

### Added
- **Core Persistence Detectors (7 Categories)**:
  - `CronDetector` (`cron`): Audits system crontabs (`/etc/crontab`, `/etc/cron.*`), user spools (`/var/spool/cron/crontabs`), and anacron entries for reverse shells, download pipes, inline interpreter executions, and non-standard commands.
  - `SystemdDetector` (`systemd`): Enumerates system and user service units, timers, generators, and drop-in overrides (`*.d/*.conf`) for suspicious `ExecStart`/`ExecStartPre` directives, `/tmp` executions, and network sockets.
  - `SSHDetector` (`ssh`): Audits `authorized_keys` across `/root` and `/home/*`, detecting unauthorized forced commands, wildcard restrictions, and insecure `sshd_config` directives while shielding sensitive private key material.
  - `ShellDetector` (`shell`): Audits profile and startup files (`/etc/profile`, `/etc/profile.d/*`, `~/.bashrc`, `~/.zshrc`, `~/.profile`) safely as untrusted text without sourcing or executing commands.
  - `SuidDetector` (`suid`): Discovers SUID (`chmod u+s`) and SGID (`chmod g+s`) binaries across the filesystem, identifying non-standard locations (`/tmp`, `/dev/shm`), user-writable permissions, and elevated interpreters.
  - `ProcessDetector` (`process`): Safely inspects active processes via `/proc` (without attaching debuggers or injecting code) to flag executions from temporary/hidden paths, deleted binaries (`(deleted)`), and interpreter chains.
  - `AccountDetector` (`account`): Audits `/etc/passwd` and `/etc/shadow` for rogue non-root UID 0 accounts, interactive shells on system accounts, and missing shadow entries.
- **Deterministic Risk Scoring Engine**:
  - `RiskScorer` & `RiskReport` computing standardized 0.0–10.0 risk scores based on explicit mathematical weights (`INFO`=0, `LOW`=1, `MEDIUM`=3, `HIGH`=6, `CRITICAL`=10).
  - Built-in explainability breakdown detailing exact points, highest severity found, and top contributing findings.
- **Multi-Format Reporting Engine**:
  - Stable machine-readable JSON schema output with metadata, statistics, and finding details.
  - Human-readable ANSI terminal output formatted for rapid command-line triage.
  - Self-contained, single-file HTML report export with zero external CDN dependencies for air-gapped environments.
- **Production CLI (`persisthunt`)**:
  - Subcommands: `persisthunt scan` and `persisthunt version`.
  - Flags: `--json`, `-c`/`--category`, `-s`/`--severity`, `-o`/`--output`, `-q`/`--quiet`, `--exit-zero`, and `--root-prefix`.
  - Offline / container forensic analysis support via `--root-prefix`.
  - Scriptable Unix exit codes (`0` clean, `1` error, `2` high/critical threat detected).
- **Security Hardening & Safety Invariants**:
  - `safe_read_lines()` and `safe_read_text()` preventing FIFO/device blocking deadlocks and memory exhaustion with a 10 MB safety limit.
  - Isolated detector execution ensuring partial failures or permission limits never crash a full audit.
  - Strict zero-dependency architecture: 100% Python standard library for runtime execution.
- **Automated Test Suite**:
  - 183 automated unit, integration, and security hardening tests across 12 test modules.
- **Community Standards & Documentation**:
  - MIT License, `pyproject.toml` (PEP 518/621), `setup.py`, `CONTRIBUTING.md`, and `SECURITY.md`.
  - Ready-to-use example scripts in `examples/`: `basic_scan.py`, `custom_detector.py`, and `json_export.py`.

[Unreleased]: https://github.com/0xraiven/persistHunt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xraiven/persistHunt/releases/tag/v0.1.0
