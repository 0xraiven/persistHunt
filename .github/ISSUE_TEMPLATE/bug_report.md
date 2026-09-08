---
name: Bug Report
about: Report an unexpected crash, false positive/negative, or defect in PersistHunt
title: '[BUG]: '
labels: ['bug', 'triage']
assignees: ''
---

## Description
A clear and concise description of the bug or unexpected behavior.

## Environment Information
- **PersistHunt Version**: (e.g. `0.1.0` or `git rev-parse --short HEAD`)
- **Python Version**: (e.g. `3.11.2`)
- **Operating System / Distribution**: (e.g. `Ubuntu 22.04 LTS`, `Debian 12`, `Arch Linux`, `RHEL 9`)
- **Privilege Level**: (e.g. `root` / `sudo` or unprivileged user)

## Affected Detector(s)
- [ ] CronDetector (`cron`)
- [ ] SystemdDetector (`systemd`)
- [ ] SSHDetector (`ssh`)
- [ ] ShellDetector (`shell`)
- [ ] SuidDetector (`suid`)
- [ ] ProcessDetector (`process`)
- [ ] AccountDetector (`account`)
- [ ] CLI / Core / Reporting Engine

## Steps to Reproduce
1. Command executed: `persisthunt scan ...`
2. Target filesystem configuration or simulated fixture:
3. Error observed:

## Expected Behavior
A concise description of what you expected to happen.

## Terminal Output / Log Snippet
```text
Paste sanitized terminal or JSON output here.
Please ensure all private hostnames, sensitive tokens, or internal IP addresses are redacted.
```

## Additional Context
Add any other context about the problem (e.g. unusual filesystem mounts, container runtime, selinux/apparmor configuration).
