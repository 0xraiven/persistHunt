---
name: Detector Proposal
about: Propose a new Linux persistence detection mechanism or technique
title: '[DETECTOR]: '
labels: ['detector', 'enhancement']
assignees: ''
---

## Persistence Mechanism Name
What Linux persistence technique does this detector audit? (e.g. PAM modules, udev rules, binfmt_misc, kernel modules, MOTD, at jobs, systemd generators, ld.so.preload).

## MITRE ATT&CK Mapping
- **Technique ID**: (e.g., `T1546.004` Unix Shell Configuration Modification, `T1053.003` Cron, `T1547.006` Kernel Modules)
- **Sub-technique**:
- **Tactic**: Persistence / Privilege Escalation

## Target Filesystem Artifacts & Configuration Paths
Which files, directories, or kernel interfaces must be inspected?
```text
/etc/...
```

## Detection Indicators & Logic
Describe how to identify malicious, unauthorized, or suspicious configurations versus legitimate administrative configurations:
- Suspicious execution patterns:
- Insecure permissions / ownership:
- Anomalous paths:

## Proposed Finding Metadata
- **Proposed ID Range**: `PH-<CATEGORY>-001` through `PH-<CATEGORY>-010`
- **Default Severity Range**: (e.g. `MEDIUM` to `CRITICAL`)
- **Remediation Recommendation**:

## False Positive Mitigations
What legitimate packages or default distributions configure this mechanism? How will the detector avoid excessive false positives?

## Safety Invariant Confirmation
- [ ] Read-only inspection only (zero file modification, zero command execution).
- [ ] Safe file parsing via `safe_read_lines` / `safe_read_text` with resource bounds.
- [ ] Uses Python standard library only (no external packages).
