## Description
Provide a clear summary of the changes made, the motivation behind them, and how they benefit PersistHunt users.

Fixes #(issue)

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New detector (adding detection for a new persistence mechanism)
- [ ] Detector enhancement (improving indicators, reducing false positives)
- [ ] CLI / Core / Reporting feature
- [ ] Documentation update
- [ ] Performance / hardening improvement

## Checklist

### Safety & Architectural Invariants
- [ ] **Zero External Runtime Dependencies**: Code relies strictly on Python's standard library. No new entries in `install_requires`.
- [ ] **Strict Read-Only Guarantee**:
  - Does NOT execute discovered files, binaries, or commands.
  - Does NOT write to or modify target filesystem paths.
  - Does NOT open outbound network sockets.
- [ ] **Resource Limits & Parsing**:
  - Uses `safe_read_lines()` or `safe_read_text()` for untrusted file contents.
  - Respects file size ceiling (10 MB) and handles FIFOs / symlink cycles safely.
- [ ] **Detector Isolation**:
  - Gracefully catches `PermissionError` and `OSError` without aborting the overall scan.
  - Supports `root_prefix` for offline forensic inspections where applicable.

### Code Quality & Testing
- [ ] Fully typed function signatures and return values (`typing`).
- [ ] Passes all unit and integration tests (`pytest -v`).
- [ ] New tests added in `tests/` covering benign configurations, malicious indicators, and permission errors.
- [ ] Follows PEP 8 conventions and documented docstrings.
- [ ] Updated `README.md` / `CHANGELOG.md` if user-facing features or CLI flags were modified.
