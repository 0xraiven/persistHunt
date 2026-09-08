# Contributing to PersistHunt

Thank you for your interest in contributing to **PersistHunt**! We welcome contributions from security researchers, systems engineers, threat hunters, and open-source contributors of all skill levels.

This document outlines our core architectural invariants, development workflows, testing requirements, and guidelines for adding new persistence detectors.

---

## Core Invariants & Security Rules

PersistHunt is deployed across critical servers, production clusters, air-gapped systems, and forensic triage workstations. Therefore, every contribution must uphold these non-negotiable principles:

1. **Zero External Runtime Dependencies**:
   - The core framework and all detectors must rely exclusively on Python's standard library.
   - External dependencies are only allowed for development/testing (`pytest`).
2. **Strict Read-Only Guarantee**:
   - PersistHunt **never** executes discovered files, commands, or interpreters.
   - PersistHunt **never** modifies filesystem state, file permissions, users, groups, or configurations.
   - PersistHunt **never** attempts privilege escalation (`sudo`, `pkexec`, SUID exploitation).
   - PersistHunt **never** opens outbound network connections or exfiltrates data.
3. **Fault Isolation & Resilience**:
   - A failure, permission exception, or malformed artifact in one detector must never abort the overall scan.
   - Every detector must gracefully handle missing files, unreadable directories, broken symlinks, non-UTF-8 bytes, and unusual filenames.
4. **Deterministic & Explainable Evaluation**:
   - Detections and risk scoring must be mathematically repeatable and transparent.

---

## Development Setup

### Prerequisites

- Python 3.8 or newer
- Git

### Initializing the Environment

```bash
# 1. Clone the repository
git clone https://github.com/0xraiven/persistHunt.git
cd persistHunt

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable development mode with dev dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# 4. Verify the test suite passes
pytest -v
```

---

## Adding a New Persistence Detector

PersistHunt is designed around a modular detector architecture. Follow these steps to implement a new persistence detector:

### 1. Inherit from `BaseDetector`

Create your detector file in `persisthunt/detectors/<module_name>.py`. Subclass `BaseDetector`:

```python
from pathlib import Path
from typing import Optional, Union, List, Set
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector, safe_read_lines, safe_read_text

class ExampleDetector(BaseDetector):
    """Audits example Linux persistence mechanisms."""

    name: str = "Example Persistence Detector"
    detector_id: str = "example"

    def __init__(self, root_prefix: Optional[Union[str, Path]] = None):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix).resolve() if root_prefix else None

    def scan(self) -> FindingCollection:
        collection = FindingCollection()
        # Perform read-only audit here
        return collection
```

### 2. Finding Taxonomies and ID Conventions

Findings must use standardized identifiers:
- Format: `PH-<CATEGORY>-<NUMBER>`
  - Examples: `PH-CRON-001`, `PH-SYSTEMD-005`, `PH-SSH-002`, `PH-SUID-001`.
  - For permission denied warnings, use the convention `PH-<CATEGORY>-090` at `Severity.INFO`.

Every `Finding` must specify:
- `id` (str): Unique finding ID.
- `category` (str): Detector category matching detector_id.
- `severity` (Severity): One of `Severity.INFO`, `Severity.LOW`, `Severity.MEDIUM`, `Severity.HIGH`, `Severity.CRITICAL`.
- `title` (str): Concise human-readable title.
- `description` (str): Detailed context on why this pattern represents persistence risk.
- `evidence` (Any): Sanitized snippet or configuration excerpt demonstrating the indicator.
- `location` (Optional[str]): Absolute filepath and line number (e.g. `/etc/cron.d/job:14`).
- `recommendation` (Optional[str]): Remediation advice for system defenders.

### 3. Safe File Reading

Never use unconstrained `open()` directly on user-provided or untrusted paths. Always use PersistHunt's hardened helpers from `persisthunt.detectors.base`:

- `safe_read_lines(path)`: Safe line-by-line reading with strict file size cap (default 10 MB), FIFO/device protection, and `errors='replace'` for binary bytes.
- `safe_read_text(path)`: Safe full-text reading with identical safeguards.

### 4. Support Offline Forensic Inspections (`root_prefix`)

Detectors should support `root_prefix` so analysts can scan mounted disk images or container overlays:

```python
target_path = self.root_prefix / "etc/myconfig" if self.root_prefix else Path("/etc/myconfig")
```

### 5. Register the Detector

1. Export your detector in `persisthunt/detectors/__init__.py`:
   ```python
   from persisthunt.detectors.example import ExampleDetector
   __all__ = [..., "ExampleDetector"]
   ```
2. Register the detector in `persisthunt/__init__.py`:
   ```python
   from persisthunt.detectors import ExampleDetector
   ```
3. Register the detector in `persisthunt/cli.py`:
   ```python
   DETECTOR_REGISTRY["example"] = ExampleDetector
   ```

### 6. Write Unit Tests

Add a dedicated test file in `tests/test_<module_name>_detector.py`:
- Use `tempfile.TemporaryDirectory` with `root_prefix` to simulate file structures.
- Test normal / benign states (assert 0 findings).
- Test known persistence indicators and edge cases.
- Test permission denied handling.
- Test read-only safety guarantees.
- Include a test verifying real-system execution does not crash:
  ```python
  def test_real_system_scan_does_not_crash(self):
      detector = ExampleDetector()
      findings = detector.scan()
      self.assertIsInstance(findings, FindingCollection)
  ```

---

## Coding Standards & Style

- **Python Version Compatibility**: Code must run seamlessly across Python 3.8 through 3.14.
- **Type Annotations**: All function signatures, method parameters, and return types must have explicit type hints (`typing`).
- **Formatting & PEP 8**: Adhere to PEP 8 standards (4-space indentation, max 100 character line length where feasible).
- **Docstrings**: Public classes and methods must provide informative docstrings explaining behavior, arguments, and safety considerations.
- **Imports**: Organize imports logically: standard library first, then internal package modules. Avoid circular imports.

---

## Git Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` A new persistence detector or user-facing feature.
- `fix:` A bug fix in detection logic, CLI, or reporting.
- `docs:` Documentation updates, guides, or examples.
- `test:` Adding or refining automated tests.
- `refactor:` Code restructuring that does not alter external behavior.
- `chore:` Maintenance, packaging, or CI configuration.

**Example Commit Message**:
```text
feat(detector): add PAM backdoor and auth module persistence detector

Implement PamDetector auditing /etc/pam.d/ and common PAM modules
for suspicious pam_exec, pam_userdb, and unauthorized SO hooks.
Add unit tests with 100% path coverage.
```

---

## Pull Request Lifecycle

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feat/my-new-detector
   ```
2. **Ensure All Tests Pass**:
   ```bash
   pytest -v
   ```
3. **Smoketest CLI and Examples**:
   ```bash
   python -m persisthunt scan -c <new_category>
   python examples/basic_scan.py
   ```
4. **Push and Open a Pull Request**:
   - Open a PR against `main`.
   - Fill out the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
   - Ensure GitHub Actions CI passes completely.
5. **Code Review**:
   - Maintainers will review your submission for code quality, test coverage, safety invariants, and performance.

---

## Questions & Assistance

Feel free to open an issue or start a GitHub Discussion if you have questions or want feedback on a detector concept before writing code!
