from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, Dict, List, Iterable

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Finding:
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: Any = None
    location: Optional[str] = None
    recommendation: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            raise ValueError("Finding 'id' cannot be empty.")
        if not self.title:
            raise ValueError("Finding 'title' cannot be empty.")
        if not isinstance(self.severity, Severity):
            raise ValueError(f"Invalid severity value: {self.severity}. Must be a Severity enum instance.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "recommendation": self.recommendation
        }

class FindingCollection:
    def __init__(self):
        self._findings: List[Finding] = []

    def add(self, finding: Finding) -> None:
        """Add a finding to the collection."""
        self._findings.append(finding)

    def remove(self, finding: Finding) -> None:
        """Remove a finding from the collection."""
        self._findings.remove(finding)

    def clear(self) -> None:
        """Clear all findings."""
        self._findings.clear()

    def count(self) -> int:
        """Return the number of findings in the collection."""
        return len(self._findings)

    def by_severity(self, severity: Severity) -> List[Finding]:
        """Filter findings by severity."""
        return [f for f in self._findings if f.severity == severity]

    def by_category(self, category: str) -> List[Finding]:
        """Filter findings by category."""
        return [f for f in self._findings if f.category == category]

    def __iter__(self) -> Iterable[Finding]:
        """Iterate over all findings."""
        return iter(self._findings)

    def to_dict(self) -> List[Dict[str, Any]]:
        """Convert all findings to a list of JSON-compatible dictionaries."""
        return [f.to_dict() for f in self._findings]

    def severity_counts(self) -> Dict[str, int]:
        """Return a machine-readable dictionary of finding counts by severity."""
        counts = {sev.value: 0 for sev in Severity}
        for finding in self._findings:
            counts[finding.severity.value] += 1
        return counts
