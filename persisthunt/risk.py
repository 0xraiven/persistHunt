from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Iterable, Any
from persisthunt.findings import Finding, FindingCollection, Severity

@dataclass
class RiskReport:
    """Detailed risk scoring report generated from security findings."""

    score: float
    max_score: float
    severity_counts: Dict[str, int]
    highest_severity: Optional[Severity]
    finding_count: int
    raw_score: float
    breakdown: Dict[str, Dict[str, Any]]
    contributing_findings: List[Finding]

    def summary(self) -> str:
        """Format a human-readable risk scoring summary.

        Produces output in the standard format:
        Risk Score: 7.4/10

        Critical: 1
        High: 2
        Medium: 4
        Low: 3
        Info: 1
        """
        lines = [
            f"Risk Score: {self.score:.1f}/{self.max_score:.0f}",
            "",
            f"Critical: {self.severity_counts.get('CRITICAL', 0)}",
            f"High: {self.severity_counts.get('HIGH', 0)}",
            f"Medium: {self.severity_counts.get('MEDIUM', 0)}",
            f"Low: {self.severity_counts.get('LOW', 0)}",
            f"Info: {self.severity_counts.get('INFO', 0)}",
        ]
        return "\n".join(lines)

    def explain(self) -> str:
        """Provide an explainable breakdown of the risk score calculation."""
        lines = [
            "=== Risk Score Explanation ===",
            f"Overall Risk Score: {self.score:.1f} / {self.max_score:.0f} (Raw Weight: {self.raw_score:.1f})",
            f"Total Findings: {self.finding_count}",
            f"Highest Severity Detected: {self.highest_severity.value if self.highest_severity else 'None'}",
            "",
            "Severity Breakdown:",
        ]

        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            info = self.breakdown.get(sev_name, {"count": 0, "weight": 0, "subtotal": 0})
            lines.append(
                f"  - {sev_name:8}: {info['count']:2d} finding(s) x {info['weight']:4.1f} weight = {info['subtotal']:5.1f} pts"
            )

        if self.contributing_findings:
            lines.append("")
            lines.append("Top Contributing Findings:")
            for idx, f in enumerate(self.contributing_findings[:10], 1):
                loc = f" at {f.location}" if f.location else ""
                lines.append(f"  {idx}. [{f.severity.value}] {f.id} - {f.title}{loc}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert risk report into a JSON-compatible dictionary."""
        return {
            "score": self.score,
            "max_score": self.max_score,
            "severity_counts": self.severity_counts,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "finding_count": self.finding_count,
            "raw_score": self.raw_score,
            "breakdown": self.breakdown,
            "contributing_findings": [f.to_dict() for f in self.contributing_findings],
        }


class RiskScorer:
    """Deterministic and explainable risk-scoring engine for PersistHunt.

    Calculates an overall risk score from a collection of findings using a
    documented severity-weight model.

    Severity Weights:
      INFO     = 0
      LOW      = 1
      MEDIUM   = 3
      HIGH     = 6
      CRITICAL = 10

    Aggregation Formula:
      Raw Score = sum(Weight(f.severity) for f in findings)
      Risk Score = min(max_score, round(Raw Score / divisor, 1))

    By default:
      divisor = max_raw_score / max_score = 50.0 / 10.0 = 5.0
      Risk Score = min(10.0, round(Raw Score / 5.0, 1))
    """

    DEFAULT_WEIGHTS: Dict[Severity, float] = {
        Severity.INFO: 0.0,
        Severity.LOW: 1.0,
        Severity.MEDIUM: 3.0,
        Severity.HIGH: 6.0,
        Severity.CRITICAL: 10.0,
    }

    DEFAULT_MAX_RAW_SCORE: float = 50.0
    DEFAULT_MAX_SCORE: float = 10.0

    # Severity hierarchy for determining highest severity
    SEVERITY_ORDER: List[Severity] = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]

    def __init__(
        self,
        weights: Optional[Dict[Severity, float]] = None,
        max_raw_score: float = DEFAULT_MAX_RAW_SCORE,
        max_score: float = DEFAULT_MAX_SCORE,
    ):
        if max_raw_score <= 0:
            raise ValueError("max_raw_score must be greater than zero.")
        if max_score <= 0:
            raise ValueError("max_score must be greater than zero.")

        self.weights = dict(weights) if weights is not None else dict(self.DEFAULT_WEIGHTS)
        self.max_raw_score = float(max_raw_score)
        self.max_score = float(max_score)
        self.divisor = self.max_raw_score / self.max_score

    def calculate(self, findings: Union[FindingCollection, Iterable[Finding]]) -> RiskReport:
        """Calculate the overall risk score from collected findings.

        Args:
            findings: FindingCollection or iterable of Finding objects.

        Returns:
            RiskReport: Documented, deterministic, and explainable risk report.
        """
        # 1. Normalize findings into a list
        finding_list: List[Finding] = list(findings)
        total_count = len(finding_list)

        # 2. Count findings per severity
        counts: Dict[str, int] = {sev.value: 0 for sev in self.SEVERITY_ORDER}
        highest_severity: Optional[Severity] = None

        for f in finding_list:
            sev_val = f.severity.value
            counts[sev_val] = counts.get(sev_val, 0) + 1

        # 3. Determine highest severity present
        for sev in self.SEVERITY_ORDER:
            if counts.get(sev.value, 0) > 0:
                highest_severity = sev
                break

        # 4. Compute raw score and per-severity breakdown
        raw_score = 0.0
        breakdown: Dict[str, Dict[str, Any]] = {}

        for sev in self.SEVERITY_ORDER:
            c = counts.get(sev.value, 0)
            w = self.weights.get(sev, 0.0)
            subtotal = c * w
            raw_score += subtotal
            breakdown[sev.value] = {
                "count": c,
                "weight": w,
                "subtotal": subtotal,
            }

        # 5. Compute normalized risk score [0.0, max_score]
        if total_count == 0 or raw_score <= 0.0:
            final_score = 0.0
        else:
            normalized = raw_score / self.divisor
            final_score = min(self.max_score, round(normalized, 1))

        # 6. Sort contributing findings by severity descending (Critical first)
        severity_rank = {sev: idx for idx, sev in enumerate(self.SEVERITY_ORDER)}
        sorted_findings = sorted(
            finding_list,
            key=lambda f: (severity_rank.get(f.severity, 99), f.id)
        )

        return RiskReport(
            score=final_score,
            max_score=self.max_score,
            severity_counts=counts,
            highest_severity=highest_severity,
            finding_count=total_count,
            raw_score=raw_score,
            breakdown=breakdown,
            contributing_findings=sorted_findings,
        )


def calculate_risk(
    findings: Union[FindingCollection, Iterable[Finding]],
    weights: Optional[Dict[Severity, float]] = None,
    max_raw_score: float = RiskScorer.DEFAULT_MAX_RAW_SCORE,
    max_score: float = RiskScorer.DEFAULT_MAX_SCORE,
) -> RiskReport:
    """Convenience function to calculate risk score using default or custom settings."""
    scorer = RiskScorer(weights=weights, max_raw_score=max_raw_score, max_score=max_score)
    return scorer.calculate(findings)
