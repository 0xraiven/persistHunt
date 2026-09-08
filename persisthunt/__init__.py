"""PersistHunt core package."""

from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors import (
    BaseDetector,
    CronDetector,
    SystemdDetector,
    SSHDetector,
    ShellDetector,
    SuidDetector,
    ProcessDetector,
    AccountDetector,
)
from persisthunt.risk import (
    RiskScorer,
    RiskReport,
    calculate_risk,
)
from persisthunt.reporting import (
    ScanReport,
    Reporter,
    generate_report,
    TOOL_VERSION,
)

__version__ = TOOL_VERSION

__all__ = [
    "__version__",
    "Finding",
    "FindingCollection",
    "Severity",
    "BaseDetector",
    "CronDetector",
    "SystemdDetector",
    "SSHDetector",
    "ShellDetector",
    "SuidDetector",
    "ProcessDetector",
    "AccountDetector",
    "RiskScorer",
    "RiskReport",
    "calculate_risk",
    "ScanReport",
    "Reporter",
    "generate_report",
]



