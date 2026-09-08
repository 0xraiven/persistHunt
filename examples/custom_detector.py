import sys
from pathlib import Path

# Ensure repository root is in sys.path when running example directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector, safe_read_lines
from persisthunt.reporting import generate_report


class LdPreloadDetector(BaseDetector):
    """Custom detector auditing /etc/ld.so.preload for shared object hijacking persistence."""

    name = "LD_PRELOAD Persistence Detector"
    detector_id = "ld_preload"

    def __init__(self, preload_path: str = "/etc/ld.so.preload"):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.preload_path = Path(preload_path)

    def scan(self) -> FindingCollection:
        collection = FindingCollection()

        if not self.preload_path.exists():
            return collection

        try:
            lines = safe_read_lines(self.preload_path)
        except PermissionError as e:
            collection.add(Finding(
                id="PH-LDPRELOAD-090",
                category="ld_preload",
                severity=Severity.INFO,
                title="Unreadable ld.so.preload file (permission denied)",
                description=f"Permission denied accessing {self.preload_path}.",
                evidence=str(e),
                location=str(self.preload_path),
                recommendation="Run with elevated permissions to inspect dynamic linker hooks."
            ))
            return collection
        except OSError:
            return collection

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Any non-comment entry in ld.so.preload hooks all dynamically linked processes
            collection.add(Finding(
                id="PH-LDPRELOAD-001",
                category="ld_preload",
                severity=Severity.CRITICAL,
                title="Dynamic linker library preloading configured",
                description=(
                    f"File {self.preload_path} specifies preloaded library '{line}'. "
                    "This causes the library to be loaded into every dynamically linked process, "
                    "a classic rootkit and userland persistence mechanism."
                ),
                evidence=line,
                location=f"{self.preload_path}:{line_no}",
                recommendation="Inspect and verify the legitimate provenance of preloaded shared libraries."
            ))

        return collection


def main():
    print("Running custom LdPreloadDetector...")
    detector = LdPreloadDetector()
    findings = detector.scan()

    report = generate_report(findings)
    print(report.to_terminal(show_details=True))


if __name__ == "__main__":
    main()
