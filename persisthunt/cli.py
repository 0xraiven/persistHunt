import sys
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Type, Set, Union
from persisthunt.reporting import TOOL_VERSION as __version__, generate_report
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors import (
    CronDetector,
    SystemdDetector,
    SSHDetector,
    ShellDetector,
    SuidDetector,
    ProcessDetector,
    AccountDetector,
)
from persisthunt.detectors.base import BaseDetector


# Exit Codes
EXIT_SUCCESS = 0            # Clean scan or low/info findings only
EXIT_ERROR = 1              # Operational error / invalid arguments
EXIT_THREAT_DETECTED = 2    # One or more HIGH or CRITICAL threats found

DETECTOR_REGISTRY: Dict[str, Type[BaseDetector]] = {
    "cron": CronDetector,
    "systemd": SystemdDetector,
    "ssh": SSHDetector,
    "shell": ShellDetector,
    "suid": SuidDetector,
    "process": ProcessDetector,
    "account": AccountDetector,
}

SEVERITY_HIERARCHY: Dict[str, Set[Severity]] = {
    "info": {Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
    "low": {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
    "medium": {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
    "high": {Severity.HIGH, Severity.CRITICAL},
    "critical": {Severity.CRITICAL},
}


def create_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="persisthunt",
        description="PersistHunt: Linux Persistence Detection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version",
        action="store_true",
        help="Display PersistHunt version and exit",
    )

    subparsers = parser.add_subparsers(dest="subcommand", title="Commands")

    # Command: persisthunt scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan system for persistence mechanisms",
        description="Scan the system using configured persistence detectors.",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan results in machine-readable JSON format",
    )
    scan_parser.add_argument(
        "-c", "--category",
        action="append",
        dest="categories",
        help=(
            "Filter detector execution by category (e.g. cron, systemd, ssh, shell, suid, process, account). "
            "Can be specified multiple times or as comma-separated values."
        ),
    )
    scan_parser.add_argument(
        "-s", "--severity",
        type=str,
        choices=["info", "low", "medium", "high", "critical"],
        help="Filter findings by minimum severity threshold (case-insensitive)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        type=str,
        metavar="FILE",
        help="Save report to file (.json or .html based on file extension)",
    )
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress scan progress messages on stderr",
    )
    scan_parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Return exit code 0 even if HIGH or CRITICAL threats are detected",
    )
    scan_parser.add_argument(
        "--root-prefix",
        type=str,
        default=None,
        help="Target filesystem root prefix for offline image or container inspection",
    )

    # Command: persisthunt version
    subparsers.add_parser(
        "version",
        help="Display PersistHunt version",
        description="Display the installed PersistHunt version.",
    )

    return parser


def parse_categories(cat_args: Optional[List[str]]) -> List[str]:
    """Parse single, repeated, or comma-separated category arguments."""
    if not cat_args:
        return list(DETECTOR_REGISTRY.keys())

    selected: List[str] = []
    for item in cat_args:
        for cat in item.split(","):
            cleaned = cat.strip().lower()
            if not cleaned:
                continue
            if cleaned == "all":
                return list(DETECTOR_REGISTRY.keys())
            if cleaned not in DETECTOR_REGISTRY:
                valid = ", ".join(sorted(DETECTOR_REGISTRY.keys()))
                raise ValueError(f"Unknown category '{cleaned}'. Valid categories: {valid}")
            if cleaned not in selected:
                selected.append(cleaned)

    return selected if selected else list(DETECTOR_REGISTRY.keys())


def run_scan(args: argparse.Namespace) -> int:
    """Execute the persistence scan command."""
    # 1. Resolve selected detector categories
    try:
        categories = parse_categories(args.categories)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return EXIT_ERROR

    # 2. Instantiate and run selected detectors
    all_findings = FindingCollection()
    detector_statuses: Dict[str, Dict[str, Any]] = {}

    for cat in categories:
        detector_cls = DETECTOR_REGISTRY[cat]
        if not args.quiet:
            sys.stderr.write(f"[+] Scanning {cat} persistence...\n")
            sys.stderr.flush()

        try:
            # Initialize with root_prefix if supported and supplied
            if args.root_prefix and "root_prefix" in detector_cls.__init__.__code__.co_varnames:
                detector = detector_cls(root_prefix=args.root_prefix)
            else:
                detector = detector_cls()

            findings = detector.scan()
            cat_findings_count = 0
            for f in findings:
                all_findings.add(f)
                cat_findings_count += 1

            # Detect permission restrictions
            is_perm_limited = any(
                f.id.endswith("090")
                or "permission denied" in f.title.lower()
                or "permission denied" in f.description.lower()
                for f in findings
            )
            status_val = "permission-limited" if is_perm_limited else "successful"
            detector_statuses[cat] = {
                "status": status_val,
                "findings_count": cat_findings_count,
                "error": None,
            }
        except PermissionError as e:
            sys.stderr.write(f"[-] Permission denied running {cat} detector: {e}\n")
            detector_statuses[cat] = {
                "status": "permission-limited",
                "findings_count": 0,
                "error": str(e),
            }
        except Exception as e:
            sys.stderr.write(f"[-] Error running {cat} detector: {e}\n")
            detector_statuses[cat] = {
                "status": "failed",
                "findings_count": 0,
                "error": str(e),
            }

    # 3. Apply severity filter if requested
    filtered_findings: List[Finding] = []
    if args.severity:
        threshold = SEVERITY_HIERARCHY.get(args.severity.lower())
        if threshold is not None:
            filtered_findings = [f for f in all_findings if f.severity in threshold]
        else:
            filtered_findings = list(all_findings)
    else:
        filtered_findings = list(all_findings)

    # 4. Generate report
    report = generate_report(filtered_findings, detector_status=detector_statuses)

    # 5. Output results
    if args.json:
        # Machine-readable JSON output to stdout
        sys.stdout.write(report.to_json(indent=2) + "\n")
        sys.stdout.flush()
    else:
        # Human-readable terminal output to stdout
        sys.stdout.write(report.to_terminal(show_details=True) + "\n")
        sys.stdout.flush()

    # 6. Save to file if --output specified
    if args.output:
        out_path = Path(args.output)
        if out_path.suffix.lower() == ".html":
            report.save_html(out_path)
            if not args.quiet:
                sys.stderr.write(f"[+] HTML report saved to {out_path}\n")
        else:
            report.save_json(out_path)
            if not args.quiet:
                sys.stderr.write(f"[+] JSON report saved to {out_path}\n")

    # 7. Determine exit code
    has_threats = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in filtered_findings)
    if has_threats and not args.exit_zero:
        return EXIT_THREAT_DETECTED

    return EXIT_SUCCESS


def main(argv: Optional[List[str]] = None) -> int:
    """Primary CLI entrypoint for PersistHunt."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()

    # Handle top-level --version or persisthunt version
    if not argv:
        parser.print_help(sys.stderr)
        return EXIT_SUCCESS

    if argv in (["-V"], ["--version"]):
        sys.stdout.write(f"PersistHunt {__version__}\n")
        return EXIT_SUCCESS

    args = parser.parse_args(argv)

    if args.version:
        sys.stdout.write(f"PersistHunt {__version__}\n")
        return EXIT_SUCCESS

    if args.subcommand == "version":
        sys.stdout.write(f"PersistHunt {__version__}\n")
        return EXIT_SUCCESS

    if args.subcommand == "scan":
        return run_scan(args)

    parser.print_help(sys.stderr)
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
