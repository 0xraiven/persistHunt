import json
import html
import socket
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Union, Dict, List, Iterable, Any
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.risk import RiskScorer, RiskReport, calculate_risk

TOOL_NAME = "PersistHunt"
TOOL_DESCRIPTION = "Linux Persistence Detection Framework"
TOOL_VERSION = "0.1.0"

@dataclass
class ScanReport:
    """Comprehensive PersistHunt scan report supporting JSON, terminal, and HTML outputs."""

    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host: str = field(default_factory=socket.gethostname)
    risk_score: float = 0.0
    risk_report: Optional[RiskReport] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report into a stable, JSON-compatible dictionary."""
        return {
            "tool": self.tool,
            "version": self.version,
            "timestamp": self.timestamp,
            "host": self.host,
            "risk_score": self.risk_score,
            "statistics": self.statistics,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to a stable JSON formatted string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_terminal(self, show_details: bool = True) -> str:
        """Format human-readable terminal summary matching the PersistHunt specification:

        PersistHunt
        Linux Persistence Detection Framework

        Scan complete.

        Findings: 8

        CRITICAL: 1
        HIGH: 2
        MEDIUM: 3
        LOW: 2

        Risk Score: 7.2/10
        """
        sev_counts = self.statistics.get("severity_counts", {})
        total_count = self.statistics.get("total_findings", len(self.findings))

        lines = [
            self.tool,
            TOOL_DESCRIPTION,
            "",
            "Scan complete.",
            "",
            f"Findings: {total_count}",
            "",
        ]

        # Display severity counts in descending order
        standard_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for sev in standard_severities:
            count = sev_counts.get(sev, 0)
            if count > 0 or total_count == 0:
                lines.append(f"{sev}: {count}")

        # Include INFO if non-zero
        info_count = sev_counts.get("INFO", 0)
        if info_count > 0:
            lines.append(f"INFO: {info_count}")

        max_score = self.risk_report.max_score if self.risk_report else 10.0
        lines.append("")
        lines.append(f"Risk Score: {self.risk_score:.1f}/{max_score:.0f}")

        # Provide useful finding summaries
        if show_details and self.findings:
            lines.append("")
            lines.append("=== Finding Summaries ===")
            for idx, f in enumerate(self.findings, 1):
                lines.append("")
                lines.append(f"{idx}. [{f.severity.value}] {f.id} - {f.title}")
                if f.location:
                    lines.append(f"   Location: {f.location}")
                if f.evidence:
                    # Truncate evidence if exceedingly long for terminal display
                    ev_str = str(f.evidence)
                    if len(ev_str) > 120:
                        ev_str = ev_str[:117] + "..."
                    lines.append(f"   Evidence: {ev_str}")
                if f.recommendation:
                    lines.append(f"   Action: {f.recommendation}")

        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate clean, self-contained, responsive HTML report without external dependencies."""
        sev_counts = self.statistics.get("severity_counts", {})
        crit = sev_counts.get("CRITICAL", 0)
        high = sev_counts.get("HIGH", 0)
        med = sev_counts.get("MEDIUM", 0)
        low = sev_counts.get("LOW", 0)
        info = sev_counts.get("INFO", 0)

        finding_rows = []
        for f in self.findings:
            sev_class = f.severity.value.lower()
            ev_html = f"<code>{html.escape(str(f.evidence))}</code>" if f.evidence else "&mdash;"
            loc_html = f"<code>{html.escape(f.location)}</code>" if f.location else "&mdash;"
            rec_html = html.escape(f.recommendation) if f.recommendation else "&mdash;"

            finding_rows.append(f"""
            <tr class="finding-row {sev_class}">
                <td><span class="badge {sev_class}">{html.escape(f.severity.value)}</span></td>
                <td><code>{html.escape(f.id)}</code></td>
                <td><strong>{html.escape(f.title)}</strong><br><small>{html.escape(f.description)}</small></td>
                <td>{loc_html}</td>
                <td>{ev_html}</td>
                <td>{rec_html}</td>
            </tr>
            """)

        rows_content = "".join(finding_rows) if finding_rows else "<tr><td colspan='6' class='empty'>No persistence findings detected.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(self.tool)} Audit Report - {html.escape(self.host)}</title>
<style>
  :root {{
    --bg: #0f172a; --card-bg: #1e293b; --text: #f8fafc; --muted: #94a3b8;
    --border: #334155; --crit: #ef4444; --high: #f97316; --med: #eab308;
    --low: #3b82f6; --info: #64748b;
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.5; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 2rem; }}
  h1 {{ margin: 0; font-size: 1.8rem; }}
  .subtitle {{ color: var(--muted); margin: 0.25rem 0 0; font-size: 0.95rem; }}
  .meta-badges {{ display: flex; gap: 0.5rem; }}
  .badge {{ padding: 0.25rem 0.6rem; border-radius: 9999px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }}
  .badge.critical {{ background: var(--crit); color: #fff; }}
  .badge.high {{ background: var(--high); color: #fff; }}
  .badge.medium {{ background: var(--med); color: #000; }}
  .badge.low {{ background: var(--low); color: #fff; }}
  .badge.info {{ background: var(--info); color: #fff; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; text-align: center; }}
  .card .val {{ font-size: 2rem; font-weight: bold; margin: 0.25rem 0; }}
  .card .lbl {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card.score .val {{ color: {("#ef4444" if self.risk_score >= 7.0 else "#f97316" if self.risk_score >= 4.0 else "#22c55e")}; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 0.5rem; overflow: hidden; margin-top: 1rem; border: 1px solid var(--border); }}
  th, td {{ padding: 0.85rem 1rem; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ background: #0b1120; color: var(--muted); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
  code {{ background: #0b1120; padding: 0.15rem 0.35rem; border-radius: 0.25rem; font-size: 0.85rem; font-family: monospace; word-break: break-all; }}
  small {{ color: var(--muted); display: block; margin-top: 0.25rem; }}
  td.empty {{ text-align: center; color: var(--muted); padding: 3rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>{html.escape(self.tool)} <small style="display:inline; font-size: 1rem; color: var(--muted);">v{html.escape(self.version)}</small></h1>
      <p class="subtitle">{html.escape(TOOL_DESCRIPTION)} &bull; Host: <strong>{html.escape(self.host)}</strong> &bull; {html.escape(self.timestamp)}</p>
    </div>
  </header>

  <div class="stats-grid">
    <div class="card score">
      <div class="lbl">Risk Score</div>
      <div class="val">{self.risk_score:.1f} / 10</div>
    </div>
    <div class="card">
      <div class="lbl">Total Findings</div>
      <div class="val">{len(self.findings)}</div>
    </div>
    <div class="card">
      <div class="lbl">Critical / High</div>
      <div class="val" style="color: var(--crit);">{crit} / {high}</div>
    </div>
    <div class="card">
      <div class="lbl">Medium / Low</div>
      <div class="val" style="color: var(--med);">{med} / {low}</div>
    </div>
  </div>

  <h2>Discovered Findings ({len(self.findings)})</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 100px;">Severity</th>
        <th style="width: 140px;">Finding ID</th>
        <th>Description</th>
        <th>Location</th>
        <th>Evidence</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      {rows_content}
    </tbody>
  </table>
</div>
</body>
</html>
"""

    def save_json(self, path: Union[str, Path], indent: int = 2) -> Path:
        """Write JSON report to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(indent=indent), encoding="utf-8")
        return target

    def save_html(self, path: Union[str, Path]) -> Path:
        """Write HTML report to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_html(), encoding="utf-8")
        return target


class Reporter:
    """Report generator for PersistHunt security audit findings."""

    def __init__(
        self,
        tool: str = TOOL_NAME,
        version: str = TOOL_VERSION,
        risk_scorer: Optional[RiskScorer] = None,
    ):
        self.tool = tool
        self.version = version
        self.risk_scorer = risk_scorer if risk_scorer is not None else RiskScorer()

    def generate(
        self,
        findings: Union[FindingCollection, Iterable[Finding]],
        host: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> ScanReport:
        """Generate a complete ScanReport from findings."""
        finding_list: List[Finding] = list(findings)
        risk_rep = self.risk_scorer.calculate(finding_list)

        # Compute statistics
        cat_counts: Dict[str, int] = {}
        for f in finding_list:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

        stats = {
            "total_findings": len(finding_list),
            "highest_severity": risk_rep.highest_severity.value if risk_rep.highest_severity else None,
            "severity_counts": risk_rep.severity_counts,
            "category_counts": cat_counts,
            "raw_score": risk_rep.raw_score,
        }

        # Sort findings by severity order (Critical first)
        sorted_findings = list(risk_rep.contributing_findings)

        report_timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        report_host = host or socket.gethostname()

        return ScanReport(
            tool=self.tool,
            version=self.version,
            timestamp=report_timestamp,
            host=report_host,
            risk_score=risk_rep.score,
            risk_report=risk_rep,
            statistics=stats,
            findings=sorted_findings,
        )


def generate_report(
    findings: Union[FindingCollection, Iterable[Finding]],
    host: Optional[str] = None,
    timestamp: Optional[str] = None,
    risk_scorer: Optional[RiskScorer] = None,
) -> ScanReport:
    """Convenience function to generate a ScanReport from findings."""
    reporter = Reporter(risk_scorer=risk_scorer)
    return reporter.generate(findings, host=host, timestamp=timestamp)
