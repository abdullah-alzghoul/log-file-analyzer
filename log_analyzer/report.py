"""Console and file reporting for the Log File Analyzer.

Takes the AnalysisResult produced by analyzer.py and renders it three
ways: a human-readable console summary grouped by severity, a JSON
export (one object per alert, machine-readable, nothing lossy), and a
CSV export (one row per alert, flattened for spreadsheet tools). Nothing
in here decides what counts as an alert -- that's rules.py's job. This
file only presents results that already exist.
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from log_analyzer.analyzer import AnalysisResult
from log_analyzer.models import Alert, Severity


_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW)

CSV_FIELDNAMES = [
    "rule_id", "title", "severity", "description", "timestamp",
    "source_file", "source_ip", "username", "evidence_lines",
]


def print_console_summary(result: AnalysisResult) -> None:
    """Print a human-readable summary to stdout, alerts grouped by
    severity (High, then Medium, then Low), each group in the order
    analyzer.py already sorted them (earliest-first within a tier).

    Groups instead of one flat list because a triage read-through wants
    "show me everything High first," not a single list where a High
    alert from 3am is buried between two Low ones from mid-morning.
    """
    print("=" * 70)
    print("LOG FILE ANALYZER -- SCAN SUMMARY")
    print("=" * 70)
    if result.auth_log_path:
        print(f"Auth log:   {result.auth_log_path} ({result.auth_events_parsed} events parsed)")
    if result.access_log_path:
        print(f"Access log: {result.access_log_path} ({result.access_events_parsed} events parsed)")
    print(f"Total alerts: {len(result.alerts)}")
    print()

    if not result.alerts:
        print("No suspicious activity detected.")
        return

    by_severity: dict[Severity, list[Alert]] = {sev: [] for sev in _SEVERITY_ORDER}
    for alert in result.alerts:
        by_severity[alert.severity].append(alert)

    for severity in _SEVERITY_ORDER:
        alerts = by_severity[severity]
        if not alerts:
            continue
        print(f"--- {severity} ({len(alerts)}) ---")
        for alert in alerts:
            ip_part = f" | ip={alert.source_ip}" if alert.source_ip else ""
            user_part = f" | user={alert.username}" if alert.username else ""
            print(f"[{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {alert.title}{ip_part}{user_part}")
            print(f"    {alert.description}")
        print()


def export_json(result: AnalysisResult, output_path: str | Path) -> Path:
    """Write every alert to a JSON file: a top-level object with a
    small metadata block plus a list of alert dicts (Alert.to_dict(),
    unmodified -- report.py doesn't reshape what models.py already
    defined as the canonical alert representation).
    """
    output_path = Path(output_path)
    payload = {
        "generated_at": datetime.now().isoformat(),
        "auth_log_path": result.auth_log_path,
        "access_log_path": result.access_log_path,
        "auth_events_parsed": result.auth_events_parsed,
        "access_events_parsed": result.access_events_parsed,
        "total_alerts": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return output_path


def export_csv(result: AnalysisResult, output_path: str | Path) -> Path:
    """Write every alert to a CSV file, one row per alert.

    evidence_lines is a list on the underlying Alert, but a CSV cell is
    a flat string -- so it's joined with ';' here, the one field that
    needs reshaping between Alert.to_dict()'s JSON-friendly form and a
    spreadsheet-friendly row. None values become empty cells rather than
    the literal text "None", since that's what a blank field means to
    someone reading this in Excel or Sheets.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for alert in result.alerts:
            row = alert.to_dict()
            row["evidence_lines"] = ";".join(str(n) for n in row["evidence_lines"])
            row["source_ip"] = row["source_ip"] or ""
            row["username"] = row["username"] or ""
            writer.writerow(row)
    return output_path