"""Orchestration layer for the Log File Analyzer.

Ties parsers.py and rules.py together: given one or both log file paths,
parses them into events, runs every detection rule against the
appropriate event list, and returns one sorted list of Alert objects
plus a few summary counts. Nothing in here parses log lines or decides
what's suspicious -- that's parsers.py and rules.py respectively. This
file's only job is calling them in the right order and combining the
results.
"""

from dataclasses import dataclass
from pathlib import Path

from log_analyzer import rules
from log_analyzer.models import Alert
from log_analyzer.parsers import parse_access_log, parse_auth_log


@dataclass
class AnalysisResult:
    """Everything report.py needs to render a full run's results."""

    alerts: list[Alert]
    auth_log_path: str | None
    access_log_path: str | None
    auth_events_parsed: int
    access_events_parsed: int


def run_analysis(
    auth_log_path: str | Path | None = None,
    access_log_path: str | Path | None = None,
    year: int | None = None,
) -> AnalysisResult:
    """Parse the given log file(s) and run every baseline detection rule
    against them, returning one combined, severity-sorted result.

    At least one of auth_log_path / access_log_path must be given --
    passing neither raises ValueError, since there'd be nothing to
    analyze. Either one may be omitted on its own; rules that need the
    missing log type simply produce no alerts from that side (e.g. skip
    access_log_path and you still get all four auth.log-only rules, just
    nothing from unusual_hour_access's access-side half).

    `year` is forwarded to parse_auth_log only -- access.log timestamps
    already carry a full 4-digit year, but classic syslog timestamps in
    auth.log don't, per that function's docstring.

    File-not-found and similar path errors are deliberately NOT caught
    here; they propagate up so cli.py (File 8) can turn them into a
    clean, user-facing message instead of this module silently guessing
    what the caller meant.
    """
    if auth_log_path is None and access_log_path is None:
        raise ValueError("run_analysis needs at least one of auth_log_path or access_log_path")

    auth_events = parse_auth_log(auth_log_path, year=year) if auth_log_path is not None else []
    access_events = parse_access_log(access_log_path) if access_log_path is not None else []

    alerts: list[Alert] = []
    alerts.extend(rules.detect_brute_force_login(auth_events))
    alerts.extend(rules.detect_login_success_after_failures(auth_events))
    alerts.extend(rules.detect_unusual_hour_access(auth_events, access_events))
    alerts.extend(rules.detect_sql_injection_attempt(access_events))
    alerts.extend(rules.detect_xss_attempt(access_events))
    alerts.extend(rules.detect_path_traversal_attempt(access_events))
    alerts.extend(rules.detect_sensitive_path_access(access_events))
    alerts.extend(rules.detect_high_request_rate(access_events))
    alerts.extend(rules.detect_scanner_user_agent(access_events))
    alerts.extend(rules.detect_privilege_escalation(auth_events))
    alerts.extend(rules.detect_invalid_user_probe(auth_events))
    alerts.extend(rules.detect_http_error_spike(access_events))

    # Highest severity first; earliest-first within a severity tier, so
    # each tier reads as a timeline rather than in rule-call order.
    alerts.sort(key=lambda a: (-a.severity, a.timestamp))

    return AnalysisResult(
        alerts=alerts,
        auth_log_path=str(auth_log_path) if auth_log_path is not None else None,
        access_log_path=str(access_log_path) if access_log_path is not None else None,
        auth_events_parsed=len(auth_events),
        access_events_parsed=len(access_events),
    )