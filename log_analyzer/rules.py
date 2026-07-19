"""Detection rules for the Log File Analyzer.

One function per baseline suspicious-activity category from the Phase 1
blueprint, each named detect_<rule_id> to match its entry in
config.RULES — so given a rule_id you can always find its function by
name, no separate lookup table to keep in sync.

Every function takes already-parsed event objects (from parsers.py) and
returns a list of Alert objects (from models.py); none of them read
files or know anything about log line formats. Two shared engines back
most of the individual rules:

- _find_bursts groups a time-sorted event list into non-overlapping
  clusters where enough events happened close enough together in time —
  used by the four "N events within a window" rules (brute force,
  invalid-user probing, high request rate, 4xx spike).
- _detect_pattern_match runs a list of compiled regexes against every
  request path — used by the three access.log pattern rules (SQLi, XSS,
  path traversal), which are otherwise identical apart from which
  pattern list and rule_id they use.
"""

from collections import defaultdict
from datetime import timedelta

from log_analyzer import config
from log_analyzer.models import AccessLogEvent, Alert, AuthEventType, AuthLogEvent


# --------------------------------------------------------------------------
# Shared infrastructure
# --------------------------------------------------------------------------

def _group_by_ip(events: list) -> dict[str, list]:
    """Group events by source_ip, each group's events sorted by timestamp.

    Events with no IP (source_ip is None — true for some auth.log event
    types like sudo/su) are dropped; there's nothing to attribute a
    per-IP pattern to.
    """
    groups: dict[str, list] = defaultdict(list)
    for event in events:
        if event.source_ip:
            groups[event.source_ip].append(event)
    for ip_events in groups.values():
        ip_events.sort(key=lambda e: e.timestamp)
    return groups


def _find_bursts(events: list, window_seconds: int, threshold: int) -> list[list]:
    """Group a time-sorted event list into non-overlapping clusters where
    `threshold` or more events fall within `window_seconds` of each
    other.

    Scanning resumes right after each emitted cluster, so one sustained
    burst produces exactly one alert instead of one alert per event past
    threshold — a 40-attempt brute-force run becomes a single "40 failed
    logins" alert, not 36 overlapping near-duplicate alerts.
    """
    bursts: list[list] = []
    i = 0
    n = len(events)
    while i < n:
        j = i
        while j + 1 < n and (events[j + 1].timestamp - events[i].timestamp).total_seconds() <= window_seconds:
            j += 1
        if (j - i + 1) >= threshold:
            bursts.append(events[i:j + 1])
            i = j + 1
        else:
            i += 1
    return bursts


def _detect_pattern_match(
    events: list[AccessLogEvent], patterns: list, rule_id: str, label: str
) -> list[Alert]:
    """Shared engine for the three access.log pattern-match rules (SQLi,
    XSS, path traversal) — same logic each time: does any pattern in the
    list match this request's path? Uses any() so one request matching
    several patterns at once still produces a single alert, not one per
    matching pattern.
    """
    alerts = []
    meta = config.RULES[rule_id]
    for event in events:
        if any(pattern.search(event.path) for pattern in patterns):
            path_display = event.path if len(event.path) <= 150 else event.path[:150] + "..."
            alerts.append(Alert(
                rule_id=rule_id,
                title=meta.title,
                severity=meta.severity,
                description=f"{label} matched in request from {event.source_ip}: {path_display}",
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=event.source_ip,
                username=None,
                evidence_lines=[event.line_number],
            ))
    return alerts


def _matches_sensitive_path(path: str, sensitive: str) -> bool:
    """True if `path` IS `sensitive`, or is nested under it as a
    subpath — so /admin matches /admin and /admin/users, but not
    /administrator.
    """
    return path == sensitive or path.startswith(sensitive.rstrip("/") + "/")


def _is_unusual_hour(hour: int) -> bool:
    return config.UNUSUAL_HOUR_START <= hour <= config.UNUSUAL_HOUR_END


# --------------------------------------------------------------------------
# Category 1 — brute-force login attempts (auth.log)
# --------------------------------------------------------------------------

def detect_brute_force_login(events: list[AuthLogEvent]) -> list[Alert]:
    """Flags 5+ failed-password attempts (real, existing accounts) from
    one IP within a 5-minute window. Deliberately excludes invalid-user
    attempts — see detect_invalid_user_probe for that distinct pattern.
    """
    alerts = []
    meta = config.RULES["brute_force_login"]
    failed = [e for e in events if e.event_type == AuthEventType.FAILED_PASSWORD]
    for ip, ip_events in _group_by_ip(failed).items():
        for burst in _find_bursts(ip_events, config.BRUTE_FORCE_WINDOW_SECONDS, config.BRUTE_FORCE_THRESHOLD):
            usernames = sorted({e.username for e in burst if e.username})
            alerts.append(Alert(
                rule_id="brute_force_login",
                title=meta.title,
                severity=meta.severity,
                description=(
                    f"{len(burst)} failed login attempts from {ip} within "
                    f"{config.BRUTE_FORCE_WINDOW_SECONDS}s (targeting: "
                    f"{', '.join(usernames) if usernames else 'unknown'})"
                ),
                timestamp=burst[-1].timestamp,
                source_file=burst[-1].source_file,
                source_ip=ip,
                username=usernames[0] if len(usernames) == 1 else None,
                evidence_lines=[e.line_number for e in burst],
            ))
    return alerts


# --------------------------------------------------------------------------
# Category 2 — successful login right after several failed attempts
# --------------------------------------------------------------------------

def detect_login_success_after_failures(events: list[AuthLogEvent]) -> list[Alert]:
    """Flags a successful login preceded by 3+ failed attempts from the
    same IP within 5 minutes — the "brute force finally landed" pattern,
    distinct from a burst of failures alone.
    """
    alerts = []
    meta = config.RULES["login_success_after_failures"]
    relevant = [e for e in events if e.event_type in (AuthEventType.FAILED_PASSWORD, AuthEventType.ACCEPTED_PASSWORD)]
    for ip, ip_events in _group_by_ip(relevant).items():
        for idx, event in enumerate(ip_events):
            if event.event_type != AuthEventType.ACCEPTED_PASSWORD:
                continue
            window_start = event.timestamp - timedelta(seconds=config.LOGIN_SUCCESS_AFTER_FAILURES_WINDOW_SECONDS)
            preceding_failures = [
                e for e in ip_events[:idx]
                if e.event_type == AuthEventType.FAILED_PASSWORD and e.timestamp >= window_start
            ]
            if len(preceding_failures) >= config.LOGIN_SUCCESS_AFTER_FAILURES_THRESHOLD:
                evidence = preceding_failures + [event]
                alerts.append(Alert(
                    rule_id="login_success_after_failures",
                    title=meta.title,
                    severity=meta.severity,
                    description=(
                        f"Successful login for {event.username!r} from {ip} followed "
                        f"{len(preceding_failures)} failed attempts within "
                        f"{config.LOGIN_SUCCESS_AFTER_FAILURES_WINDOW_SECONDS}s"
                    ),
                    timestamp=event.timestamp,
                    source_file=event.source_file,
                    source_ip=ip,
                    username=event.username,
                    evidence_lines=[e.line_number for e in evidence],
                ))
    return alerts


# --------------------------------------------------------------------------
# Category 3 — access at unusual hours (auth.log + access.log)
# --------------------------------------------------------------------------

def detect_unusual_hour_access(
    auth_events: list[AuthLogEvent], access_events: list[AccessLogEvent]
) -> list[Alert]:
    """Flags activity between UNUSUAL_HOUR_START and UNUSUAL_HOUR_END.

    On the auth side, only successful logins count — flagging every
    failed attempt too would just duplicate brute-force alerts, since
    attacks already skew toward off-hours by nature. On the access side,
    every request in the window counts.
    """
    alerts = []
    meta = config.RULES["unusual_hour_access"]

    for event in auth_events:
        if event.event_type == AuthEventType.ACCEPTED_PASSWORD and _is_unusual_hour(event.timestamp.hour):
            alerts.append(Alert(
                rule_id="unusual_hour_access",
                title=meta.title,
                severity=meta.severity,
                description=(
                    f"Successful login for {event.username!r} from {event.source_ip} "
                    f"at {event.timestamp.strftime('%H:%M')} (outside normal hours)"
                ),
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=event.source_ip,
                username=event.username,
                evidence_lines=[event.line_number],
            ))

    for event in access_events:
        if _is_unusual_hour(event.timestamp.hour):
            alerts.append(Alert(
                rule_id="unusual_hour_access",
                title=meta.title,
                severity=meta.severity,
                description=(
                    f"Request to {event.path} from {event.source_ip} "
                    f"at {event.timestamp.strftime('%H:%M')} (outside normal hours)"
                ),
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=event.source_ip,
                username=None,
                evidence_lines=[event.line_number],
            ))
    return alerts


# --------------------------------------------------------------------------
# Categories 4-6 — SQLi / XSS / path traversal (access.log)
# --------------------------------------------------------------------------

def detect_sql_injection_attempt(events: list[AccessLogEvent]) -> list[Alert]:
    return _detect_pattern_match(events, config.SQLI_PATTERNS, "sql_injection_attempt", "SQL injection pattern")


def detect_xss_attempt(events: list[AccessLogEvent]) -> list[Alert]:
    return _detect_pattern_match(events, config.XSS_PATTERNS, "xss_attempt", "XSS pattern")


def detect_path_traversal_attempt(events: list[AccessLogEvent]) -> list[Alert]:
    return _detect_pattern_match(events, config.PATH_TRAVERSAL_PATTERNS, "path_traversal_attempt", "Path traversal pattern")


# --------------------------------------------------------------------------
# Category 7 — sensitive/administrative paths (access.log)
# --------------------------------------------------------------------------

def detect_sensitive_path_access(events: list[AccessLogEvent]) -> list[Alert]:
    alerts = []
    meta = config.RULES["sensitive_path_access"]
    for event in events:
        path_only = event.path.split("?", 1)[0]
        if any(_matches_sensitive_path(path_only, sensitive) for sensitive in config.SENSITIVE_PATHS):
            alerts.append(Alert(
                rule_id="sensitive_path_access",
                title=meta.title,
                severity=meta.severity,
                description=f"Request to sensitive path {path_only} from {event.source_ip} (status {event.status_code})",
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=event.source_ip,
                username=None,
                evidence_lines=[event.line_number],
            ))
    return alerts


# --------------------------------------------------------------------------
# Category 8 — abnormally high request rate (access.log)
# --------------------------------------------------------------------------

def detect_high_request_rate(events: list[AccessLogEvent]) -> list[Alert]:
    alerts = []
    meta = config.RULES["high_request_rate"]
    for ip, ip_events in _group_by_ip(events).items():
        for burst in _find_bursts(ip_events, config.HIGH_REQUEST_RATE_WINDOW_SECONDS, config.HIGH_REQUEST_RATE_THRESHOLD):
            alerts.append(Alert(
                rule_id="high_request_rate",
                title=meta.title,
                severity=meta.severity,
                description=f"{len(burst)} requests from {ip} within {config.HIGH_REQUEST_RATE_WINDOW_SECONDS}s",
                timestamp=burst[-1].timestamp,
                source_file=burst[-1].source_file,
                source_ip=ip,
                username=None,
                evidence_lines=[e.line_number for e in burst],
            ))
    return alerts


# --------------------------------------------------------------------------
# Category 9 — known scanning/attack-tool User-Agent (access.log)
# --------------------------------------------------------------------------

def detect_scanner_user_agent(events: list[AccessLogEvent]) -> list[Alert]:
    alerts = []
    meta = config.RULES["scanner_user_agent"]
    for event in events:
        ua_lower = event.user_agent.lower()
        matched = next((ua for ua in config.SCANNER_USER_AGENTS if ua in ua_lower), None)
        if matched:
            alerts.append(Alert(
                rule_id="scanner_user_agent",
                title=meta.title,
                severity=meta.severity,
                description=f"Known scanning-tool signature ({matched!r}) in User-Agent from {event.source_ip}: {event.user_agent[:120]}",
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=event.source_ip,
                username=None,
                evidence_lines=[event.line_number],
            ))
    return alerts


# --------------------------------------------------------------------------
# Category 10 — privilege escalation (auth.log)
# --------------------------------------------------------------------------

def detect_privilege_escalation(events: list[AuthLogEvent]) -> list[Alert]:
    """Flags every sudo authentication failure, and every su attempt
    regardless of outcome. sudo is routine — only its failures are
    noteworthy. su is different: it's a direct switch to another
    account's identity (commonly root), so its mere use is inherently
    privilege-relevant whether or not it succeeded.
    """
    alerts = []
    meta = config.RULES["privilege_escalation"]
    for event in events:
        if event.event_type == AuthEventType.SUDO_FAILURE:
            alerts.append(Alert(
                rule_id="privilege_escalation",
                title=meta.title,
                severity=meta.severity,
                description=f"sudo authentication failure for user {event.username!r} on {event.host}",
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=None,
                username=event.username,
                evidence_lines=[event.line_number],
            ))
        elif event.event_type == AuthEventType.SU_ATTEMPT:
            outcome = "Failed" if event.message.lower().startswith("failed") else "Successful"
            alerts.append(Alert(
                rule_id="privilege_escalation",
                title=meta.title,
                severity=meta.severity,
                description=f"{outcome} su attempt by {event.username!r} on {event.host}",
                timestamp=event.timestamp,
                source_file=event.source_file,
                source_ip=None,
                username=event.username,
                evidence_lines=[event.line_number],
            ))
    return alerts


# --------------------------------------------------------------------------
# Category 11 — invalid-user login probing (auth.log)
# --------------------------------------------------------------------------

def detect_invalid_user_probe(events: list[AuthLogEvent]) -> list[Alert]:
    """Flags 5+ login attempts against usernames that don't exist at all,
    from one IP within 5 minutes — probing for accounts, distinct from
    detect_brute_force_login's password-guessing against a real account.
    """
    alerts = []
    meta = config.RULES["invalid_user_probe"]
    invalid = [e for e in events if e.event_type == AuthEventType.INVALID_USER]
    for ip, ip_events in _group_by_ip(invalid).items():
        for burst in _find_bursts(ip_events, config.INVALID_USER_WINDOW_SECONDS, config.INVALID_USER_THRESHOLD):
            usernames = sorted({e.username for e in burst if e.username})
            shown = ", ".join(usernames[:5]) + ("..." if len(usernames) > 5 else "")
            alerts.append(Alert(
                rule_id="invalid_user_probe",
                title=meta.title,
                severity=meta.severity,
                description=(
                    f"{len(burst)} invalid-user login attempts from {ip} within "
                    f"{config.INVALID_USER_WINDOW_SECONDS}s (usernames tried: {shown})"
                ),
                timestamp=burst[-1].timestamp,
                source_file=burst[-1].source_file,
                source_ip=ip,
                username=None,
                evidence_lines=[e.line_number for e in burst],
            ))
    return alerts


# --------------------------------------------------------------------------
# Category 12 — spike in 4xx responses (access.log)
# --------------------------------------------------------------------------

def detect_http_error_spike(events: list[AccessLogEvent]) -> list[Alert]:
    """Flags 20+ 4xx (client error) responses to one IP within 60
    seconds — the fingerprint of directory/file brute-forcing tools like
    dirbuster or gobuster. Distinct from detect_high_request_rate: this
    is about concentration of *errors*, not raw traffic volume.
    """
    alerts = []
    meta = config.RULES["http_error_spike"]
    error_events = [e for e in events if 400 <= e.status_code < 500]
    for ip, ip_events in _group_by_ip(error_events).items():
        for burst in _find_bursts(ip_events, config.FOUR_XX_SPIKE_WINDOW_SECONDS, config.FOUR_XX_SPIKE_THRESHOLD):
            alerts.append(Alert(
                rule_id="http_error_spike",
                title=meta.title,
                severity=meta.severity,
                description=(
                    f"{len(burst)} 4xx responses from {ip} within "
                    f"{config.FOUR_XX_SPIKE_WINDOW_SECONDS}s (possible directory/file brute-forcing)"
                ),
                timestamp=burst[-1].timestamp,
                source_file=burst[-1].source_file,
                source_ip=ip,
                username=None,
                evidence_lines=[e.line_number for e in burst],
            ))
    return alerts