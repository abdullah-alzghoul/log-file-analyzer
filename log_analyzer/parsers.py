"""Log parsers for the Log File Analyzer.

Turns raw text lines from Linux-style auth.log files and Apache/Nginx
combined-format access.log files into the LogEvent objects defined in
models.py. Nothing in here decides whether an event is suspicious —
that's rules.py's job. This file's only responsibility is: given a line
of text, either produce a correctly-typed event object, or skip the line
cleanly (with a warning) if it doesn't match a recognized format.
"""

import re
import sys
from datetime import datetime
from pathlib import Path

from log_analyzer.models import AccessLogEvent, AuthEventType, AuthLogEvent


_MONTH_NUMBERS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


# --------------------------------------------------------------------------
# auth.log
# --------------------------------------------------------------------------

# Classic syslog envelope: "Mon DD HH:MM:SS host process[pid]: message"
# Month/day/time are captured separately (not handed to strptime) so that
# syslog's habit of space-padding single-digit days ("Jul  4") is handled
# by a plain \s+ instead of relying on strptime's whitespace behavior,
# and so month names never depend on the system's locale.
AUTH_LOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_ACCEPTED_RE = re.compile(
    r"^Accepted \S+ for (?P<username>\S+) from (?P<ip>\S+) port \d+", re.IGNORECASE
)
_FAILED_INVALID_RE = re.compile(
    r"^Failed \S+ for invalid user (?P<username>\S+) from (?P<ip>\S+) port \d+", re.IGNORECASE
)
_FAILED_VALID_RE = re.compile(
    r"^Failed \S+ for (?P<username>\S+) from (?P<ip>\S+) port \d+", re.IGNORECASE
)
_INVALID_USER_STANDALONE_RE = re.compile(
    r"^Invalid user (?P<username>\S+) from (?P<ip>\S+)", re.IGNORECASE
)
_SUDO_FAILURE_RE = re.compile(
    r"authentication failure;.*?\buser=(?P<username>\S*)", re.IGNORECASE
)
_SU_RE = re.compile(
    r"^(?P<result>Successful|FAILED) su for (?P<target_user>\S+) by (?P<username>\S+)",
    re.IGNORECASE,
)
_SESSION_OPENED_RE = re.compile(r"session opened for user (?P<username>\S+)", re.IGNORECASE)
_SESSION_CLOSED_RE = re.compile(r"session closed for user (?P<username>\S+)", re.IGNORECASE)


def _classify_auth_message(process: str, message: str) -> tuple[AuthEventType, str | None, str | None]:
    """Return (event_type, username, source_ip) for a syslog message body.

    process gates the sudo/su checks specifically, since their message
    text alone ("authentication failure", "for X by Y") isn't unique
    enough to trust without knowing which daemon logged it.
    """
    if process == "sudo":
        match = _SUDO_FAILURE_RE.search(message)
        if match:
            return AuthEventType.SUDO_FAILURE, match.group("username") or None, None

    if process == "su":
        match = _SU_RE.match(message)
        if match:
            return AuthEventType.SU_ATTEMPT, match.group("username"), None

    match = _ACCEPTED_RE.match(message)
    if match:
        return AuthEventType.ACCEPTED_PASSWORD, match.group("username"), match.group("ip")

    match = _FAILED_INVALID_RE.match(message)
    if match:
        return AuthEventType.INVALID_USER, match.group("username"), match.group("ip")

    match = _FAILED_VALID_RE.match(message)
    if match:
        return AuthEventType.FAILED_PASSWORD, match.group("username"), match.group("ip")

    match = _INVALID_USER_STANDALONE_RE.match(message)
    if match:
        return AuthEventType.INVALID_USER, match.group("username"), match.group("ip")

    match = _SESSION_OPENED_RE.search(message)
    if match:
        return AuthEventType.SESSION_OPENED, match.group("username"), None

    match = _SESSION_CLOSED_RE.search(message)
    if match:
        return AuthEventType.SESSION_CLOSED, match.group("username"), None

    return AuthEventType.OTHER, None, None


def parse_auth_line(
    line: str, line_number: int, source_file: str, year: int | None = None
) -> AuthLogEvent | None:
    """Parse one auth.log line into an AuthLogEvent, or None if it doesn't
    match the expected syslog envelope at all.

    Classic syslog timestamps carry no year. `year` defaults to the
    current year, which is correct for freshly generated demo data but
    is a documented simplification — a log file spanning a year boundary
    would need the caller to pass the right year explicitly.
    """
    stripped = line.rstrip("\r\n")
    if not stripped.strip():
        return None

    match = AUTH_LOG_LINE_RE.match(stripped)
    if match is None:
        print(f"[parsers] Skipping malformed line {line_number} in {source_file}: {stripped[:80]!r}", file=sys.stderr)
        return None

    fields = match.groupdict()
    month_num = _MONTH_NUMBERS.get(fields["month"].title())
    if month_num is None:
        print(f"[parsers] Skipping line {line_number} in {source_file}: unrecognized month {fields['month']!r}", file=sys.stderr)
        return None

    hour, minute, second = (int(part) for part in fields["time"].split(":"))
    resolved_year = year if year is not None else datetime.now().year

    try:
        timestamp = datetime(resolved_year, month_num, int(fields["day"]), hour, minute, second)
    except ValueError as exc:
        print(f"[parsers] Skipping line {line_number} in {source_file}: invalid timestamp ({exc})", file=sys.stderr)
        return None

    event_type, username, source_ip = _classify_auth_message(fields["process"], fields["message"])

    return AuthLogEvent(
        raw_line=stripped,
        line_number=line_number,
        source_file=source_file,
        timestamp=timestamp,
        host=fields["host"],
        process=fields["process"],
        event_type=event_type,
        message=fields["message"],
        pid=int(fields["pid"]) if fields["pid"] else None,
        username=username,
        source_ip=source_ip,
    )


def parse_auth_log(filepath: str | Path, year: int | None = None) -> list[AuthLogEvent]:
    """Parse an entire auth.log file into a list of AuthLogEvent objects.

    Malformed lines are skipped with a warning printed to stderr rather
    than raising — one bad line in a multi-thousand-line file shouldn't
    take down the whole run. Reads line-by-line rather than loading the
    whole file into memory, so this scales to large files too.
    """
    filepath = Path(filepath)
    source_name = filepath.name
    events: list[AuthLogEvent] = []
    with filepath.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            event = parse_auth_line(line, line_number, source_name, year=year)
            if event is not None:
                events.append(event)
    return events


# --------------------------------------------------------------------------
# access.log (Apache/Nginx combined format)
# --------------------------------------------------------------------------

ACCESS_LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"\s*$'
)

_ACCESS_TIMESTAMP_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<tz_sign>[+-])(?P<tz_hour>\d{2})(?P<tz_minute>\d{2})$"
)

_PROTOCOL_RE = re.compile(r"^HTTP/\d\.\d$")


def _parse_access_timestamp(raw: str) -> datetime | None:
    """Parse a combined-log-format timestamp into a naive datetime.

    The timezone offset (e.g. +0000) is validated as part of the format
    but not attached to the result. Every timestamp in this project is
    treated as wall-clock time as logged, matching AuthLogEvent — which
    carries no timezone info at all — so the two log sources stay
    directly comparable for rules like unusual-hours detection.
    """
    match = _ACCESS_TIMESTAMP_RE.match(raw)
    if match is None:
        return None
    month_num = _MONTH_NUMBERS.get(match.group("month").title())
    if month_num is None:
        return None
    try:
        return datetime(
            int(match.group("year")), month_num, int(match.group("day")),
            int(match.group("hour")), int(match.group("minute")), int(match.group("second")),
        )
    except ValueError:
        return None


def _split_request_line(request_line: str) -> tuple[str, str, str]:
    """Split a raw request line into (method, path, protocol).

    A well-formed line is "METHOD PATH PROTOCOL", but an attacker's raw
    payload can itself contain literal spaces (against HTTP spec — spaces
    belong URL-encoded — but a log records what was actually sent). So
    instead of a naive split on the first two spaces, the protocol is
    peeled off the end first if it looks like one, the method off the
    front, and everything remaining — however many spaces it contains —
    is treated as the path. That keeps an injected payload like "UNION
    SELECT ..." intact in `path`, where the SQLi/XSS rules expect it.
    """
    if not request_line:
        return "", "", ""

    parts = request_line.split(" ")
    if len(parts) >= 3 and _PROTOCOL_RE.match(parts[-1]):
        return parts[0], " ".join(parts[1:-1]), parts[-1]
    if len(parts) >= 2:
        return parts[0], " ".join(parts[1:]), ""
    return "", parts[0], ""


def parse_access_line(line: str, line_number: int, source_file: str) -> AccessLogEvent | None:
    """Parse one combined-format access.log line into an AccessLogEvent,
    or None if it doesn't match the expected structure at all.
    """
    stripped = line.rstrip("\r\n")
    if not stripped.strip():
        return None

    match = ACCESS_LOG_LINE_RE.match(stripped)
    if match is None:
        print(f"[parsers] Skipping malformed line {line_number} in {source_file}: {stripped[:80]!r}", file=sys.stderr)
        return None

    fields = match.groupdict()

    timestamp = _parse_access_timestamp(fields["timestamp"])
    if timestamp is None:
        print(f"[parsers] Skipping line {line_number} in {source_file}: unparseable timestamp {fields['timestamp']!r}", file=sys.stderr)
        return None

    method, path, protocol = _split_request_line(fields["request"])
    size_raw = fields["size"]
    response_size = int(size_raw) if size_raw.isdigit() else None

    return AccessLogEvent(
        raw_line=stripped,
        line_number=line_number,
        source_file=source_file,
        source_ip=fields["ip"],
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status_code=int(fields["status"]),
        user_agent=fields["user_agent"],
        response_size=response_size,
        referrer=fields["referrer"] if fields["referrer"] != "-" else None,
    )


def parse_access_log(filepath: str | Path) -> list[AccessLogEvent]:
    """Parse an entire access.log file into a list of AccessLogEvent
    objects. Same skip-and-warn behavior as parse_auth_log.
    """
    filepath = Path(filepath)
    source_name = filepath.name
    events: list[AccessLogEvent] = []
    with filepath.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            event = parse_access_line(line, line_number, source_name)
            if event is not None:
                events.append(event)
    return events