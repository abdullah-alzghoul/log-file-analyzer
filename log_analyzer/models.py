"""Data models shared across the Log File Analyzer.

Every other module in this package works with the types defined here:
parsers.py turns raw log lines into LogEvent subclasses, rules.py inspects
those events and produces Alert objects, and report.py renders or exports
whatever alerts the rules found. Keeping these shapes in one place means
every file agrees on what a "log event" or "alert" actually looks like.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum


class Severity(IntEnum):
    """Alert severity. Members compare and sort naturally: LOW < MEDIUM < HIGH."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name.capitalize()


class AuthEventType(Enum):
    """Normalized categories of auth.log events, assigned during parsing."""

    ACCEPTED_PASSWORD = "accepted_password"
    FAILED_PASSWORD = "failed_password"
    INVALID_USER = "invalid_user"
    SUDO_FAILURE = "sudo_failure"
    SU_ATTEMPT = "su_attempt"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    OTHER = "other"


@dataclass
class LogEvent:
    """Fields common to every parsed log line, regardless of format.

    Not meant to be instantiated directly — use AuthLogEvent or
    AccessLogEvent, which extend this with format-specific fields.
    """

    raw_line: str
    line_number: int
    source_file: str


@dataclass
class AuthLogEvent(LogEvent):
    """A single parsed line from a Linux-style auth.log."""

    timestamp: datetime
    host: str
    process: str
    event_type: AuthEventType
    message: str
    pid: int | None = None
    username: str | None = None
    source_ip: str | None = None


@dataclass
class AccessLogEvent(LogEvent):
    """A single parsed line from an Apache/Nginx combined-format access.log."""

    source_ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status_code: int
    user_agent: str
    response_size: int | None = None
    referrer: str | None = None


@dataclass
class Alert:
    """A single suspicious-activity finding, ready to display or export."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    timestamp: datetime
    source_file: str
    source_ip: str | None = None
    username: str | None = None
    evidence_lines: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON/CSV-safe representation of this alert."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_file": self.source_file,
            "source_ip": self.source_ip,
            "username": self.username,
            "evidence_lines": self.evidence_lines,
        }