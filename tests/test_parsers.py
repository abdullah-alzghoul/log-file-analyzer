"""Unit tests for log_analyzer.parsers.

Covers every AuthEventType the parser can produce, the access.log
field-splitting behavior (including the embedded-space case SQLi
payloads rely on), and how both line-level and file-level parsing
handle malformed or empty input -- skip and warn, never crash.
"""

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime
from pathlib import Path

from log_analyzer.models import AuthEventType
from log_analyzer.parsers import (
    parse_access_line,
    parse_access_log,
    parse_auth_line,
    parse_auth_log,
)


class TestParseAuthLine(unittest.TestCase):
    """One test per AuthEventType the parser can produce, plus the
    malformed/empty-line paths every auth.log line goes through first.
    """

    def test_accepted_password(self):
        line = "Jul 14 09:48:03 webserver01 sshd[24601]: Accepted password for alice from 198.51.100.23 port 51234 ssh2"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, AuthEventType.ACCEPTED_PASSWORD)
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.source_ip, "198.51.100.23")
        self.assertEqual(event.pid, 24601)
        self.assertEqual(event.timestamp, datetime(2026, 7, 14, 9, 48, 3))

    def test_failed_password(self):
        line = "Jul 14 09:48:10 webserver01 sshd[24602]: Failed password for root from 203.0.113.45 port 51240 ssh2"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.FAILED_PASSWORD)
        self.assertEqual(event.username, "root")
        self.assertEqual(event.source_ip, "203.0.113.45")

    def test_invalid_user_failed_password_phrasing(self):
        line = "Jul 14 09:48:15 webserver01 sshd[24603]: Failed password for invalid user test123 from 203.0.113.45 port 51241 ssh2"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.INVALID_USER)
        self.assertEqual(event.username, "test123")

    def test_invalid_user_standalone_phrasing(self):
        # Some OpenSSH versions log a standalone "Invalid user X from Y"
        # line with no separate "Failed password" line at all.
        line = "Jul 14 09:48:16 webserver01 sshd[24604]: Invalid user backdoor from 203.0.113.45"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.INVALID_USER)
        self.assertEqual(event.username, "backdoor")
        self.assertEqual(event.source_ip, "203.0.113.45")

    def test_sudo_failure(self):
        line = "Jul 14 09:49:00 webserver01 sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser= rhost=  user=bob"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.SUDO_FAILURE)
        self.assertEqual(event.username, "bob")
        self.assertIsNone(event.source_ip)

    def test_su_attempt_failed(self):
        line = "Jul 14 09:50:00 webserver01 su: FAILED su for root by carol"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.SU_ATTEMPT)
        self.assertEqual(event.username, "carol")

    def test_su_attempt_successful(self):
        line = "Jul 14 09:50:05 webserver01 su: Successful su for root by dave"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.SU_ATTEMPT)
        self.assertEqual(event.username, "dave")

    def test_session_opened(self):
        line = "Jul 14 09:47:00 webserver01 sshd[24600]: pam_unix(sshd:session): session opened for user alice by (uid=0)"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.SESSION_OPENED)
        self.assertEqual(event.username, "alice")

    def test_session_closed(self):
        line = "Jul 14 09:55:00 webserver01 sshd[24600]: pam_unix(sshd:session): session closed for user alice"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertEqual(event.event_type, AuthEventType.SESSION_CLOSED)
        self.assertEqual(event.username, "alice")

    def test_unrecognized_message_becomes_other(self):
        # Well-formed syslog envelope, but a message body none of the
        # specific regexes match -- should parse, not be dropped, and
        # land in the catch-all bucket rather than raising.
        line = "Jul 14 09:56:00 webserver01 sshd[24600]: fatal: Timeout before authentication for 203.0.113.99"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, AuthEventType.OTHER)

    def test_space_padded_single_digit_day(self):
        # Classic syslog pads single-digit days with a space, not a
        # zero -- "Jul  4", not "Jul 04". This is the exact case that
        # ruled out using strptime's %d directly.
        line = "Jul  4 03:15:00 webserver01 sshd[100]: Accepted password for erin from 10.0.0.5 port 22 ssh2"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, datetime(2026, 7, 4, 3, 15, 0))

    def test_pid_absent(self):
        # process[pid] is common but not universal -- the pid group is
        # optional in AUTH_LOG_LINE_RE, so a line without it should
        # still parse, with pid=None rather than raising.
        line = "Jul 14 09:56:30 webserver01 kernel: some kernel message with no pid at all"
        event = parse_auth_line(line, 1, "auth.log", year=2026)
        self.assertIsNotNone(event)
        self.assertIsNone(event.pid)

    def test_default_year_is_current_year_when_omitted(self):
        line = "Jul 14 09:48:03 webserver01 sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
        event = parse_auth_line(line, 1, "auth.log")  # no year passed
        self.assertEqual(event.timestamp.year, datetime.now().year)

    def test_malformed_line_returns_none_not_raise(self):
        with redirect_stderr(io.StringIO()):
            event = parse_auth_line("this is not a syslog line at all", 1, "auth.log")
        self.assertIsNone(event)

    def test_empty_line_returns_none_silently(self):
        # Distinct from a malformed line -- a blank line is expected
        # (trailing newline at EOF, for instance), not a warning-worthy
        # parse failure, so it should produce no stderr output at all.
        captured = io.StringIO()
        with redirect_stderr(captured):
            event = parse_auth_line("", 1, "auth.log")
        self.assertIsNone(event)
        self.assertEqual(captured.getvalue(), "")

    def test_invalid_calendar_date_returns_none(self):
        # Well-formed envelope, impossible date -- Feb 30 doesn't
        # exist. Should be skipped like any other malformed line, not
        # raise ValueError up through the caller.
        with redirect_stderr(io.StringIO()):
            event = parse_auth_line(
                "Feb 30 09:00:00 webserver01 sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2",
                1, "auth.log", year=2026,
            )
        self.assertIsNone(event)


class TestParseAccessLine(unittest.TestCase):
    """Combined-log-format parsing, including the field-splitting logic
    that has to survive a payload containing literal spaces.
    """

    def test_normal_get_request(self):
        line = '198.51.100.23 - - [14/Jul/2026:09:48:03 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        event = parse_access_line(line, 1, "access.log")
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "198.51.100.23")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/index.html")
        self.assertEqual(event.protocol, "HTTP/1.1")
        self.assertEqual(event.status_code, 200)
        self.assertEqual(event.response_size, 1024)
        self.assertIsNone(event.referrer)  # "-" becomes None
        self.assertEqual(event.timestamp, datetime(2026, 7, 14, 9, 48, 3))

    def test_request_with_embedded_spaces_in_payload(self):
        # The exact scenario _split_request_line exists for: a SQLi
        # payload containing literal spaces must not get chopped by a
        # naive split, or the SQLi rule would never see it intact.
        line = '203.0.113.45 - - [14/Jul/2026:09:49:00 +0000] "GET /product?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        event = parse_access_line(line, 1, "access.log")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/product?id=1 UNION SELECT username,password FROM users--")
        self.assertEqual(event.protocol, "HTTP/1.1")

    def test_referrer_present(self):
        line = '203.0.113.10 - - [14/Jul/2026:10:00:00 +0000] "GET /about HTTP/1.1" 200 500 "https://example.com/" "Mozilla/5.0"'
        event = parse_access_line(line, 1, "access.log")
        self.assertEqual(event.referrer, "https://example.com/")

    def test_non_numeric_response_size_becomes_none(self):
        # Apache logs "-" for size when a request has no body (e.g. a
        # 304 Not Modified) -- not a digit, so response_size should be
        # None rather than raising trying to int() it.
        line = '203.0.113.10 - - [14/Jul/2026:10:01:00 +0000] "GET /style.css HTTP/1.1" 304 - "-" "Mozilla/5.0"'
        event = parse_access_line(line, 1, "access.log")
        self.assertIsNotNone(event)
        self.assertIsNone(event.response_size)

    def test_malformed_line_returns_none_not_raise(self):
        with redirect_stderr(io.StringIO()):
            event = parse_access_line("not an access log line at all", 1, "access.log")
        self.assertIsNone(event)

    def test_empty_line_returns_none_silently(self):
        captured = io.StringIO()
        with redirect_stderr(captured):
            event = parse_access_line("", 1, "access.log")
        self.assertIsNone(event)
        self.assertEqual(captured.getvalue(), "")

    def test_unparseable_timestamp_returns_none(self):
        # Well-formed everywhere except the bracketed timestamp itself.
        with redirect_stderr(io.StringIO()):
            event = parse_access_line(
                '203.0.113.10 - - [not-a-real-timestamp] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
                1, "access.log",
            )
        self.assertIsNone(event)


class TestParseAuthLog(unittest.TestCase):
    """File-level parsing: does a mix of good and malformed lines in
    one real file produce exactly the events it should, skipping the
    bad ones without aborting the whole read?
    """

    def _write_temp_log(self, content: str) -> Path:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
        handle.write(content)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def test_mixed_valid_and_malformed_lines(self):
        content = (
            "Jul 14 09:00:00 webserver01 sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2\n"
            "this line is garbage and matches nothing\n"
            "Jul 14 09:00:05 webserver01 sshd[2]: Failed password for root from 10.0.0.2 port 22 ssh2\n"
            "\n"
            "Jul 14 09:00:10 webserver01 sshd[3]: Accepted password for bob from 10.0.0.3 port 22 ssh2\n"
        )
        path = self._write_temp_log(content)
        with redirect_stderr(io.StringIO()):
            events = parse_auth_log(path, year=2026)
        # 5 lines in: 3 valid, 1 garbage (skipped+warned), 1 blank
        # (skipped silently) -- exactly 3 events back.
        self.assertEqual(len(events), 3)
        self.assertEqual([e.line_number for e in events], [1, 3, 5])

    def test_empty_file_returns_empty_list(self):
        path = self._write_temp_log("")
        events = parse_auth_log(path, year=2026)
        self.assertEqual(events, [])


class TestParseAccessLog(unittest.TestCase):
    """Same file-level coverage as TestParseAuthLog, for access.log."""

    def _write_temp_log(self, content: str) -> Path:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
        handle.write(content)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def test_mixed_valid_and_malformed_lines(self):
        content = (
            '198.51.100.1 - - [14/Jul/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n'
            "not an access log line\n"
            '198.51.100.2 - - [14/Jul/2026:09:00:05 +0000] "GET /about HTTP/1.1" 200 300 "-" "Mozilla/5.0"\n'
        )
        path = self._write_temp_log(content)
        with redirect_stderr(io.StringIO()):
            events = parse_access_log(path)
        self.assertEqual(len(events), 2)
        self.assertEqual([e.line_number for e in events], [1, 3])

    def test_empty_file_returns_empty_list(self):
        path = self._write_temp_log("")
        events = parse_access_log(path)
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()