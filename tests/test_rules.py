"""Unit tests for log_analyzer.rules.

One TestCase per detection rule: does it fire on a known-bad event (or
burst), stay quiet on ordinary traffic, and -- for the five threshold/
burst-based rules -- correctly NOT fire one event below its threshold?
Events are built via parsers.py's own parse_auth_line/parse_access_line
rather than constructed by hand, since parsers.py already has its own
dedicated test coverage in test_parsers.py; this keeps every fixture
here as a realistic log line instead of a hand-assembled object that
might not match what parsing a real file would actually produce.
"""

import unittest
from datetime import datetime, timedelta

from log_analyzer import rules
from log_analyzer.models import AccessLogEvent, AuthLogEvent
from log_analyzer.parsers import parse_access_line, parse_auth_line


def _auth_event(text: str, year: int = 2026) -> AuthLogEvent:
    event = parse_auth_line(text, 1, "auth.log", year=year)
    assert event is not None, f"test fixture line failed to parse: {text!r}"
    return event


def _access_event(text: str) -> AccessLogEvent:
    event = parse_access_line(text, 1, "access.log")
    assert event is not None, f"test fixture line failed to parse: {text!r}"
    return event


def _failed_password_burst(ip: str, username: str, count: int, start: datetime, step_seconds: int = 8) -> list[AuthLogEvent]:
    events = []
    moment = start
    for i in range(count):
        day = f"{moment.day:2d}"
        line = f"{moment.strftime('%b')} {day} {moment.strftime('%H:%M:%S')} webserver01 sshd[{9000 + i}]: Failed password for {username} from {ip} port {40000 + i} ssh2"
        events.append(_auth_event(line, year=moment.year))
        moment += timedelta(seconds=step_seconds)
    return events


def _invalid_user_burst(ip: str, count: int, start: datetime, step_seconds: int = 8) -> list[AuthLogEvent]:
    events = []
    moment = start
    for i in range(count):
        day = f"{moment.day:2d}"
        line = f"{moment.strftime('%b')} {day} {moment.strftime('%H:%M:%S')} webserver01 sshd[{9000 + i}]: Failed password for invalid user fake{i} from {ip} port {41000 + i} ssh2"
        events.append(_auth_event(line, year=moment.year))
        moment += timedelta(seconds=step_seconds)
    return events


def _access_burst(ip: str, count: int, start: datetime, status: int = 200, step_seconds: int = 1) -> list[AccessLogEvent]:
    events = []
    moment = start
    for i in range(count):
        ts = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = f'{ip} - - [{ts}] "GET /page{i} HTTP/1.1" {status} 500 "-" "Mozilla/5.0"'
        events.append(_access_event(line))
        moment += timedelta(seconds=step_seconds)
    return events


BASE_TIME = datetime(2026, 7, 14, 10, 0, 0)  # a normal daytime hour throughout


class TestBruteForceLogin(unittest.TestCase):
    def test_fires_on_six_failures_one_ip(self):
        events = _failed_password_burst("203.0.113.10", "root", 6, BASE_TIME)
        alerts = rules.detect_brute_force_login(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "brute_force_login")
        self.assertEqual(alerts[0].source_ip, "203.0.113.10")
        self.assertEqual(len(alerts[0].evidence_lines), 6)

    def test_does_not_fire_on_four_failures_below_threshold(self):
        events = _failed_password_burst("203.0.113.10", "root", 4, BASE_TIME)
        alerts = rules.detect_brute_force_login(events)
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_normal_successful_logins(self):
        events = [_auth_event(f"Jul 14 10:0{i}:00 webserver01 sshd[{i}]: Accepted password for alice from 203.0.113.20 port 2222{i} ssh2") for i in range(3)]
        alerts = rules.detect_brute_force_login(events)
        self.assertEqual(alerts, [])


class TestLoginSuccessAfterFailures(unittest.TestCase):
    def test_fires_on_three_failures_then_success(self):
        events = _failed_password_burst("203.0.113.11", "alice", 3, BASE_TIME, step_seconds=5)
        success_time = BASE_TIME + timedelta(seconds=3 * 5 + 5)
        day = f"{success_time.day:2d}"
        events.append(_auth_event(f"{success_time.strftime('%b')} {day} {success_time.strftime('%H:%M:%S')} webserver01 sshd[9999]: Accepted password for alice from 203.0.113.11 port 22222 ssh2"))
        alerts = rules.detect_login_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].username, "alice")

    def test_does_not_fire_on_two_failures_then_success(self):
        events = _failed_password_burst("203.0.113.11", "alice", 2, BASE_TIME, step_seconds=5)
        success_time = BASE_TIME + timedelta(seconds=2 * 5 + 5)
        day = f"{success_time.day:2d}"
        events.append(_auth_event(f"{success_time.strftime('%b')} {day} {success_time.strftime('%H:%M:%S')} webserver01 sshd[9999]: Accepted password for alice from 203.0.113.11 port 22222 ssh2"))
        alerts = rules.detect_login_success_after_failures(events)
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_success_with_no_preceding_failures(self):
        events = [_auth_event("Jul 14 10:00:00 webserver01 sshd[1]: Accepted password for bob from 203.0.113.12 port 22222 ssh2")]
        alerts = rules.detect_login_success_after_failures(events)
        self.assertEqual(alerts, [])


class TestUnusualHourAccess(unittest.TestCase):
    def test_fires_on_successful_login_at_3am(self):
        auth_events = [_auth_event("Jul 14 03:00:00 webserver01 sshd[1]: Accepted password for night_owl from 203.0.113.13 port 22222 ssh2")]
        alerts = rules.detect_unusual_hour_access(auth_events, [])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "unusual_hour_access")

    def test_does_not_fire_on_successful_login_at_2pm(self):
        auth_events = [_auth_event("Jul 14 14:00:00 webserver01 sshd[1]: Accepted password for alice from 203.0.113.13 port 22222 ssh2")]
        alerts = rules.detect_unusual_hour_access(auth_events, [])
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_failed_login_at_3am(self):
        auth_events = [_auth_event("Jul 14 03:00:00 webserver01 sshd[1]: Failed password for root from 203.0.113.13 port 22222 ssh2")]
        alerts = rules.detect_unusual_hour_access(auth_events, [])
        self.assertEqual(alerts, [])

    def test_fires_on_access_request_at_4am(self):
        access_events = [_access_event('203.0.113.14 - - [14/Jul/2026:04:00:00 +0000] "GET /dashboard HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_unusual_hour_access([], access_events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_access_request_at_2pm(self):
        access_events = [_access_event('203.0.113.14 - - [14/Jul/2026:14:00:00 +0000] "GET /dashboard HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_unusual_hour_access([], access_events)
        self.assertEqual(alerts, [])


class TestSqlInjectionAttempt(unittest.TestCase):
    def test_fires_on_union_select_payload(self):
        events = [_access_event('203.0.113.15 - - [14/Jul/2026:10:00:00 +0000] "GET /product?id=1 UNION SELECT user,pass FROM users-- HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_sql_injection_attempt(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "sql_injection_attempt")

    def test_does_not_fire_on_clean_request(self):
        events = [_access_event('203.0.113.15 - - [14/Jul/2026:10:00:00 +0000] "GET /product?id=42 HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_sql_injection_attempt(events)
        self.assertEqual(alerts, [])


class TestXssAttempt(unittest.TestCase):
    def test_fires_on_script_tag_payload(self):
        events = [_access_event('203.0.113.16 - - [14/Jul/2026:10:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_xss_attempt(events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_clean_request(self):
        events = [_access_event('203.0.113.16 - - [14/Jul/2026:10:00:00 +0000] "GET /search?q=laptops HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_xss_attempt(events)
        self.assertEqual(alerts, [])


class TestPathTraversalAttempt(unittest.TestCase):
    def test_fires_on_dot_dot_slash_payload(self):
        events = [_access_event('203.0.113.17 - - [14/Jul/2026:10:00:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 0 "-" "Mozilla/5.0"')]
        alerts = rules.detect_path_traversal_attempt(events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_clean_request(self):
        events = [_access_event('203.0.113.17 - - [14/Jul/2026:10:00:00 +0000] "GET /download?file=report.pdf HTTP/1.1" 200 5000 "-" "Mozilla/5.0"')]
        alerts = rules.detect_path_traversal_attempt(events)
        self.assertEqual(alerts, [])


class TestSensitivePathAccess(unittest.TestCase):
    def test_fires_on_exact_sensitive_path(self):
        events = [_access_event('203.0.113.18 - - [14/Jul/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Mozilla/5.0"')]
        alerts = rules.detect_sensitive_path_access(events)
        self.assertEqual(len(alerts), 1)

    def test_fires_on_sensitive_subpath(self):
        events = [_access_event('203.0.113.18 - - [14/Jul/2026:10:00:00 +0000] "GET /admin/users HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_sensitive_path_access(events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_similarly_named_path(self):
        # /administrator merely starts with the same characters as
        # /admin -- it isn't /admin or a subpath of it, and shouldn't
        # be flagged as one.
        events = [_access_event('203.0.113.18 - - [14/Jul/2026:10:00:00 +0000] "GET /administrator HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_sensitive_path_access(events)
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_ordinary_path(self):
        events = [_access_event('203.0.113.18 - - [14/Jul/2026:10:00:00 +0000] "GET /about HTTP/1.1" 200 500 "-" "Mozilla/5.0"')]
        alerts = rules.detect_sensitive_path_access(events)
        self.assertEqual(alerts, [])


class TestHighRequestRate(unittest.TestCase):
    def test_fires_on_fifty_five_requests_one_minute(self):
        events = _access_burst("203.0.113.19", 55, BASE_TIME)
        alerts = rules.detect_high_request_rate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0].evidence_lines), 55)

    def test_does_not_fire_on_forty_nine_requests_below_threshold(self):
        events = _access_burst("203.0.113.19", 49, BASE_TIME)
        alerts = rules.detect_high_request_rate(events)
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_a_handful_of_normal_requests(self):
        events = _access_burst("203.0.113.19", 5, BASE_TIME, step_seconds=20)
        alerts = rules.detect_high_request_rate(events)
        self.assertEqual(alerts, [])


class TestScannerUserAgent(unittest.TestCase):
    def test_fires_on_sqlmap_user_agent(self):
        events = [_access_event('203.0.113.21 - - [14/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 500 "-" "sqlmap/1.6.12#stable"')]
        alerts = rules.detect_scanner_user_agent(events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_normal_browser_user_agent(self):
        events = [_access_event('203.0.113.21 - - [14/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')]
        alerts = rules.detect_scanner_user_agent(events)
        self.assertEqual(alerts, [])


class TestPrivilegeEscalation(unittest.TestCase):
    def test_fires_on_sudo_failure(self):
        events = [_auth_event("Jul 14 10:00:00 webserver01 sudo: pam_unix(sudo:auth): authentication failure; logname=eve uid=1000 euid=0 tty=/dev/pts/1 ruser= rhost=  user=eve")]
        alerts = rules.detect_privilege_escalation(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].username, "eve")

    def test_fires_on_su_attempt(self):
        events = [_auth_event("Jul 14 10:00:00 webserver01 su: FAILED su for root by mallory")]
        alerts = rules.detect_privilege_escalation(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].username, "mallory")

    def test_does_not_fire_on_routine_sudo_command(self):
        # A sudo command that isn't an auth failure classifies as
        # AuthEventType.OTHER, not SUDO_FAILURE -- routine admin work,
        # not an escalation attempt.
        events = [_auth_event("Jul 14 10:00:00 webserver01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls")]
        alerts = rules.detect_privilege_escalation(events)
        self.assertEqual(alerts, [])


class TestInvalidUserProbe(unittest.TestCase):
    def test_fires_on_six_invalid_users_one_ip(self):
        events = _invalid_user_burst("203.0.113.22", 6, BASE_TIME)
        alerts = rules.detect_invalid_user_probe(events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_four_invalid_users_below_threshold(self):
        events = _invalid_user_burst("203.0.113.22", 4, BASE_TIME)
        alerts = rules.detect_invalid_user_probe(events)
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_normal_login(self):
        events = [_auth_event("Jul 14 10:00:00 webserver01 sshd[1]: Accepted password for alice from 203.0.113.22 port 22222 ssh2")]
        alerts = rules.detect_invalid_user_probe(events)
        self.assertEqual(alerts, [])


class TestHttpErrorSpike(unittest.TestCase):
    def test_fires_on_twenty_two_404s_one_minute(self):
        events = _access_burst("203.0.113.23", 22, BASE_TIME, status=404, step_seconds=2)
        alerts = rules.detect_http_error_spike(events)
        self.assertEqual(len(alerts), 1)

    def test_does_not_fire_on_nineteen_404s_below_threshold(self):
        events = _access_burst("203.0.113.23", 19, BASE_TIME, status=404, step_seconds=2)
        alerts = rules.detect_http_error_spike(events)
        self.assertEqual(alerts, [])

    def test_does_not_fire_on_a_couple_isolated_404s(self):
        events = _access_burst("203.0.113.23", 2, BASE_TIME, status=404, step_seconds=30)
        alerts = rules.detect_http_error_spike(events)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()