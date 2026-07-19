"""Unit tests for log_analyzer.analyzer.

Small end-to-end checks: a few realistic log lines in, the expected
combined, sorted Alert list out. Doesn't re-test what test_rules.py and
test_parsers.py already cover in depth -- this file is specifically
about run_analysis()'s own job: wiring parsing and every rule together,
handling the optional-log-type branching, and enforcing its own
preconditions.
"""

import tempfile
import unittest
from pathlib import Path

from log_analyzer.analyzer import run_analysis


AUTH_LOG = """\
Jul 14 10:00:00 webserver01 sshd[1]: Failed password for root from 203.0.113.10 port 40000 ssh2
Jul 14 10:00:08 webserver01 sshd[2]: Failed password for root from 203.0.113.10 port 40001 ssh2
Jul 14 10:00:16 webserver01 sshd[3]: Failed password for root from 203.0.113.10 port 40002 ssh2
Jul 14 10:00:24 webserver01 sshd[4]: Failed password for root from 203.0.113.10 port 40003 ssh2
Jul 14 10:00:32 webserver01 sshd[5]: Failed password for root from 203.0.113.10 port 40004 ssh2
Jul 14 10:00:40 webserver01 sshd[6]: Failed password for root from 203.0.113.10 port 40005 ssh2
Jul 14 03:00:00 webserver01 sshd[7]: Accepted password for night_owl from 203.0.113.20 port 41000 ssh2
"""

ACCESS_LOG = """\
203.0.113.30 - - [14/Jul/2026:11:00:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "sqlmap/1.6.12#stable"
"""


class TestAnalyzerCombinedLogs(unittest.TestCase):
    """Both log types given at once -- the normal, full-featured case."""

    def setUp(self):
        self.auth_path = self._write_temp(AUTH_LOG, "auth")
        self.access_path = self._write_temp(ACCESS_LOG, "access")

    def _write_temp(self, content: str, tag: str) -> Path:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=f"_{tag}.log", delete=False, encoding="utf-8")
        handle.write(content)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def test_event_counts(self):
        result = run_analysis(self.auth_path, self.access_path, year=2026)
        self.assertEqual(result.auth_events_parsed, 7)
        self.assertEqual(result.access_events_parsed, 1)

    def test_expected_rule_ids_fire_and_nothing_else(self):
        result = run_analysis(self.auth_path, self.access_path, year=2026)
        expected = {"brute_force_login", "unusual_hour_access", "sensitive_path_access", "scanner_user_agent"}
        actual = {a.rule_id for a in result.alerts}
        self.assertEqual(actual, expected)
        # one line hitting two rules at once -- 4 rule_ids, but one of
        # them (sensitive_path_access + scanner_user_agent) share a
        # single evidence line, so 4 alerts total, not 3 or 5.
        self.assertEqual(len(result.alerts), 4)

    def test_alerts_sorted_by_severity_descending(self):
        result = run_analysis(self.auth_path, self.access_path, year=2026)
        severities = [int(a.severity) for a in result.alerts]
        self.assertEqual(severities, sorted(severities, reverse=True))
        self.assertEqual(result.alerts[0].rule_id, "brute_force_login")  # the only High
        self.assertEqual(result.alerts[-1].rule_id, "unusual_hour_access")  # the only Low

    def test_result_records_the_paths_it_was_given(self):
        result = run_analysis(self.auth_path, self.access_path, year=2026)
        self.assertEqual(result.auth_log_path, str(self.auth_path))
        self.assertEqual(result.access_log_path, str(self.access_path))


class TestAnalyzerSingleLogType(unittest.TestCase):
    """Either log type may be omitted -- confirms both directions skip
    cleanly instead of erroring or silently mixing in the other side.
    """

    def setUp(self):
        self.auth_path = self._write_temp(AUTH_LOG, "auth")
        self.access_path = self._write_temp(ACCESS_LOG, "access")

    def _write_temp(self, content: str, tag: str) -> Path:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=f"_{tag}.log", delete=False, encoding="utf-8")
        handle.write(content)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def test_auth_only_produces_no_access_side_alerts(self):
        result = run_analysis(auth_log_path=self.auth_path, year=2026)
        self.assertEqual(result.access_events_parsed, 0)
        self.assertIsNone(result.access_log_path)
        rule_ids = {a.rule_id for a in result.alerts}
        self.assertNotIn("sensitive_path_access", rule_ids)
        self.assertNotIn("scanner_user_agent", rule_ids)
        self.assertIn("brute_force_login", rule_ids)

    def test_access_only_produces_no_auth_side_alerts(self):
        result = run_analysis(access_log_path=self.access_path)
        self.assertEqual(result.auth_events_parsed, 0)
        self.assertIsNone(result.auth_log_path)
        rule_ids = {a.rule_id for a in result.alerts}
        self.assertNotIn("brute_force_login", rule_ids)
        self.assertNotIn("unusual_hour_access", rule_ids)
        self.assertIn("sensitive_path_access", rule_ids)


class TestAnalyzerErrorHandling(unittest.TestCase):
    def test_no_paths_raises_value_error(self):
        with self.assertRaises(ValueError):
            run_analysis()

    def test_nonexistent_file_propagates_not_swallowed(self):
        # analyzer.py deliberately does not catch file errors itself --
        # that's cli.py's job. A missing path should surface as a real,
        # catchable OSError here, not vanish into an empty result.
        with self.assertRaises(OSError):
            run_analysis(auth_log_path="this_file_does_not_exist_12345.log")


if __name__ == "__main__":
    unittest.main()