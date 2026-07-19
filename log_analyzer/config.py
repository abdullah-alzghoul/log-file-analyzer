"""Tunable detection settings for the Log File Analyzer.

Every numeric threshold, time window, and suspicious-pattern list a
detection rule needs lives here, not scattered across rules.py — so
tuning the analyzer for a different environment (stricter thresholds,
extra sensitive paths, additional scanner signatures) means editing one
file, not hunting through detection logic.

Sections below are ordered to match the 12 baseline categories agreed on
in Phase 1; each constant's comment names the category it backs.
"""

import re
from dataclasses import dataclass

from log_analyzer.models import Severity


# --------------------------------------------------------------------------
# Rule metadata — single source of truth for each rule's display title and
# severity. rules.py looks up RULES[rule_id] rather than hardcoding either,
# so the two can never drift out of sync with each other.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleMeta:
    """Fixed metadata for one detection rule."""

    title: str
    severity: Severity


RULES: dict[str, RuleMeta] = {
    "brute_force_login": RuleMeta("Brute-Force Login Attempt", Severity.HIGH),
    "login_success_after_failures": RuleMeta(
        "Successful Login After Repeated Failures", Severity.HIGH
    ),
    "unusual_hour_access": RuleMeta("Access During Unusual Hours", Severity.LOW),
    "sql_injection_attempt": RuleMeta("SQL Injection Pattern Detected", Severity.HIGH),
    "xss_attempt": RuleMeta(
        "Cross-Site Scripting (XSS) Pattern Detected", Severity.MEDIUM
    ),
    "path_traversal_attempt": RuleMeta("Path Traversal Attempt", Severity.HIGH),
    "sensitive_path_access": RuleMeta(
        "Request to Sensitive or Administrative Path", Severity.MEDIUM
    ),
    "high_request_rate": RuleMeta("Abnormally High Request Rate", Severity.MEDIUM),
    "scanner_user_agent": RuleMeta(
        "Known Scanning/Attack-Tool User-Agent", Severity.MEDIUM
    ),
    "privilege_escalation": RuleMeta("Privilege Escalation Indicator", Severity.HIGH),
    "invalid_user_probe": RuleMeta("Invalid-User Login Probing", Severity.LOW),
    "http_error_spike": RuleMeta("Spike in HTTP Error Responses", Severity.MEDIUM),
}


# --------------------------------------------------------------------------
# Login / brute-force thresholds (auth.log)
# --------------------------------------------------------------------------

# Category 1: brute-force login attempts
BRUTE_FORCE_WINDOW_SECONDS = 300     # 5 minutes
BRUTE_FORCE_THRESHOLD = 5            # 5+ failed logins, same IP, within the window

# Category 2: successful login right after several failures
LOGIN_SUCCESS_AFTER_FAILURES_WINDOW_SECONDS = 300
LOGIN_SUCCESS_AFTER_FAILURES_THRESHOLD = 3   # 3+ prior failures, same IP, then a success

# Category 11: invalid-user probing (guessing usernames that don't exist)
INVALID_USER_WINDOW_SECONDS = 300
INVALID_USER_THRESHOLD = 5           # 5+ distinct invalid-user attempts, same IP, within window


# --------------------------------------------------------------------------
# Category 3: unusual-hours window (auth.log + access.log)
# Fixed baseline for a demo dataset — a real deployment would calibrate
# this to actual business hours instead of a hardcoded overnight window.
# --------------------------------------------------------------------------

UNUSUAL_HOUR_START = 0    # 12:00 AM
UNUSUAL_HOUR_END = 5      # 5:59 AM


# --------------------------------------------------------------------------
# Request-volume thresholds (access.log)
# --------------------------------------------------------------------------

# Category 8: abnormally high request rate from one IP
HIGH_REQUEST_RATE_WINDOW_SECONDS = 60
HIGH_REQUEST_RATE_THRESHOLD = 50     # 50+ requests, same IP, within the window

# Category 12: spike in 4xx (client error) responses from one IP —
# the fingerprint of directory/file brute-forcing tools
FOUR_XX_SPIKE_WINDOW_SECONDS = 60
FOUR_XX_SPIKE_THRESHOLD = 20         # 20+ 4xx responses, same IP, within the window


# --------------------------------------------------------------------------
# Category 4: SQL-injection patterns
# Compiled once here so rules.py never recompiles a pattern per log line.
# --------------------------------------------------------------------------

SQLI_PATTERNS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in [
    r"'\s*or\s*'?\d+'?\s*=\s*'?\d+",   # ' or 1=1
    r"union\s+select",
    r"drop\s+table",
    r"insert\s+into\s+\w+\s+values",
    r"select\s+.+\s+from\s+information_schema",
    r"sleep\(\s*\d+\s*\)",
    r"benchmark\s*\(",
    r"xp_cmdshell",
    r";\s*--",
    r"waitfor\s+delay",
]]


# --------------------------------------------------------------------------
# Category 5: XSS patterns
# --------------------------------------------------------------------------

XSS_PATTERNS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in [
    r"<script[\s>]",
    r"javascript:",
    r"on(error|load|click|mouseover|focus)\s*=",
    r"<iframe[\s>]",
    r"document\.cookie",
    r"<img[^>]+onerror",
    r"%3cscript",                       # URL-encoded <script
    r"alert\s*\(",
]]


# --------------------------------------------------------------------------
# Category 6: path traversal patterns
# --------------------------------------------------------------------------

PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"etc/passwd",
    r"boot\.ini",
    r"win\.ini",
]]


# --------------------------------------------------------------------------
# Category 7: sensitive / administrative paths
# Matched as a case-insensitive substring check against the request path
# in rules.py — plain strings, not regex, since these are fixed literals.
# --------------------------------------------------------------------------

SENSITIVE_PATHS: list[str] = [
    "/admin",
    "/.env",
    "/.git",
    "/.htpasswd",
    "/.ssh",
    "/.aws",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/config",
    "/backup",
    "/server-status",
    "/actuator",
]


# --------------------------------------------------------------------------
# Category 9: known scanning / attack-tool User-Agent substrings
# Matched case-insensitively against the full User-Agent header.
# --------------------------------------------------------------------------

SCANNER_USER_AGENTS: list[str] = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
    "wpscan",
    "acunetix",
    "nessus",
    "metasploit",
    "hydra",
    "w3af",
    "havij",
]