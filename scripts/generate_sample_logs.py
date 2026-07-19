"""Synthetic sample-log generator for the Log File Analyzer.

Builds a realistic-looking day of Linux auth.log and Apache/Nginx
access.log traffic: normal background activity, plus one deliberately
injected event (or burst) per baseline detection category. Every
injection is tracked as it's written, and the exact rule_id, log file,
and line numbers are recorded in manifest.json -- the answer key Phase 4
checks the analyzer's real output against, line by line, instead of
eyeballing whether "it looks about right."

Usage:
    python scripts/generate_sample_logs.py

Writes three files to sample_logs/ (created if it doesn't exist yet,
relative to the project root regardless of the current working
directory this script is run from):
    sample_logs/auth.log
    sample_logs/access.log
    sample_logs/manifest.json
"""

import json
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

SEED = 1337                 # fixed seed -- reruns produce identical output
LOG_DATE = datetime(2026, 7, 14)
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "sample_logs"

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# RFC 5737 documentation ranges, kept visually distinct on purpose:
# benign traffic reads as 203.0.113.x, injected attacks as 198.51.100.x.
BENIGN_IPS = [f"203.0.113.{n}" for n in (10, 11, 12, 14, 18, 21, 25, 30)]
BENIGN_USERNAMES = ["alice", "bob", "carol", "dave", "erin", "frank"]
BENIGN_PATHS = ["/", "/about", "/products", "/contact", "/blog/2026-roadmap",
                "/pricing", "/login", "/dashboard", "/api/status", "/images/logo.png"]
BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]


@dataclass
class ManifestEntry:
    """One injected suspicious event (or burst), and where to find it."""

    rule_id: str
    description: str
    log_file: str
    line_numbers: list[int] = field(default_factory=list)


manifest: list[ManifestEntry] = []
auth_lines: list[str] = []
access_lines: list[str] = []


# --------------------------------------------------------------------------
# Line-building helpers
# --------------------------------------------------------------------------

def add_auth(line: str) -> int:
    """Append one auth.log line, return its 1-indexed line number --
    matching exactly what parsers.py's enumerate(handle, start=1) will
    assign it when the file is read back.
    """
    auth_lines.append(line)
    return len(auth_lines)


def add_access(line: str) -> int:
    access_lines.append(line)
    return len(access_lines)


def format_auth_line(moment: datetime, process: str, pid: int, message: str, host: str = "webserver01") -> str:
    """Classic syslog format: "Mon DD HH:MM:SS host process[pid]: message".

    Day is manually space-padded to two characters (" 4" not "04") to
    match real syslog's convention -- Python's strftime has no portable
    equivalent across platforms, so it's built by hand instead of relying
    on a format code that behaves differently on Windows.
    """
    day_str = f"{moment.day:2d}"
    return f"{_MONTHS[moment.month - 1]} {day_str} {moment.strftime('%H:%M:%S')} {host} {process}[{pid}]: {message}"


def format_access_line(
    moment: datetime, ip: str, method: str, path: str, status: int,
    size: int, user_agent: str, referrer: str = "-",
) -> str:
    """Apache/Nginx combined log format."""
    ts = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"'


def record(rule_id: str, description: str, log_file: str, line_numbers: list[int]) -> None:
    manifest.append(ManifestEntry(rule_id, description, log_file, line_numbers))


# --------------------------------------------------------------------------
# Benign background traffic
# --------------------------------------------------------------------------

def add_benign_auth_block(start: datetime, count: int) -> None:
    """A handful of normal logins: session open, accepted password,
    occasionally one isolated failed attempt (a typo, not an attack --
    never more than one or two per IP, always well under every
    threshold in config.py) and a routine (non-failing) sudo command.
    """
    moment = start
    for _ in range(count):
        ip = random.choice(BENIGN_IPS)
        user = random.choice(BENIGN_USERNAMES)
        pid = random.randint(10000, 32000)
        add_auth(format_auth_line(moment, "sshd", pid, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"))
        moment += timedelta(seconds=random.randint(2, 5))
        add_auth(format_auth_line(moment, "sshd", pid, f"Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2"))
        moment += timedelta(seconds=random.randint(30, 90))

        if random.random() < 0.15:
            # One isolated mistyped password -- realistic, and safely
            # below every failed-login threshold on its own.
            add_auth(format_auth_line(moment, "sshd", pid + 1, f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2"))
            moment += timedelta(seconds=random.randint(5, 15))

        if random.random() < 0.2:
            # A routine sudo command that succeeds -- parses to
            # AuthEventType.OTHER, since only sudo *failures* match
            # _SUDO_FAILURE_RE. Confirms the parser handles ordinary
            # sudo usage without misclassifying it as an alert.
            add_auth(format_auth_line(moment, "sudo", pid + 2, f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/systemctl status nginx"))
            moment += timedelta(seconds=random.randint(5, 15))

        add_auth(format_auth_line(moment, "sshd", pid, f"pam_unix(sshd:session): session closed for user {user}"))
        moment += timedelta(seconds=random.randint(60, 300))


def add_benign_access_block(start: datetime, count: int) -> None:
    """Normal page views: mostly 200s, an occasional isolated 404 for a
    missing asset -- never more than one or two per IP, always well
    under the 4xx-spike threshold.
    """
    moment = start
    for _ in range(count):
        ip = random.choice(BENIGN_IPS)
        ua = random.choice(BENIGN_USER_AGENTS)
        path = random.choice(BENIGN_PATHS)
        status = 404 if random.random() < 0.08 else 200
        size = 0 if status == 404 else random.randint(300, 15000)
        add_access(format_access_line(moment, ip, "GET", path, status, size, ua))
        moment += timedelta(seconds=random.randint(3, 20))


# --------------------------------------------------------------------------
# Injected suspicious events -- one function per baseline category
# --------------------------------------------------------------------------

def inject_unusual_hour_auth(moment: datetime) -> None:
    ip = "198.51.100.22"
    line_no = add_auth(format_auth_line(moment, "sshd", 8801, f"Accepted password for night_owl_dev from {ip} port 51500 ssh2"))
    record("unusual_hour_access", f"Successful login for 'night_owl_dev' from {ip} at {moment.strftime('%H:%M')}", "auth.log", [line_no])


def inject_unusual_hour_access(moment: datetime) -> None:
    ip = "198.51.100.44"
    line_no = add_access(format_access_line(moment, ip, "GET", "/dashboard", 200, 4200, BENIGN_USER_AGENTS[0]))
    record("unusual_hour_access", f"Request to /dashboard from {ip} at {moment.strftime('%H:%M')}", "access.log", [line_no])


def inject_invalid_user_probe(start: datetime) -> None:
    ip = "198.51.100.33"
    fake_usernames = ["test", "oracle", "postgres", "admin1", "ftpuser", "guest"]
    line_numbers = []
    moment = start
    for i, name in enumerate(fake_usernames):
        line_numbers.append(add_auth(format_auth_line(moment, "sshd", 9100 + i, f"Failed password for invalid user {name} from {ip} port {43000 + i} ssh2")))
        moment += timedelta(seconds=random.randint(6, 12))
    record("invalid_user_probe", f"{len(fake_usernames)} invalid-user login attempts from {ip}", "auth.log", line_numbers)


def inject_privilege_escalation_sudo(moment: datetime) -> None:
    line_no = add_auth(format_auth_line(
        moment, "sudo", 9200,
        "pam_unix(sudo:auth): authentication failure; logname=contractor_bob uid=1000 euid=0 tty=/dev/pts/3 ruser= rhost=  user=contractor_bob",
    ))
    record("privilege_escalation", "sudo authentication failure for user 'contractor_bob'", "auth.log", [line_no])


def inject_privilege_escalation_su(moment: datetime) -> None:
    line_no = add_auth(format_auth_line(moment, "su", 9201, "FAILED su for root by eve"))
    record("privilege_escalation", "Failed su attempt by 'eve' targeting root", "auth.log", [line_no])


def inject_brute_force(start: datetime) -> None:
    ip = "198.51.100.7"
    line_numbers = []
    moment = start
    for i in range(7):
        line_numbers.append(add_auth(format_auth_line(moment, "sshd", 9300 + i, f"Failed password for root from {ip} port {44000 + i} ssh2")))
        moment += timedelta(seconds=random.randint(6, 10))
    record("brute_force_login", f"{len(line_numbers)} failed logins for 'root' from {ip}", "auth.log", line_numbers)


def inject_login_success_after_failures(start: datetime) -> None:
    ip = "198.51.100.15"
    line_numbers = []
    moment = start
    for i in range(3):
        line_numbers.append(add_auth(format_auth_line(moment, "sshd", 9400 + i, f"Failed password for alice from {ip} port {45000 + i} ssh2")))
        moment += timedelta(seconds=random.randint(5, 9))
    line_numbers.append(add_auth(format_auth_line(moment, "sshd", 9404, f"Accepted password for alice from {ip} port 45010 ssh2")))
    record("login_success_after_failures", f"Successful login for 'alice' from {ip} after 3 failed attempts", "auth.log", line_numbers)


def inject_sql_injection(moment: datetime) -> None:
    ip = "198.51.100.55"
    path = "/product?id=1 UNION SELECT username,password FROM users--"
    line_no = add_access(format_access_line(moment, ip, "GET", path, 200, 512, BENIGN_USER_AGENTS[0]))
    record("sql_injection_attempt", f"SQL injection pattern from {ip}: {path}", "access.log", [line_no])


def inject_xss(moment: datetime) -> None:
    ip = "198.51.100.66"
    path = "/search?q=<script>document.cookie</script>"
    line_no = add_access(format_access_line(moment, ip, "GET", path, 200, 300, BENIGN_USER_AGENTS[1]))
    record("xss_attempt", f"XSS pattern from {ip}: {path}", "access.log", [line_no])


def inject_path_traversal(moment: datetime) -> None:
    ip = "198.51.100.77"
    path = "/download?file=../../../../etc/passwd"
    line_no = add_access(format_access_line(moment, ip, "GET", path, 403, 0, BENIGN_USER_AGENTS[2]))
    record("path_traversal_attempt", f"Path traversal pattern from {ip}: {path}", "access.log", [line_no])


def inject_sensitive_path(moment: datetime) -> None:
    ip = "198.51.100.88"
    line_no = add_access(format_access_line(moment, ip, "GET", "/.env", 404, 0, BENIGN_USER_AGENTS[0]))
    record("sensitive_path_access", f"Request to sensitive path /.env from {ip}", "access.log", [line_no])


def inject_scanner_user_agent(moment: datetime) -> None:
    ip = "198.51.100.99"
    line_no = add_access(format_access_line(moment, ip, "GET", "/", 200, 8000, "Mozilla/5.0 (compatible; Nikto/2.5.0)"))
    record("scanner_user_agent", f"Known scanning-tool User-Agent from {ip}", "access.log", [line_no])


def inject_high_request_rate(start: datetime) -> None:
    ip = "198.51.100.111"
    line_numbers = []
    moment = start
    for i in range(55):
        line_numbers.append(add_access(format_access_line(moment, ip, "GET", f"/page{i}", 200, 1200, BENIGN_USER_AGENTS[0])))
        moment += timedelta(seconds=1)
    record("high_request_rate", f"55 requests from {ip} within 60s", "access.log", line_numbers)


def inject_http_error_spike(start: datetime) -> None:
    ip = "198.51.100.122"
    line_numbers = []
    moment = start
    for i in range(22):
        line_numbers.append(add_access(format_access_line(moment, ip, "GET", f"/nonexistent{i}", 404, 0, "curl/7.81.0")))
        moment += timedelta(seconds=2)
    record("http_error_spike", f"22 4xx responses from {ip} within 60s", "access.log", line_numbers)


# --------------------------------------------------------------------------
# Assemble a full day, chronologically
# --------------------------------------------------------------------------

def build_logs() -> None:
    random.seed(SEED)

    inject_unusual_hour_auth(LOG_DATE.replace(hour=2, minute=17))
    inject_unusual_hour_access(LOG_DATE.replace(hour=3, minute=42))

    add_benign_auth_block(LOG_DATE.replace(hour=8, minute=40), count=4)
    add_benign_access_block(LOG_DATE.replace(hour=9, minute=0), count=8)

    inject_invalid_user_probe(LOG_DATE.replace(hour=9, minute=15))
    inject_privilege_escalation_sudo(LOG_DATE.replace(hour=9, minute=30))

    add_benign_auth_block(LOG_DATE.replace(hour=9, minute=40), count=3)

    inject_brute_force(LOG_DATE.replace(hour=9, minute=50))
    inject_login_success_after_failures(LOG_DATE.replace(hour=10, minute=5))
    inject_privilege_escalation_su(LOG_DATE.replace(hour=10, minute=30))

    add_benign_access_block(LOG_DATE.replace(hour=10, minute=45), count=6)

    inject_sql_injection(LOG_DATE.replace(hour=11, minute=0))
    inject_xss(LOG_DATE.replace(hour=11, minute=5))
    inject_path_traversal(LOG_DATE.replace(hour=11, minute=10))
    inject_sensitive_path(LOG_DATE.replace(hour=11, minute=15))
    inject_scanner_user_agent(LOG_DATE.replace(hour=11, minute=20))
    inject_high_request_rate(LOG_DATE.replace(hour=11, minute=30))
    inject_http_error_spike(LOG_DATE.replace(hour=11, minute=45))

    add_benign_auth_block(LOG_DATE.replace(hour=13, minute=0), count=5)
    add_benign_access_block(LOG_DATE.replace(hour=13, minute=30), count=12)
    add_benign_auth_block(LOG_DATE.replace(hour=17, minute=0), count=3)
    add_benign_access_block(LOG_DATE.replace(hour=17, minute=30), count=6)


def write_outputs() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    auth_path = OUTPUT_DIR / "auth.log"
    access_path = OUTPUT_DIR / "access.log"
    manifest_path = OUTPUT_DIR / "manifest.json"

    auth_path.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    access_path.write_text("\n".join(access_lines) + "\n", encoding="utf-8")

    manifest_payload = {
        "generated_at": datetime.now().isoformat(),
        "seed": SEED,
        "auth_log": "auth.log",
        "access_log": "access.log",
        "auth_log_total_lines": len(auth_lines),
        "access_log_total_lines": len(access_lines),
        "injected_events": [asdict(entry) for entry in manifest],
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

    print(f"Wrote {len(auth_lines)} auth.log lines to {auth_path}")
    print(f"Wrote {len(access_lines)} access.log lines to {access_path}")
    print(f"Wrote {len(manifest)} manifest entries to {manifest_path}")
    print()
    rule_ids = sorted({entry.rule_id for entry in manifest})
    print(f"Injected categories covered ({len(rule_ids)} of 12): {', '.join(rule_ids)}")


def main() -> None:
    build_logs()
    write_outputs()


if __name__ == "__main__":
    main()