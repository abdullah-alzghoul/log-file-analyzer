# Log File Analyzer

A command-line tool that parses Linux authentication logs and Apache/Nginx access logs, flags suspicious or malicious activity across 12 detection categories, and produces severity-ranked, human-readable alerts plus exportable JSON/CSV reports.

Built as a portfolio project to demonstrate practical Python and security-analysis skills — real log formats, a synthetic sample-data generator so every detection rule can be verified end-to-end, and 75 passing unit tests.

## Features

- Parses two log formats: Linux-style `auth.log` (classic syslog) and Apache/Nginx combined-format `access.log`
- 12 independent detection rules, each carrying a severity so findings can be triaged:

| # | Category | Severity |
|---|----------|----------|
| 1 | Brute-Force Login Attempt | High |
| 2 | Successful Login After Repeated Failures | High |
| 3 | Access During Unusual Hours | Low |
| 4 | SQL Injection Pattern Detected | High |
| 5 | Cross-Site Scripting (XSS) Pattern Detected | Medium |
| 6 | Path Traversal Attempt | High |
| 7 | Request to Sensitive or Administrative Path | Medium |
| 8 | Abnormally High Request Rate | Medium |
| 9 | Known Scanning/Attack-Tool User-Agent | Medium |
| 10 | Privilege Escalation Indicator | High |
| 11 | Invalid-User Login Probing | Low |
| 12 | Spike in HTTP Error Responses | Medium |

- Console output grouped by severity, plus optional JSON and CSV export
- Malformed lines, empty files, and encoding issues are skipped and warned about — never crash the run
- Ships with `scripts/generate_sample_logs.py`, which builds a realistic day of synthetic logs with every category deliberately triggered at least once — no live server or real data required to see every rule fire
- 75 unit tests across parsing, detection rules, and orchestration

## Project structure

```
log-file-analyzer/
├── log_analyzer/               # Core package
│   ├── __init__.py
│   ├── models.py                # Severity enum, LogEvent/Alert dataclasses
│   ├── config.py                 # Thresholds, time windows, patterns, rule metadata
│   ├── parsers.py                # Raw log lines -> LogEvent objects
│   ├── rules.py                  # One detection function per category -> Alert objects
│   ├── analyzer.py               # Orchestrator: parse + run every rule + sort
│   ├── report.py                 # Console summary + JSON/CSV export
│   └── cli.py                    # argparse-based command-line interface
├── scripts/
│   └── generate_sample_logs.py   # Synthetic auth.log/access.log + manifest.json
├── tests/
│   ├── __init__.py
│   ├── test_parsers.py
│   ├── test_rules.py
│   └── test_analyzer.py
├── sample_logs/                  # generated -- not tracked in git
│   ├── auth.log
│   ├── access.log
│   └── manifest.json
├── run.py                        # Entry point: python run.py [options]
├── requirements.txt               # No third-party dependencies (see file for why)
├── README.md
└── .gitignore
```

## Requirements

- Python 3.10 or later (built and tested against Python 3.14.4)
- No third-party packages — standard library only (`requirements.txt` explains this; `pip install -r requirements.txt` is safe to run and installs nothing)

## Setup

```powershell
git clone https://github.com/abdullah-alzghoul/log-file-analyzer.git
cd log-file-analyzer
```

That's the entire setup — there's nothing to install.

## Usage

### 1. Generate sample data

No live server or real logs required. Writes `sample_logs/auth.log`, `sample_logs/access.log`, and `sample_logs/manifest.json` (the answer key listing exactly which lines are deliberately suspicious):

```powershell
python scripts\generate_sample_logs.py
```

### 2. Run the analyzer

```powershell
python run.py --auth-log sample_logs\auth.log --access-log sample_logs\access.log --year 2026
```

### Command-line options

| Flag | Required | Description |
|---|---|---|
| `--auth-log PATH` | One of `--auth-log` / `--access-log` | Path to a Linux-style `auth.log` file |
| `--access-log PATH` | One of `--auth-log` / `--access-log` | Path to an Apache/Nginx combined-format `access.log` file |
| `--year YYYY` | No | Year to assume for `auth.log` timestamps (classic syslog carries no year); defaults to the current year |
| `--json PATH` | No | Write a JSON report to this path |
| `--csv PATH` | No | Write a CSV report to this path |

Either log type can be supplied on its own — rules that need the missing type just produce no alerts from that side. Exporting both formats at once:

```powershell
python run.py --auth-log sample_logs\auth.log --access-log sample_logs\access.log --year 2026 --json reports\scan.json --csv reports\scan.csv
```

(`reports\` is created automatically if it doesn't exist yet.)

## Sample output

Running against the generated sample data produces 14 alerts — one representative alert per severity tier shown below:

```
======================================================================
LOG FILE ANALYZER -- SCAN SUMMARY
======================================================================
Auth log:   sample_logs\auth.log (70 events parsed)
Access log: sample_logs\access.log (115 events parsed)
Total alerts: 14

--- High (6) ---
[2026-07-14 09:30:00] Privilege Escalation Indicator | user=contractor_bob
    sudo authentication failure for user 'contractor_bob' on webserver01
...

--- Medium (5) ---
[2026-07-14 11:05:00] Cross-Site Scripting (XSS) Pattern Detected | ip=198.51.100.66
    XSS pattern matched in request from 198.51.100.66: /search?q=<script>document.cookie</script>
...

--- Low (3) ---
[2026-07-14 02:17:00] Access During Unusual Hours | ip=198.51.100.22 | user=night_owl_dev
    Successful login for 'night_owl_dev' from 198.51.100.22 at 02:17 (outside normal hours)
...
```

## Running the tests

```powershell
python -m unittest discover -s tests -v
```

Expected result:

```
----------------------------------------------------------------------
Ran 75 tests in 0.158s

OK
```

## How it fits together

```
parsers.py  -->  rules.py  -->  analyzer.py  -->  report.py / cli.py
(raw lines       (event lists    (orchestrates     (renders results:
 -> LogEvent      -> Alert        every rule,        console, JSON,
 objects)         objects)        merges + sorts)    CSV)
```

Each layer only knows about the one below it — `rules.py` has no idea what a raw log line looks like, and `cli.py` has no idea how any individual rule works. That separation is what let every file in this project be built and tested independently, one at a time, before anything was wired together.