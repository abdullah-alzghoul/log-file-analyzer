"""Command-line interface for the Log File Analyzer.

Wraps analyzer.py and report.py behind a standard argparse CLI: parse
one or both log files, print a console summary, and optionally export
JSON and/or CSV. Nothing in here parses logs or detects anything --
this file's only job is turning command-line arguments into calls
against analyzer.py and report.py, and turning their results (or
failures) into clean console output and a process exit code.
"""

import argparse
import sys

from log_analyzer.analyzer import run_analysis
from log_analyzer.report import export_csv, export_json, print_console_summary


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser as its own function, not inline in
    main() -- this is what lets tests import and inspect the parser,
    or call main() with an explicit argv list, without needing to
    invoke the process via subprocess.
    """
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Parse auth.log and/or access.log files and flag suspicious activity.",
        epilog="Example: python run.py --auth-log samples/auth.log --access-log samples/access.log --json reports/scan.json",
    )
    parser.add_argument("--auth-log", metavar="PATH", help="Path to a Linux-style auth.log file")
    parser.add_argument("--access-log", metavar="PATH", help="Path to an Apache/Nginx combined-format access.log file")
    parser.add_argument("--year", type=int, metavar="YYYY", help="Year to assume for auth.log timestamps (default: current year)")
    parser.add_argument("--json", metavar="PATH", dest="json_path", help="Write a JSON report to this path")
    parser.add_argument("--csv", metavar="PATH", dest="csv_path", help="Write a CSV report to this path")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0 = success, 1 =
    error) rather than calling sys.exit() directly, so tests can call
    main([...]) and check the return value without ending the test
    process.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.auth_log and not args.access_log:
        parser.error("at least one of --auth-log or --access-log is required")

    try:
        result = run_analysis(
            auth_log_path=args.auth_log,
            access_log_path=args.access_log,
            year=args.year,
        )
    except OSError as exc:
        # Covers FileNotFoundError, PermissionError, etc. -- whatever
        # went wrong reading the file, str(exc) already carries a
        # specific, useful OS-level message (errno + filename).
        print(f"Error reading log file: {exc}", file=sys.stderr)
        return 1

    print_console_summary(result)

    if args.json_path:
        written = export_json(result, args.json_path)
        print(f"JSON report written to {written}")
    if args.csv_path:
        written = export_csv(result, args.csv_path)
        print(f"CSV report written to {written}")

    return 0


if __name__ == "__main__":
    sys.exit(main())