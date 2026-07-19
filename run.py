#!/usr/bin/env python3
"""Entry point for the Log File Analyzer.

Thin wrapper so the tool can be run as `python run.py [args]` from the
project root, instead of `python -m log_analyzer.cli [args]`. All the
actual argument parsing and orchestration logic lives in
log_analyzer/cli.py -- this file's only job is to call it and exit with
its return code.
"""

import sys

from log_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())