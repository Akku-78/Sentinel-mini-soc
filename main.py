"""
main.py
-------
Entry point for Sentinel. Wires together parser → detector → reporter.

Usage:
    python main.py
    python main.py --log data/auth.log --threshold 5 --output output/alerts.txt
"""

import argparse
import os
import sys

from sentinel.parser import parse_file
from sentinel.detector import count_failures, detect_threats
from sentinel.reporter import print_alerts, write_alerts

DEFAULT_LOG = os.path.join("data", "auth.log")
DEFAULT_OUTPUT = os.path.join("output", "alerts.txt")
DEFAULT_THRESHOLD = 5


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel — Mini SOC Log Analyzer"
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG,
        help=f"Path to the auth log file (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Failed attempts to trigger an alert (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Path for the alerts output file (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    # --- Parse ---
    try:
        records = parse_file(args.log)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    # --- Detect ---
    failure_counts = count_failures(records)
    alerts = detect_threats(failure_counts, threshold=args.threshold)

    # --- Report ---
    print_alerts(alerts)
    write_alerts(alerts, args.output)
    print(f"\nAlerts written to: {args.output}")


if __name__ == "__main__":
    main()
