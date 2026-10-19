"""
sentinel/reporter.py
--------------------
Formats security alerts and delivers them to stdout and/or a file.
All I/O is isolated here so parser and detector stay pure.
"""

import os
from datetime import datetime

_NO_THREATS_MSG = "No threats detected."


def format_alert(alert: dict) -> str:
    """Return a human-readable one-line string for a single alert.

    Example output:
        [ALERT] 192.168.1.105 - 7 failed login attempts (threshold: 5)
    """
    return (
        f"[ALERT] {alert['ip']} - {alert['count']} failed login attempts "
        f"(threshold: {alert['threshold']})"
    )


def _build_report(alerts: list) -> str:
    """Build the full report string (header + alert lines)."""
    run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"=== Sentinel Security Report | {run_time} ===\n"

    if not alerts:
        return header + _NO_THREATS_MSG + "\n"

    lines = [header]
    for alert in alerts:
        lines.append(format_alert(alert))
    return "\n".join(lines) + "\n"


def print_alerts(alerts: list) -> None:
    """Print the security report to stdout."""
    print(_build_report(alerts), end="")


def write_alerts(alerts: list, path: str) -> None:
    """Write the security report to a file, creating it if needed.

    Args:
        alerts: List of alert dicts (from detector.py).
        path:   Destination file path.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_build_report(alerts))
