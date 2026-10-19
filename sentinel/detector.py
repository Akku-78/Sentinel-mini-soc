"""
sentinel/detector.py
--------------------
Core detection logic: counts failed logins per IP and flags
any IP that meets or exceeds a configurable threshold.
"""

from collections import Counter


def count_failures(records: list) -> dict:
    """Count failed login attempts per IP address.

    Args:
        records: List of parsed log record dicts (from parser.py).

    Returns:
        A dict mapping ip -> number of failed attempts.
        IPs with zero failures are not included.
    """
    failed_ips = [r["ip"] for r in records if r["status"] == "FAILED"]
    return dict(Counter(failed_ips))


def detect_threats(failure_counts: dict, threshold: int = 5) -> list:
    """Identify IPs that have reached or exceeded the failure threshold.

    Args:
        failure_counts: Dict of ip -> failed attempt count.
        threshold:      Minimum failures needed to trigger an alert.

    Returns:
        A list of alert dicts, each with keys: ip, count, threshold.
    """
    alerts = []
    for ip, count in failure_counts.items():
        if count >= threshold:
            alerts.append({"ip": ip, "count": count, "threshold": threshold})
    return alerts
