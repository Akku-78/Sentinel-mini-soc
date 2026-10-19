"""
sentinel/parser.py
------------------
Converts raw auth.log lines into structured Python dicts.
All other modules work with these dicts — never raw strings.
"""

import re
from datetime import datetime

# Matches lines like:
# 2024-06-01 08:00:15 FAILED login from 192.168.1.105 user=admin
_LINE_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<status>FAILED|SUCCESS)\s+"
    r"login from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"user=(?P<username>\S+)$"
)


def parse_line(line: str) -> dict | None:
    """Parse a single log line.

    Returns a dict with keys: timestamp, status, ip, username.
    Returns None if the line does not match the expected format.
    """
    match = _LINE_PATTERN.match(line.strip())
    if match is None:
        return None

    raw_ts = f"{match.group('date')} {match.group('time')}"
    return {
        "timestamp": datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S"),
        "status": match.group("status"),
        "ip": match.group("ip"),
        "username": match.group("username"),
    }


def parse_file(path: str) -> list:
    """Read a log file and return all successfully parsed records.

    Malformed lines are silently skipped.
    """
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            record = parse_line(line)
            if record is not None:
                records.append(record)
    return records
