"""
tests/test_parser.py
--------------------
Unit tests for sentinel.parser.
"""

import unittest
from datetime import datetime
from sentinel.parser import parse_line, parse_file
import tempfile
import os


class TestParseLine(unittest.TestCase):

    def test_valid_failed_line(self):
        line = "2024-06-01 08:00:15 FAILED login from 192.168.1.105 user=admin"
        record = parse_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "FAILED")
        self.assertEqual(record["ip"], "192.168.1.105")
        self.assertEqual(record["username"], "admin")
        self.assertIsInstance(record["timestamp"], datetime)

    def test_valid_success_line(self):
        line = "2024-06-01 09:15:00 SUCCESS login from 10.0.0.1 user=alice"
        record = parse_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "SUCCESS")
        self.assertEqual(record["ip"], "10.0.0.1")
        self.assertEqual(record["username"], "alice")

    def test_malformed_line_returns_none(self):
        line = "this line is malformed and should be skipped silently"
        self.assertIsNone(parse_line(line))

    def test_empty_line_returns_none(self):
        self.assertIsNone(parse_line(""))

    def test_partial_line_returns_none(self):
        line = "2024-06-01 08:00:15 FAILED login from"
        self.assertIsNone(parse_line(line))


class TestParseFile(unittest.TestCase):

    def test_skips_malformed_lines(self):
        content = (
            "2024-06-01 08:00:01 SUCCESS login from 10.0.0.1 user=alice\n"
            "this is garbage\n"
            "2024-06-01 08:00:15 FAILED login from 192.168.1.105 user=admin\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            records = parse_file(tmp_path)
            self.assertEqual(len(records), 2)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
