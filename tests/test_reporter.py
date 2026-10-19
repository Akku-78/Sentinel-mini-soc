"""
tests/test_reporter.py
----------------------
Unit tests for sentinel.reporter.
"""

import os
import tempfile
import unittest
from sentinel.reporter import format_alert, write_alerts, print_alerts
from io import StringIO
import sys


class TestFormatAlert(unittest.TestCase):

    def test_format_contains_ip(self):
        alert = {"ip": "1.2.3.4", "count": 7, "threshold": 5}
        result = format_alert(alert)
        self.assertIn("1.2.3.4", result)

    def test_format_contains_count(self):
        alert = {"ip": "1.2.3.4", "count": 7, "threshold": 5}
        result = format_alert(alert)
        self.assertIn("7", result)

    def test_format_contains_alert_tag(self):
        alert = {"ip": "1.2.3.4", "count": 7, "threshold": 5}
        result = format_alert(alert)
        self.assertIn("[ALERT]", result)


class TestWriteAlerts(unittest.TestCase):

    def test_writes_alert_to_file(self):
        alerts = [{"ip": "1.2.3.4", "count": 7, "threshold": 5}]
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = os.path.join(tmp_dir, "alerts.txt")
            write_alerts(alerts, out_path)
            with open(out_path, "r", encoding="utf-8") as fh:
                content = fh.read()
        self.assertIn("1.2.3.4", content)
        self.assertIn("[ALERT]", content)

    def test_no_threats_message_when_empty(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = os.path.join(tmp_dir, "alerts.txt")
            write_alerts([], out_path)
            with open(out_path, "r", encoding="utf-8") as fh:
                content = fh.read()
        self.assertIn("No threats detected", content)

    def test_creates_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = os.path.join(tmp_dir, "subdir", "alerts.txt")
            write_alerts([], out_path)
            self.assertTrue(os.path.exists(out_path))


class TestPrintAlerts(unittest.TestCase):

    def test_prints_no_threats_when_empty(self):
        captured = StringIO()
        sys.stdout = captured
        try:
            print_alerts([])
        finally:
            sys.stdout = sys.__stdout__
        self.assertIn("No threats detected", captured.getvalue())

    def test_prints_alert_line_when_threats_found(self):
        captured = StringIO()
        sys.stdout = captured
        try:
            print_alerts([{"ip": "9.8.7.6", "count": 6, "threshold": 5}])
        finally:
            sys.stdout = sys.__stdout__
        self.assertIn("9.8.7.6", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
