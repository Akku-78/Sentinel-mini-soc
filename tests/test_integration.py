"""
tests/test_integration.py
--------------------------
Lightweight end-to-end test for the full Sentinel pipeline:
    parse_file → count_failures → detect_threats → write_alerts

Uses a temporary log file to stay self-contained.
No mocking — exercises the real code path from disk to output file.
"""

import os
import tempfile
import unittest

from sentinel.parser import parse_file
from sentinel.detector import count_failures, detect_threats
from sentinel.reporter import write_alerts

# A minimal log that contains:
#   - 192.168.1.1  with 6 FAILED  → should be flagged (>= 5)
#   - 10.0.0.1     with 2 FAILED  → should NOT be flagged
#   - 10.0.0.2     with 1 SUCCESS → should NOT appear at all
SAMPLE_LOG = """\
2024-06-01 09:00:01 FAILED login from 192.168.1.1 user=admin
2024-06-01 09:00:02 FAILED login from 192.168.1.1 user=root
2024-06-01 09:00:03 FAILED login from 192.168.1.1 user=admin
2024-06-01 09:00:04 FAILED login from 192.168.1.1 user=guest
2024-06-01 09:00:05 FAILED login from 192.168.1.1 user=admin
2024-06-01 09:00:06 FAILED login from 192.168.1.1 user=root
2024-06-01 09:00:07 FAILED login from 10.0.0.1 user=admin
2024-06-01 09:00:08 FAILED login from 10.0.0.1 user=root
2024-06-01 09:00:09 SUCCESS login from 10.0.0.2 user=alice
not a valid log line
"""


class TestFullPipeline(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmp_dir, "auth.log")
        self.out_path = os.path.join(self.tmp_dir, "alerts.txt")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE_LOG)

    def test_pipeline_produces_one_alert(self):
        records = parse_file(self.log_path)
        failure_counts = count_failures(records)
        alerts = detect_threats(failure_counts, threshold=5)

        # Only 192.168.1.1 should be flagged
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "192.168.1.1")
        self.assertEqual(alerts[0]["count"], 6)

    def test_pipeline_output_file_contains_flagged_ip(self):
        records = parse_file(self.log_path)
        failure_counts = count_failures(records)
        alerts = detect_threats(failure_counts, threshold=5)
        write_alerts(alerts, self.out_path)

        with open(self.out_path, "r", encoding="utf-8") as fh:
            content = fh.read()

        self.assertIn("192.168.1.1", content)
        self.assertIn("[ALERT]", content)
        self.assertNotIn("10.0.0.1", content)

    def test_pipeline_malformed_lines_are_ignored(self):
        records = parse_file(self.log_path)
        # 9 valid lines + 1 malformed → 9 parsed records
        self.assertEqual(len(records), 9)


if __name__ == "__main__":
    unittest.main()
