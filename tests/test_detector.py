"""
tests/test_detector.py
----------------------
Unit tests for sentinel.detector.
"""

import unittest
from sentinel.detector import count_failures, detect_threats


class TestCountFailures(unittest.TestCase):

    def test_counts_failed_logins_per_ip(self):
        records = [
            {"status": "FAILED", "ip": "1.2.3.4", "username": "admin"},
            {"status": "FAILED", "ip": "1.2.3.4", "username": "root"},
            {"status": "SUCCESS", "ip": "1.2.3.4", "username": "alice"},
            {"status": "FAILED", "ip": "5.6.7.8", "username": "bob"},
        ]
        result = count_failures(records)
        self.assertEqual(result["1.2.3.4"], 2)
        self.assertEqual(result["5.6.7.8"], 1)

    def test_success_only_returns_empty(self):
        records = [
            {"status": "SUCCESS", "ip": "10.0.0.1", "username": "alice"},
        ]
        self.assertEqual(count_failures(records), {})

    def test_empty_input_returns_empty(self):
        self.assertEqual(count_failures([]), {})


class TestDetectThreats(unittest.TestCase):

    def test_ip_below_threshold_not_flagged(self):
        alerts = detect_threats({"1.2.3.4": 3}, threshold=5)
        self.assertEqual(alerts, [])

    def test_ip_at_threshold_is_flagged(self):
        alerts = detect_threats({"1.2.3.4": 5}, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "1.2.3.4")
        self.assertEqual(alerts[0]["count"], 5)
        self.assertEqual(alerts[0]["threshold"], 5)

    def test_ip_above_threshold_is_flagged(self):
        alerts = detect_threats({"1.2.3.4": 9}, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 9)

    def test_multiple_ips_only_offenders_flagged(self):
        counts = {"1.2.3.4": 7, "5.6.7.8": 2, "9.10.11.12": 5}
        alerts = detect_threats(counts, threshold=5)
        flagged_ips = {a["ip"] for a in alerts}
        self.assertIn("1.2.3.4", flagged_ips)
        self.assertIn("9.10.11.12", flagged_ips)
        self.assertNotIn("5.6.7.8", flagged_ips)

    def test_empty_input_returns_empty(self):
        self.assertEqual(detect_threats({}), [])


if __name__ == "__main__":
    unittest.main()
