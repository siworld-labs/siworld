"""Reject mislabeled proofs and distinguish RSS from physical footprint."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("composition_measurement", ROOT / "scripts/measure-composition.py")
measurement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurement)


class CompositionMeasurementTests(unittest.TestCase):
    def test_suite_topology_and_verified_status_are_bound(self):
        report = {"schema": 1, "verified": True, "slots": 16, "topology": "fanin8", "jobs": 2,
                  "proof_and_verify_ns": 100,
                  "parameters": {"suite": "D4-W16", "log_blowup": 2, "queries": 42, "grinding": 16}}
        self.assertTrue(measurement.valid_report(report, "fanin8", 2, 42))
        for key, value in (("verified", False), ("slots", 32), ("jobs", 1),
                           ("topology", "binary"), ("proof_and_verify_ns", True)):
            with self.subTest(key=key):
                self.assertFalse(measurement.valid_report({**report, key: value}, "fanin8", 2, 42))
        self.assertFalse(measurement.valid_report(report, "fanin8", 2, 92))

    def test_footprint_is_not_substituted_by_rss(self):
        output = "123 maximum resident set size\n456 peak memory footprint\n"
        self.assertEqual(measurement.os_peak(output, "maximum resident set size"), 123)
        self.assertEqual(measurement.os_peak(output, "peak memory footprint"), 456)
        self.assertIsNone(measurement.os_peak("123 maximum resident set size\n", "peak memory footprint"))


if __name__ == "__main__":
    unittest.main()
