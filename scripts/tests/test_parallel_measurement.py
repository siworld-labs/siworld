"""The aggregation gate must fail closed when OS memory data is unavailable."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("parallel_measurement", ROOT / "scripts/measure-proof-parallel.py")
measurement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurement)


class AggregationMeasurementTests(unittest.TestCase):
    def run_sample(self, stderr, returncode=0, verified=True):
        report = {
            "schema": 2, "verified": verified, "container_size": 32,
            "parallel": 2, "aggregation_ms": 100_000,
            "parameters": {"suite": "classical-D4-W16", "log_blowup": 2,
                           "queries": 42, "grinding": 16},
        }
        process = SimpleNamespace(returncode=returncode,
                                  communicate=lambda **kwargs: (json.dumps(report), stderr))
        args = SimpleNamespace(binary=Path("measurement-binary"), slots=32, root=ROOT,
                               rayon_threads=2, timeout_secs=10)
        with patch.object(measurement.subprocess, "Popen", return_value=process):
            return measurement.run_once(2, args)

    def test_successful_proof_without_positive_rss_fails_the_gate(self):
        for stderr in ("", "0 maximum resident set size\n"):
            with self.subTest(stderr=stderr):
                self.assertEqual(self.run_sample(stderr)["status"], "failed")

    def test_verified_proof_and_os_measurement_are_both_required(self):
        stderr = "1048576 maximum resident set size\n2097152 peak memory footprint\n"
        self.assertEqual(self.run_sample(stderr)["status"], "passed")
        self.assertEqual(self.run_sample(stderr, returncode=1)["status"], "failed")
        self.assertEqual(self.run_sample(stderr, verified=False)["status"], "failed")

    def test_physical_footprint_over_budget_is_not_hidden_by_low_rss(self):
        sample = self.run_sample("1048576 maximum resident set size\n4294967296 peak memory footprint\n")
        self.assertEqual(sample["accounted_peak_bytes"], 4294967296)
        self.assertEqual(measurement.summarize([sample], 3 << 30)["rss_budget_status"], "exceeded")


if __name__ == "__main__":
    unittest.main()
