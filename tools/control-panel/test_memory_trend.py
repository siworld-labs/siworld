import unittest
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

from memory_trend import MEMORY_BUDGETS, summarize


class MemoryTrendTests(unittest.TestCase):
    def test_integer_trend_and_unbounded_categories_are_explicit(self):
        value = summarize([
            {"at": 100, "vm_available_bytes": 900, "nodes": [
                {"id": "node-a", "memory_charged_bytes": 100, "canonical_metadata_bytes": 10}
            ]},
            {"at": 460, "vm_available_bytes": 800, "nodes": [
                {"id": "node-a", "memory_charged_bytes": 460, "canonical_metadata_bytes": 40}
            ]},
        ])
        charged = value["nodes"]["node-a"]["trends"]["memory_charged_bytes"]
        self.assertEqual(charged["slope_bytes_per_hour"], 3600)
        self.assertEqual(charged["budget_status"], "within")
        bounded = value["nodes"]["node-a"]["trends"]["canonical_metadata_bytes"]
        self.assertEqual(bounded["budget_status"], "within")
        self.assertEqual(bounded["bound_kind"], "measurement_ceiling")
        self.assertEqual(value["nodes"]["node-a"]["acceptance_status"], "unmeasured")
        self.assertIn("canonical_metadata_bytes", value["unbounded_categories"])
        self.assertEqual(value["vm_available_bytes"]["delta_bytes"], -100)

    def test_invalid_or_unordered_samples_do_not_create_a_false_slope(self):
        value = summarize([
            {"at": 10, "nodes": [{"id": "node-a", "memory_charged_bytes": 100}]},
            {"at": 10, "nodes": [{"id": "node-a", "memory_charged_bytes": 200}]},
            {"at": -1, "nodes": [{"id": "node-a", "memory_charged_bytes": 300}]},
        ])
        self.assertEqual(
            value["nodes"]["node-a"]["trends"]["memory_charged_bytes"]["status"],
            "non_monotonic_clock",
        )

    def test_bounded_category_reports_a_hard_budget_violation(self):
        value = summarize([
            {"at": 1, "nodes": [{"id": "node-a", "mempool_bytes": 64 << 20}]},
            {"at": 2, "nodes": [{"id": "node-a", "mempool_bytes": (64 << 20) + 1}]},
        ])
        trend = value["nodes"]["node-a"]["trends"]["mempool_bytes"]
        self.assertEqual(trend["budget_status"], "exceeded")
        self.assertEqual(value["nodes"]["node-a"]["hard_budget_violations"], ["mempool_bytes"])

    def test_missing_latest_measurement_never_reuses_an_earlier_pass(self):
        first = {"id": "node-a", "memory_charged_bytes": 1024, "memory_limit_bytes": 3 << 30,
                 **{field: 0 for field in MEMORY_BUDGETS}}
        self.assertEqual(summarize([{"at": 1, "nodes": [first]}])["nodes"]["node-a"]["acceptance_status"],
                         "sample_within_ceilings")
        value = summarize([{"at": 1, "nodes": [first]}, {"at": 2, "nodes": [{"id": "node-a"}]}])
        self.assertEqual(value["nodes"]["node-a"]["acceptance_status"], "unmeasured")

    def test_new_process_epoch_starts_a_new_trend(self):
        value = summarize([
            {"at": 1, "nodes": [{"id": "node-a", "epoch": "old", "memory_charged_bytes": 1000}]},
            {"at": 2, "nodes": [{"id": "node-a", "epoch": "new", "memory_charged_bytes": 100}]},
        ])
        self.assertEqual(value["nodes"]["node-a"]["trends"]["memory_charged_bytes"]["samples"], 1)

    def test_measurement_gate_rejects_each_excess_and_missing_category(self):
        script = Path(__file__).resolve().parents[2] / "scripts" / "check-memory-budgets.py"
        row = {"id": "fixture", "memory_charged_bytes": 1024, "memory_limit_bytes": 3 << 30,
               **{field: 0 for field in MEMORY_BUDGETS}}
        import sys
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.json"
            def check(value):
                path.write_text(json.dumps([{"at": 1, "nodes": [value]}]))
                return subprocess.run([sys.executable, str(script), str(path)], capture_output=True).returncode
            self.assertEqual(check(row), 0)
            for field, budget in MEMORY_BUDGETS.items():
                with self.subTest(field=field):
                    self.assertNotEqual(check({**row, field: budget + 1}), 0)
                    incomplete = dict(row); del incomplete[field]
                    self.assertNotEqual(check(incomplete), 0)
            self.assertNotEqual(check({**row, "memory_charged_bytes": True}), 0)
            missing_limit = dict(row); del missing_limit["memory_limit_bytes"]
            self.assertNotEqual(check(missing_limit), 0)
            self.assertNotEqual(check({**row, "memory_limit_bytes": 1023}), 0)

    def test_complete_categories_without_an_actual_limit_do_not_pass_acceptance(self):
        row = {"id": "fixture", "memory_charged_bytes": 1024,
               **{field: 0 for field in MEMORY_BUDGETS}}
        result = summarize([{"at": 1, "nodes": [row]}])["nodes"]["fixture"]
        self.assertEqual(result["acceptance_status"], "unmeasured")
        self.assertIn("memory_limit_bytes", result["unmeasured_categories"])

    def test_benchmark_rss_units_and_incomplete_samples_cannot_recommend_parallelism(self):
        path = Path(__file__).resolve().parents[2] / "scripts" / "measure-proof-parallel.py"
        spec = importlib.util.spec_from_file_location("parallel_measurement", path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(module.rss_bytes("   2147483648  maximum resident set size\n"), 2 << 30)
        self.assertEqual(module.rss_bytes("Maximum resident set size (kbytes): 2097152\n"), 2 << 30)
        self.assertIsNone(module.rss_bytes("missing OS measurement"))
        self.assertEqual(module.summarize([{"status": "timed_out"}], 3 << 30)["samples"], 0)


if __name__ == "__main__":
    unittest.main()
