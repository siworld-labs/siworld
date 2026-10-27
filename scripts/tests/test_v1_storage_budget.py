"""Check retention and minimum-position boundaries in the V1 capacity model."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'v1-storage-budget.py'
spec = importlib.util.spec_from_file_location('v1_storage_budget', SCRIPT)
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)


class StorageBudgetTests(unittest.TestCase):
    def test_low_demand_keeps_minimum_blocks_and_padding(self):
        self.assertEqual(budget.positions_per_day(0), 18_432)
        self.assertEqual(budget.positions_per_day(10_000), 18_432)
        self.assertEqual(budget.positions_per_day(50_001), 50_016)
        with self.assertRaises(ValueError):
            budget.positions_per_day(165_889)

    def test_finality_delay_is_added_before_three_day_expiry(self):
        result = budget.estimate(165_888, 1)
        self.assertEqual(budget.RETENTION_BLOCKS, 888)
        self.assertEqual(result['rolling_positions'], 511_488)
        self.assertEqual(result['transaction_settlement_sidecar_rolling_bytes'], 268_672_484_352)
        self.assertEqual(result['issuance_proof_rolling_allowance_bytes'], 465_567_744)
        self.assertEqual(result['rolling_bytes'], 269_138_052_096)

    def test_multiyear_public_growth_does_not_repeat_the_rolling_cache(self):
        first = budget.estimate(165_888, 1)
        fifth = budget.estimate(165_888, 5)
        self.assertEqual(first['rolling_bytes'], fifth['rolling_bytes'])
        self.assertEqual(fifth['permanent_public_bytes'], 640_306_944_000)
        self.assertGreater(first['device_bytes_with_20_percent_free'], 500_000_000_000)
        self.assertGreater(fifth['device_bytes_with_20_percent_free'], 1_000_000_000_000)

    def test_adaptive_window_rounds_up_to_complete_groups(self):
        result = budget.estimate(50_000, 1)
        self.assertEqual(result['rolling_positions'], 154_176)
        self.assertEqual(result['rolling_positions'] % 16, 0)
        self.assertGreaterEqual(result['rolling_positions'] * 288, 50_000 * 888)

    def test_finite_block_and_issuance_allowances_are_included(self):
        result = budget.estimate(165_888, 3)
        self.assertEqual(result['permanent_block_record_allowance_bytes'], 2_583_429_120)
        self.assertEqual(result['permanent_issuance_allowance_bytes'], 5_166_858_240)
        self.assertEqual(result['database_working_allowance_bytes'], 16_000_000_000)
        self.assertLess(result['device_bytes_with_20_percent_free'], 1_000_000_000_000)
        self.assertLess(budget.estimate(50_688, 5)['device_bytes_with_20_percent_free'],
                        500_000_000_000)

    def test_extra_permanent_records_are_never_forgotten(self):
        base = budget.estimate(50_000, 3)
        extra = budget.estimate(50_000, 3, extra_permanent_bytes=4_000_000)
        self.assertEqual(extra['used_bytes'] - base['used_bytes'], 4_000_000)
        self.assertEqual(extra['device_bytes_with_20_percent_free'] -
                         base['device_bytes_with_20_percent_free'], 5_000_000)


if __name__ == '__main__':
    unittest.main()
