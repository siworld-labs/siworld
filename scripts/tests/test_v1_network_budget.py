"""Exercise the conditional wire budget and its admission boundaries."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'v1-network-budget.py'
spec = importlib.util.spec_from_file_location('v1_network_budget', SCRIPT)
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)


class NetworkBudgetTests(unittest.TestCase):
    def test_full_payload_includes_all_relay_copies_and_settlement(self):
        result = budget.report()
        self.assertEqual(result['transaction_settlement_payload_bytes'], 911_451_741)
        self.assertGreater(result['wire_bytes_per_interval'], 1_096_000_000)
        self.assertLess(result['wire_bytes_per_interval'], 1_097_000_000)
        self.assertGreater(result['remaining_bytes_per_interval'], 0)
        self.assertLess(result['remaining_percent'], 3)

    def test_network_floor_does_not_change_the_wire_load(self):
        floor = budget.report()
        recommended = budget.report(link_mbps=100)
        self.assertEqual(floor['wire_bytes_per_interval'], recommended['wire_bytes_per_interval'])
        self.assertGreater(recommended['remaining_percent'], 70)
        self.assertLess(budget.report(link_mbps=25)['remaining_bytes_per_interval'], 0)

    def test_exact_packet_boundaries_include_ack_and_crypto_framing(self):
        self.assertGreater(budget.wire_message(1428), 1428 + 114)
        self.assertGreater(budget.wire_message(16_384), budget.wire_message(16_383))
        with self.assertRaises(ValueError):
            budget.wire_message(0)

    def test_only_fixed_capacity_groups_are_accepted(self):
        self.assertGreater(budget.report(64)['remaining_bytes_per_interval'], 0)
        for positions in (0, 63, 65, 577, 592):
            with self.assertRaises(ValueError):
                budget.report(positions)


if __name__ == '__main__':
    unittest.main()
