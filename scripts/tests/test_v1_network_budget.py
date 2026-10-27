"""Exercise wire overhead, independent proof caps and capacity headroom."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'v1-network-budget.py'
spec = importlib.util.spec_from_file_location('v1_network_budget', SCRIPT)
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)


class NetworkBudgetTests(unittest.TestCase):
    def test_original_512_kib_scenario_is_reproducible(self):
        result = budget.report(link_mbps=30, transaction_proof_cap=524_288,
                               capacity_headroom_percent=0)
        self.assertEqual(result['transaction_settlement_payload_bytes'], 911_451_741)
        self.assertEqual(result['wire_bytes_per_interval'], 1_096_933_002)
        self.assertGreater(result['remaining_bytes_per_interval'], 0)
        self.assertLess(result['remaining_percent'], 3)

    def test_minimum_link_keeps_fifteen_percent_of_capacity_free(self):
        for cap in (524_288, 704 * 1024, 768 * 1024, 832 * 1024):
            result = budget.report(transaction_proof_cap=cap)
            minimum = result['minimum_link_mbps']
            self.assertEqual(result['evaluated_link_mbps'], minimum)
            self.assertGreaterEqual(result['remaining_percent'], 15)
            self.assertTrue(result['meets_capacity_headroom'])
            below = budget.report(transaction_proof_cap=cap, link_mbps=minimum - 1)
            self.assertFalse(below['meets_capacity_headroom'])
            self.assertEqual(result['wire_bytes_per_interval'], below['wire_bytes_per_interval'])

    def test_larger_transaction_cap_does_not_expand_other_proofs(self):
        base = budget.report(transaction_proof_cap=524_288)
        larger = budget.report(transaction_proof_cap=768 * 1024)
        base_components = base['components_bytes_per_interval']
        larger_components = larger['components_bytes_per_interval']
        self.assertGreater(larger_components['transaction_and_sidecar_wire'],
                           base_components['transaction_and_sidecar_wire'])
        for component in ('settlement_wire', 'issuance_wire_allowance', 'inventory_wire',
                          'handshake_wire_allowance', 'keepalive_wire_allowance'):
            self.assertEqual(base_components[component], larger_components[component])
        self.assertEqual(larger['parameters']['settlement_proof_cap_bytes'], 524_288)
        self.assertEqual(larger['parameters']['issuance_proof_cap_bytes'], 524_288)
        expected_payload = 3 * (576 * (768 * 1024 + 2184 + 78) + 524_288 + 159)
        self.assertEqual(larger['transaction_settlement_payload_bytes'], expected_payload)

    def test_each_wire_reserve_is_added_before_capacity_headroom(self):
        result = budget.report(transaction_proof_cap=768 * 1024)
        components = result['components_bytes_per_interval']
        base = sum(value for name, value in components.items()
                   if name not in ('retransmission_reserve', 'recovery_reserve'))
        self.assertEqual(components['retransmission_reserve'], budget.ceil_div(base * 2, 100))
        self.assertEqual(components['recovery_reserve'], budget.ceil_div(base * 5, 100))
        self.assertEqual(result['wire_bytes_per_interval'], sum(components.values()))
        self.assertEqual(result['minimum_link_mbps'],
                         budget.ceil_div(result['wire_bytes_per_interval'] * 8 * 100,
                                         300 * 1_000_000 * 85))

    def test_network_floor_does_not_change_the_wire_load(self):
        floor = budget.report()
        recommended = budget.report(link_mbps=100)
        self.assertEqual(floor['wire_bytes_per_interval'], recommended['wire_bytes_per_interval'])
        self.assertGreater(recommended['remaining_percent'], 70)
        self.assertLess(budget.report(link_mbps=25)['remaining_bytes_per_interval'], 0)
        self.assertEqual(recommended['recommended_link_mbps'], 100)

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
        for arguments in ({'transaction_proof_cap': 0}, {'settlement_proof_cap': -1},
                          {'issuance_proof_cap': 0}, {'capacity_headroom_percent': -1},
                          {'capacity_headroom_percent': 100}, {'link_mbps': 0}):
            with self.assertRaises(ValueError):
                budget.report(**arguments)


if __name__ == '__main__':
    unittest.main()
