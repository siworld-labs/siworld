"""Reject incomplete and misleading security-report summaries."""
import copy
import importlib.util
import math
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "report-composition-security.py"
SPEC = importlib.util.spec_from_file_location("composition_security", PATH)
SECURITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY)


def fixture():
    # Deliberately make UDR stronger than Johnson; it must never replace it.
    terms = [{"label": "deep-ali", "bits": 101.0},
             {"label": "commitment-collision", "bits": 123.0}]
    return {layer: {"report": {
        "conjectured": {"terms": copy.deepcopy(terms),
                        "weakest_term": "deep-ali", "minimum_term_bits": 101.0},
        "proven_johnson": {"terms": copy.deepcopy(terms),
                           "weakest_term": "deep-ali", "minimum_term_bits": 101.0},
        "proven_unique_decoding": {"minimum_term_bits": 999.0},
    }} for layer, count in SECURITY.LAYERS}


class CompositionSecurityTests(unittest.TestCase):
    def test_all_terms_and_nineteen_proofs_are_charged(self):
        result = SECURITY.summarize(fixture())
        expected = 101 - math.log2(19 * (1 + 2 ** -22))
        self.assertAlmostEqual(result["composition_union_bits"]["conjectured"], expected)
        self.assertAlmostEqual(result["composition_union_bits"]["proven_johnson"], expected)
        self.assertLess(result["illustrative_quantum_halving_screen_union_bits"], 51)
        self.assertFalse(result["acceptance"])

    def test_absent_johnson_does_not_fall_back_to_udr(self):
        report = fixture()
        report["root"]["report"]["proven_johnson"] = None
        with self.assertRaisesRegex(ValueError, "Missing proven_johnson"):
            SECURITY.summarize(report)

    def test_d4_digest_cap_cannot_be_raised_by_query_terms(self):
        report = fixture()
        for layer, count in SECURITY.LAYERS:
            report[layer]["report"]["conjectured"]["terms"][0]["bits"] = 400.0
        result = SECURITY.summarize(report)
        self.assertLess(result["ideal_bht_collision_ceiling_bits"], 100)
        self.assertLess(result["illustrative_quantum_halving_screen_union_bits"], 83)
        self.assertFalse(result["acceptance"])


if __name__ == "__main__":
    unittest.main()
