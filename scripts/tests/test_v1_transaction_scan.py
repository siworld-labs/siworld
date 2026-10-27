"""Reject incomplete or substituted V1 transaction-proof scan evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[1] / "scan-v1-transaction.py"
SPEC = importlib.util.spec_from_file_location("v1_transaction_scan", PATH)
SCAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCAN)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Bundle:
    def __init__(self, base):
        self.base = base
        self.sequence = 0
        self.manifest = {
            "schema": 1,
            "scope": SCAN.SCOPE,
            "suite": SCAN.SUITE,
            "actual_production_air": True,
            "air_version": "transaction-v1",
            "codec_version": "transaction-public-v1",
            "public_transaction_bytes": 1742,
            "inputs": 2,
            "outputs": 2,
            "anchor_membership_depth": 12,
            "anchor_public_statement": "recent-root-only",
            "p3_security_version": SCAN.P3_SECURITY,
            "measurement_host": {"machine_id": "test-host", "cpu_model": "test-cpu",
                "vcpus": 4, "isa": "x86-64-v3", "qualified": True},
            "tx_fixed_len": 2998,
            "artifacts": {},
            "rows": [],
        }
        for name in SCAN.REQUIRED_ARTIFACTS:
            self.manifest["artifacts"][name] = self.artifact(name, name.encode())
        for b in SCAN.BLOWUPS:
            for g in SCAN.GRINDING:
                self.manifest["rows"].append(self.row(b, g))

    def artifact(self, name, data):
        self.sequence += 1
        path = f"evidence/{self.sequence}-{name}"
        target = self.base / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return {"path": path, "sha256": sha(data)}

    def json_artifact(self, name, data):
        return self.artifact(name, json.dumps(data, sort_keys=True).encode())

    def rewrite(self, ref, value):
        data = json.dumps(value, sort_keys=True).encode()
        (self.base / ref["path"]).write_bytes(data)
        ref["sha256"] = sha(data)

    def read(self, ref):
        return json.loads((self.base / ref["path"]).read_text())

    def row(self, b, g):
        params = {"log_blowup": b, "num_queries": 80 - b,
            "query_pow_bits": g, "batch_pow_bits": g,
            "commit_pow_bits": 0, "max_log_arity": 1, "log_final_poly_len": 0}
        shape = {"status": "actual-extracted", "base_trace_rows": 512,
            "main_width": 600, "preprocessed_width": 125, "public_values": 89,
            "num_constraints": 1400, "max_constraint_degree": 3,
            "num_quotient_chunks": 8, "num_batched_functions": 1700,
            "log_committed_trace_length": 10, "challenge_field_bits_floor": 247,
            "classical_collision_bits_floor": 185}
        vk = self.artifact(f"vk-{b}-{g}", f"vk-{b}-{g}".encode())
        binding = {"suite": SCAN.SUITE, "air_version": "transaction-v1",
            "codec_version": "transaction-public-v1", "parameters": params,
            "air_shape_sha256": SCAN.canonical_digest(shape),
            "air_source_sha256": self.manifest["artifacts"]["air_source"]["sha256"],
            "dependencies_sha256": self.manifest["artifacts"]["dependencies"]["sha256"],
            "codec_sha256": self.manifest["artifacts"]["codec"]["sha256"],
            "binary_sha256": self.manifest["artifacts"]["binary"]["sha256"],
            "verification_key_sha256": vk["sha256"], "machine_id": "test-host"}
        terms = [{"label": label, "bits": bits} for label, bits in [
            ("air-composition", 225), ("deep-ali", 220),
            ("low-degree-test", 170), ("batch-combination", 210),
            ("commitment-collision", 185)]]
        security = {**binding, "schema": 1, "scope": SCAN.SCOPE,
            "actual_production_air": True, "p3_security_version": SCAN.P3_SECURITY,
            "accounting": SCAN.ACCOUNTING, "shape": shape,
            "application_binding": copy.deepcopy(SCAN.APPLICATION_BINDING),
            "fri": params,
            "grinding_sites": {"batch_combination": g, "out_of_domain": 0, "lookup_challenge": 0},
            "conjectured": {"terms": copy.deepcopy(terms)},
            "proven_johnson": {"terms": copy.deepcopy(terms)},
            "johnson_fri_terms": [{"label": "fri-query", "bits": 170},
                                  {"label": "fri-folding", "bits": 205}],
            "fri_folding_rounds": shape["log_committed_trace_length"] + 1,
            "challenge_domain_terms": [{"label": "ood-deep-ali-domain", "bits": 220},
                {"label": "fri-folding-domain", "bits": 205}]}
        trials = {}
        for kind, workers in SCAN.TRIAL_WORKERS.items():
            trials[kind] = []
            for index in range(1, 4):
                trial = {**binding, "schema": 1, "scope": SCAN.SCOPE,
                    "actual_production_air": True, "operation": kind,
                    "workers": workers, "rayon_threads": workers,
                    "trial_index": index, "run_id": f"{b}-{g}-{kind}-{index}",
                    "exit_code": 0, "verified": True, "proof_body_bytes": 400000 - b * 1000,
                    "wall_ns": 1_000_000_000 if kind != "verification" else 10_000_000,
                    "memory_peak_bytes": 200000000, "cpu_max": "max 100000",
                    "public_transaction_bytes": 1742,
                    "measurement_kind": "actual-native-proof"}
                trials[kind].append(self.json_artifact(f"trial-{b}-{g}-{kind}-{index}", trial))
        previous = copy.deepcopy(security)
        previous["parameters"]["num_queries"] = params["num_queries"] - 1
        previous["fri"]["num_queries"] = params["num_queries"] - 1
        previous["proven_johnson"]["terms"][2]["bits"] = 159
        previous["johnson_fri_terms"][0]["bits"] = 159
        return {"parameters": params, "air_shape": shape, "verification_key": vk,
            "security": self.json_artifact(f"security-{b}-{g}", security),
            "previous_query_security": self.json_artifact(f"previous-{b}-{g}", previous),
            "trials": trials}


class V1TransactionScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.bundle = Bundle(self.base)

    def tearDown(self):
        self.temp.cleanup()

    def validate(self):
        return SCAN.evaluate(self.bundle.manifest, self.base)

    def mutate_security(self, change):
        ref = self.bundle.manifest["rows"][0]["security"]
        value = self.bundle.read(ref)
        change(value)
        self.bundle.rewrite(ref, value)

    def test_complete_actual_bundle_selects_smallest_body_and_keeps_limits_separate(self):
        result = self.validate()
        self.assertEqual(result["decision"], "candidate-selected")
        self.assertEqual(result["selected"]["parameters"]["log_blowup"], 8)
        self.assertEqual(result["selected"]["max_leaf_proof_len_body_bytes"], 524288)
        self.assertEqual(result["selected"]["tx_max_len_bytes"], 527286)
        self.assertEqual(result["capacity"]["positions"], 576)
        self.assertFalse(result["cryptographic_approval"])
        self.assertFalse(result["network_activation"])

    def test_exact_bandwidth_threshold_uses_integer_arithmetic(self):
        self.assertEqual(SCAN.body_capacity(576, 1790), 540744)
        self.assertEqual(SCAN.body_capacity(544, 1790), 572658)

    def test_proxy_scope_and_false_production_claim_are_rejected(self):
        for key, value in [("scope", "proxy"), ("actual_production_air", False),
                           ("suite", "D4-W16"), ("public_transaction_bytes", 2818)]:
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.bundle.manifest)
                manifest[key] = value
                with self.assertRaises(ValueError):
                    SCAN.evaluate(manifest, self.base)

    def test_missing_grid_pair_and_duplicate_pair_are_rejected(self):
        for rows in [self.bundle.manifest["rows"][:-1],
                     self.bundle.manifest["rows"][:-1] + [self.bundle.manifest["rows"][0]]]:
            manifest = copy.deepcopy(self.bundle.manifest)
            manifest["rows"] = rows
            with self.assertRaisesRegex(ValueError, "15|duplicate|grid"):
                SCAN.evaluate(manifest, self.base)

    def test_modified_or_missing_pinned_artifact_is_rejected(self):
        ref = self.bundle.manifest["artifacts"]["codec"]
        (self.base / ref["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "hash"):
            self.validate()

    def test_external_path_and_symlink_are_rejected(self):
        for value in ["../outside", "/etc/passwd"]:
            with self.assertRaisesRegex(ValueError, "path"):
                SCAN.bundle_file(self.base, value)
        (self.base / "link").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "path"):
            SCAN.bundle_file(self.base, "link")

    def test_wrong_codec_or_shape_in_trial_is_rejected(self):
        for key in ["codec_sha256", "air_shape_sha256", "verification_key_sha256"]:
            ref = self.bundle.manifest["rows"][0]["trials"]["four_worker"][0]
            before = self.bundle.read(ref)
            value = copy.deepcopy(before)
            value[key] = "f" * 64
            self.bundle.rewrite(ref, value)
            with self.assertRaisesRegex(ValueError, key):
                self.validate()
            self.bundle.rewrite(ref, before)

    def test_wrong_p3_version_and_missing_johnson_do_not_fall_back_to_udr(self):
        self.mutate_security(lambda data: data.update(p3_security_version="latest"))
        with self.assertRaisesRegex(ValueError, "p3-security"):
            self.validate()
        self.bundle = Bundle(self.base)
        self.mutate_security(lambda data: data.update(proven_johnson=None,
            proven_unique_decoding={"terms": [{"label": "low-degree-test", "bits": 999}]}))
        with self.assertRaisesRegex(ValueError, "Johnson"):
            self.validate()

    def test_query_boundary_requires_actual_failing_q_minus_one_report(self):
        row = self.bundle.manifest["rows"][0]
        ref = row["previous_query_security"]
        value = self.bundle.read(ref)
        value["proven_johnson"]["terms"][2]["bits"] = 170
        value["johnson_fri_terms"][0]["bits"] = 170
        self.bundle.rewrite(ref, value)
        with self.assertRaisesRegex(ValueError, "q-1|boundary"):
            self.validate()

    def test_each_johnson_term_and_challenge_domain_are_charged(self):
        self.mutate_security(lambda data: data["proven_johnson"]["terms"][0].update(bits=159))
        result = self.validate()
        self.assertFalse(result["rows"][0]["eligible"])
        self.assertIn("quantum", " ".join(result["rows"][0]["rejections"]))
        self.mutate_security(lambda data: data["challenge_domain_terms"][0].update(bits=159))
        result = self.validate()
        self.assertIn("domain", " ".join(result["rows"][0]["rejections"]))

    def test_hash_bht_uses_collision_exponent_and_not_legacy_screen(self):
        self.mutate_security(lambda data: data.update(screen={"bounds": {"bht_collision": 999}}))
        result = self.validate()
        self.assertAlmostEqual(result["rows"][0]["security"]["bht_collision_bits"], 185 * 2 / 3)
        self.assertAlmostEqual(result["rows"][0]["security"]["nominal_minimum_hash_bht_bits"], 256 / 3)

    def test_bht_target_boundary_keeps_raw_classical_collision_units(self):
        def collision(bits):
            def change(data):
                for regime in ("conjectured", "proven_johnson"):
                    for term in data[regime]["terms"]:
                        if term["label"] == "commitment-collision":
                            term["bits"] = bits
            return change

        # A 120-bit classical collision floor corresponds to 240 digest bits:
        # generic BHT costs 2^80, whereas uniform halving would give 60 bits.
        # The lower classical floor can fail another gate; inspect BHT alone.
        self.mutate_security(collision(120))
        row = self.validate()["rows"][0]
        self.assertEqual(row["security"]["johnson_terms"]["commitment-collision"], 120)
        self.assertAlmostEqual(row["security"]["bht_collision_bits"], 80)
        self.assertFalse(any("BHT collision" in reason for reason in row["rejections"]))

        self.mutate_security(collision(119))
        row = self.validate()["rows"][0]
        self.assertTrue(any("BHT collision below 80 bits" in reason
                            for reason in row["rejections"]))

    def test_application_hash_annotation_cannot_be_omitted_or_replaced_by_pcs_security(self):
        self.mutate_security(lambda data: data.pop("application_binding", None))
        with self.assertRaisesRegex(ValueError, "application binding"):
            self.validate()
        self.bundle = Bundle(self.base)
        self.mutate_security(lambda data: data["application_binding"].update(
            nominal_bht_collision_bits=185 * 2 / 3))
        with self.assertRaisesRegex(ValueError, "application binding"):
            self.validate()

    def test_three_distinct_trials_and_actual_four_workers_are_required(self):
        row = self.bundle.manifest["rows"][0]
        row["trials"]["single_worker"] = row["trials"]["single_worker"][:2]
        with self.assertRaisesRegex(ValueError, "three"):
            self.validate()
        self.bundle = Bundle(self.base)
        row = self.bundle.manifest["rows"][0]
        row["trials"]["four_worker"][1] = row["trials"]["four_worker"][0]
        with self.assertRaisesRegex(ValueError, "duplicate|trial_index"):
            self.validate()

    def test_cpu_throttle_failed_trial_and_unverified_proof_are_rejected(self):
        for change in [dict(cpu_max="200000 100000"), dict(exit_code=137),
                       dict(verified=False), dict(workers=2), dict(rayon_threads=1)]:
            ref = self.bundle.manifest["rows"][0]["trials"]["four_worker"][0]
            before = self.bundle.read(ref)
            self.bundle.rewrite(ref, {**before, **change})
            with self.assertRaises(ValueError):
                self.validate()
            self.bundle.rewrite(ref, before)

    def test_median_runtime_and_max_proof_length_are_used(self):
        row = self.bundle.manifest["rows"][-1]
        for index, wall in enumerate([1_000_000_000, 2_000_000_000, 3_000_000_000]):
            ref = row["trials"]["four_worker"][index]
            value = self.bundle.read(ref)
            value.update(wall_ns=wall, proof_body_bytes=390000 + index)
            self.bundle.rewrite(ref, value)
        result = self.validate()
        measured = result["rows"][-1]
        self.assertEqual(measured["measurements"]["four_worker"]["median_ns"], 2_000_000_000)
        self.assertEqual(measured["proof_body_bytes_max"], 392000)

    def set_all_proof_sizes(self, size):
        for row in self.bundle.manifest["rows"]:
            for refs in row["trials"].values():
                for ref in refs:
                    value = self.bundle.read(ref)
                    value["proof_body_bytes"] = size
                    self.bundle.rewrite(ref, value)

    def test_fixed_wire_cap_accepts_boundary_and_rejects_one_extra_byte(self):
        self.set_all_proof_sizes(524288)
        result = self.validate()
        self.assertEqual(result["capacity"]["positions"], 576)
        self.assertEqual(result["selected"]["max_leaf_proof_len_body_bytes"], 524288)
        self.set_all_proof_sizes(524289)
        result = self.validate()
        self.assertEqual(result["decision"], "blocked-proof-cap")
        self.assertIsNone(result["selected"])
        self.assertEqual(result["capacity"]["proposed_fallback_positions"], 544)
        self.assertTrue(result["capacity"]["requires_owner_report"])
        self.assertEqual(result["capacity"]["fixed_max_leaf_proof_len_bytes"], 524288)

    def test_large_codec_can_only_propose_544_without_raising_wire_cap(self):
        self.bundle.manifest["tx_fixed_len"] = 30000
        self.set_all_proof_sizes(524288)
        result = self.validate()
        self.assertEqual(result["capacity"]["positions"], 544)
        self.assertEqual(result["decision"], "capacity-proposed-544")
        self.assertTrue(result["capacity"]["requires_owner_report"])
        self.assertEqual(result["selected"]["max_leaf_proof_len_body_bytes"], 524288)
        self.assertFalse(result["network_activation"])

    def test_smaller_codec_preserves_fixed_512_kib_wire_cap(self):
        self.bundle.manifest["tx_fixed_len"] = 1790
        self.set_all_proof_sizes(431030)
        result = self.validate()
        self.assertEqual(result["capacity"]["positions"], 576)
        self.assertEqual(result["capacity"]["proof_body_cap_at_576_bytes"], 524288)
        self.assertGreater(result["capacity"]["actual_bandwidth_body_caps_bytes"]["576"], 524288)
        self.assertEqual(result["selected"]["measured_proof_body_bytes_max"], 431030)
        self.assertEqual(result["selected"]["max_leaf_proof_len_body_bytes"], 524288)

    def test_no_under_two_second_row_is_blocked(self):
        for row in self.bundle.manifest["rows"]:
            for ref in row["trials"]["four_worker"]:
                value = self.bundle.read(ref)
                value["wall_ns"] = 2_000_000_001
                self.bundle.rewrite(ref, value)
        result = self.validate()
        self.assertEqual(result["decision"], "blocked-no-eligible-parameter")
        self.assertIsNone(result["selected"])

    def test_nonfinite_bool_and_missing_terms_are_rejected(self):
        for bad in [float("nan"), float("inf"), True]:
            self.bundle = Bundle(self.base)
            self.mutate_security(lambda data: data["proven_johnson"]["terms"][0].update(bits=bad))
            with self.assertRaises(ValueError):
                self.validate()
        self.bundle = Bundle(self.base)
        self.mutate_security(lambda data: data["proven_johnson"].update(terms=[]))
        with self.assertRaisesRegex(ValueError, "terms"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
