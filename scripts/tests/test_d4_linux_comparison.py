"""Reject mismatched Linux controls and aggregate the corrected three-trial run."""
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('comparison',
    Path(__file__).parents[1] / 'compare-d4-linux.py')
COMPARISON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARISON)


class D4LinuxComparisonTests(unittest.TestCase):
    def fixture(self):
        row = {'verified': True, 'leaf_profile': 'b', 'jobs': 1, 'slots': 16,
            'topology': 'fanin8',
            'parameters': {'suite': 'D4-W16', 'log_blowup': 2, 'queries': 92, 'grinding': 16},
            'leaf_parameters': {'suite': 'D4-W16', 'log_blowup': 4, 'queries': 46, 'grinding': 16},
            'runtime': {'packing_width': 8, 'global_rayon_threads': 2,
                'rayon_num_threads': '2', 'composition_hiding_workers': '2',
                'compiled_avx2': True, 'compiled_avx512f': False},
            'stages': [{'phase': 'leaves', 'wall_ns': 1}],
            'batch_node_wall_ns': [2, 3], 'proof_and_verify_ns': 8, 'cold_wall_ns': 9}
        measurement = {'resource_control_pass': True, 'memory_peak': 100, 'swap_peak': 0,
            'memory_events_delta': {'oom': 0}, 'cpu_summary': {'average_cpu_cores': 1.5},
            'cpu_ancestry_before': [{'path': '/private/scope', 'cpu.max': 'max 100000',
                                     'cpuset.cpus.effective': '0-3'}]}
        return row, measurement

    def read(self, row, measurement=None, mode='avx2'):
        if measurement is None:
            measurement = self.fixture()[1]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'measurement.json').write_text(json.dumps(measurement))
            (directory / 'stdout.jsonl').write_text(json.dumps(row) + '\n')
            return COMPARISON.read_trial(directory, mode)

    def test_optimized_worker_requires_generic_cpu_check_launcher_and_matching_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / 'bin').mkdir()
            (package / 'libexec').mkdir()
            launcher = package / 'bin/composition-bench'
            worker = package / 'libexec/composition-bench'
            launcher.write_bytes(b'generic launcher')
            worker.write_bytes(b'optimized worker')
            receipt = {'worker_isa': 'x86-64-v3', 'bootstrap_isa': 'x86-64',
                'bootstrap_sha256': hashlib.sha256(launcher.read_bytes()).hexdigest(),
                'repository_config_sha256': hashlib.sha256(
                    (COMPARISON.ROOT / '.cargo/config.toml').read_bytes()).hexdigest(),
                'workers': [{'name': 'composition-bench',
                    'worker_sha256': hashlib.sha256(worker.read_bytes()).hexdigest()}]}
            path = package / 'build-receipt.json'
            path.write_text(json.dumps(receipt))
            self.assertEqual(COMPARISON.proof_worker(launcher, 'avx2'), worker.resolve())
            self.assertEqual(COMPARISON.proof_worker(worker, 'scalar'), worker)
            with self.assertRaises(ValueError):
                COMPARISON.proof_worker(worker, 'avx2')
            for mutation in ({'bootstrap_sha256': 'wrong'}, {'worker_isa': 'x86-64'},
                             {'repository_config_sha256': 'wrong'}, {'workers': []}):
                path.write_text(json.dumps({**receipt, **mutation}))
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    COMPARISON.proof_worker(launcher, 'avx2')

    def test_build_receipt_requires_effective_flags_and_repository_configuration(self):
        receipt = {'binary_sha256': 'digest', 'effective_rustflags': COMPARISON.FLAGS['avx2'],
            'cargo_working_directory': 'repository-root', 'diagnostic_only': False,
            'build_environment': {'RUSTFLAGS': None},
            'repository_config_sha256': hashlib.sha256(
                (COMPARISON.ROOT / '.cargo/config.toml').read_bytes()).hexdigest()}
        inspected = {'binary_sha256': 'digest'}
        COMPARISON.verify_build_receipt(receipt, inspected, 'avx2')
        for mutation in ({'effective_rustflags': '-C target-cpu=native'},
                         {'cargo_working_directory': 'other'}, {'binary_sha256': 'wrong'},
                         {'diagnostic_only': True}, {'repository_config_sha256': 'wrong'}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                COMPARISON.verify_build_receipt({**receipt, **mutation}, inspected, 'avx2')

    def test_v3_only_mode_never_requires_scalar_binary(self):
        args = COMPARISON.parse_arguments(['--avx2', 'prover', '--output', 'private',
            '--avx2-only', '--hardware-profile', 'epyc7763-baseline'])
        self.assertIsNone(args.scalar)
        self.assertTrue(args.avx2_only)
        self.assertEqual(args.hardware_profile, 'epyc7763-baseline')
        with self.assertRaises(SystemExit):
            COMPARISON.parse_arguments(['--avx2', 'prover', '--scalar', 'scalar',
                '--output', 'private', '--avx2-only'])
        with self.assertRaises(SystemExit):
            COMPARISON.parse_arguments(['--avx2', 'prover', '--output', 'private'])

    def test_optimized_flags_use_fixed_v3_baseline(self):
        self.assertEqual(COMPARISON.FLAGS['avx2'], '-C target-cpu=x86-64-v3')
        self.assertNotIn('native', COMPARISON.FLAGS['avx2'])

    def test_trial_preserves_qualification_without_promoting_diagnostic(self):
        row, measurement = self.fixture()
        measurement['hardware_qualification'] = {'profile': 'epyc7763-baseline',
            'role': 'baseline', 'profile_qualified': True,
            'same_physical_instance_established': False}
        result = self.read(row, measurement)
        self.assertEqual(result['hardware_qualification'], measurement['hardware_qualification'])
        self.assertFalse(result['diagnostic_only'])
        row['runtime'].update(packing_width=1, compiled_avx2=False)
        result = self.read(row, measurement, mode='scalar')
        self.assertTrue(result['diagnostic_only'])
        self.assertFalse(result['acceptance'])

    def test_rejects_wrong_packing_and_actual_worker_settings(self):
        row, _ = self.fixture()
        for key, value in (('packing_width', 1), ('global_rayon_threads', 1),
                ('rayon_num_threads', '1'), ('composition_hiding_workers', '1'),
                ('compiled_avx2', False), ('compiled_avx512f', True)):
            with self.subTest(key=key):
                changed = copy.deepcopy(row)
                changed['runtime'][key] = value
                with self.assertRaises(ValueError):
                    self.read(changed)
        scalar = copy.deepcopy(row)
        scalar['runtime'].update(packing_width=1, compiled_avx2=False)
        self.assertEqual(self.read(scalar, mode='scalar')['mode'], 'scalar')

    def test_rejects_wrong_relation_leaf_parameters_and_failed_limit(self):
        row, measurement = self.fixture()
        for key, value in (('slots', 32), ('topology', 'binary'), ('jobs', 2),
                           ('leaf_profile', 'uniform')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.read({**row, key: value})
        for key in ('parameters', 'leaf_parameters'):
            changed = copy.deepcopy(row)
            changed[key]['grinding'] = 0
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.read(changed)
        with self.assertRaises(ValueError):
            self.read(row, {**measurement, 'resource_control_pass': False})

    def test_public_trial_has_no_private_cgroup_path(self):
        result = self.read(self.fixture()[0])
        self.assertEqual(result['cpu_limits'], [{'scope': 'owned', 'cpu.max': 'max 100000',
                                                'cpuset.cpus.effective': '0-3'}])
        self.assertNotIn('/private', json.dumps(result))

    def test_three_trial_medians_include_each_merge_and_peak_maximum(self):
        trials = []
        for proof, cold, peak, left, right, leaves in (
                (40, 50, 300, 13, 12, 4), (20, 30, 100, 7, 8, 2),
                (30, 40, 200, 10, 9, 3)):
            trials.append({'proof_and_verify_ns': proof, 'cold_wall_ns': cold,
                'memory_peak': peak, 'batch_node_wall_ns': [left, right],
                'stages': [{'phase': 'leaves', 'wall_ns': leaves},
                           {'phase': 'root_proof', 'wall_ns': proof - left - right - leaves}]})
        result = COMPARISON.aggregate(trials)
        self.assertEqual(result['trials'], 3)
        self.assertEqual(result['proof_and_verify_median_ns'], 30)
        self.assertEqual(result['cold_median_ns'], 40)
        self.assertEqual(result['memory_peak_median'], 200)
        self.assertEqual(result['memory_peak_max'], 300)
        self.assertEqual(result['merge_medians_ns'], [10, 9])
        self.assertEqual(result['stage_medians_ns'], {'leaves': 3, 'root_proof': 8})
        trials[0]['stages'] = []
        with self.assertRaises(ValueError):
            COMPARISON.aggregate(trials)


if __name__ == '__main__':
    unittest.main()
