"""Reject mismatched Linux controls and aggregate the corrected three-trial run."""
import copy
import importlib.util
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
