"""Protect scope attribution, failure evidence and public artifact boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('native_cgroup',
    Path(__file__).parents[1] / 'measure-native-cgroup.py')
CG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CG)


class NativeCgroupTests(unittest.TestCase):
    UNIT = 'siworld-native-' + 'a' * 32 + '.scope'

    def counters(self):
        return {'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0},
                'memory.peak': 1000, 'memory.swap.current': 0}

    def test_exact_scope_membership_is_required(self):
        mount = Path('/synthetic/cgroup')
        self.assertEqual(CG.scoped_group('0::/system.slice/' + self.UNIT, self.UNIT, mount),
                         mount / 'system.slice' / self.UNIT)
        for membership in ('0::/', '0::/other.scope', '0::/../' + self.UNIT,
                           '1:memory:/system.slice/' + self.UNIT,
                           '0::relative/' + self.UNIT,
                           '0::/system.slice/' + self.UNIT + '\n0::/system.slice/' + self.UNIT):
            with self.subTest(membership=membership), self.assertRaises(ValueError):
                CG.scoped_group(membership, self.UNIT, mount)

    def test_scope_properties_keep_recorder_alive_and_apply_exact_limits(self):
        command = CG.scope_command(self.UNIT, Path('/synthetic/config.json'))
        self.assertIn('--scope', command)
        self.assertIn('--unit=' + self.UNIT, command)
        for prop in ('MemoryMax=5G', 'MemorySwapMax=0', 'MemoryOOMGroup=no', 'MemoryAccounting=yes', 'CPUAccounting=yes'):
            self.assertIn(prop, command)
        self.assertNotIn('--user', command)
        with self.assertRaises(ValueError):
            CG.scoped_group('0::/unrelated.scope', 'unrelated.scope')

    def test_smoke_scope_cannot_execute_an_arbitrary_worker(self):
        self.assertEqual(CG.child_command('scope-smoke', Path('/untrusted/worker'),
            Path('/ignored/output'), 1, 'unused'), ['/usr/bin/true'])

    def test_startup_errors_are_fixed_labels_without_host_paths(self):
        text = 'Failed to connect to bus: /private/owner/sensitive'
        self.assertEqual(CG.startup_diagnostic(text)['category'], 'systemd-bus-unavailable')
        text = json.dumps({'event': 'native-cgroup-diagnostic-failed',
            'classification': 'FileNotFoundError', 'stage': 'initial-counters',
            'os_error_number': 2, 'kernel_file': 'cpu.max', 'private_path': '/private/owner'})
        result = CG.startup_diagnostic(text)
        self.assertEqual(result['kernel_file'], 'cpu.max')
        self.assertEqual(result['stage'], 'initial-counters')
        self.assertNotIn('private_path', result)
        injected = json.dumps({'event': 'native-cgroup-diagnostic-failed',
            'classification': '/private/owner', 'stage': '/private/owner',
            'kernel_file': '/private/owner', 'os_error_number': '/private/owner'})
        self.assertNotIn('/private/owner', str(CG.startup_diagnostic(injected)))

    def test_failed_proof_is_never_reported_as_resource_acceptance(self):
        before, after = self.counters(), self.counters()
        success = CG.assess(before, after, 0, False, set())
        self.assertTrue(success['resource_control_pass'])
        self.assertFalse(success['acceptance'])
        self.assertFalse(success['production_parameters_frozen'])
        for event in CG.EVENTS:
            changed = copy.deepcopy(after)
            changed['memory.events'][event] = 1
            with self.subTest(event=event):
                self.assertFalse(CG.assess(before, changed, 0, False, set())['resource_control_pass'])
        for code, timeout, remaining in ((137, False, set()), (0, True, set()), (0, False, {42})):
            self.assertFalse(CG.assess(before, after, code, timeout, remaining)['resource_control_pass'])
        after['memory.peak'] = CG.MEMORY_MAX + 1
        self.assertFalse(CG.assess(before, after, 0, False, set())['resource_control_pass'])
        after['memory.events']['max'] = -1
        with self.assertRaises(ValueError):
            CG.assess(before, after, 0, False, set())

    def test_kernel_readback_cannot_silently_drop_limit_or_oom_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            files = {'memory.max': str(CG.MEMORY_MAX), 'memory.swap.max': '0',
                     'memory.oom.group': '0', 'memory.peak': '1000', 'memory.current': '500',
                     'memory.swap.current': '0', 'memory.events': 'oom 0\n',
                     'memory.events.local': 'oom 0\n', 'cpu.stat': 'usage_usec 1\n',
                     'cpu.max': 'max 100000'}
            for name, value in files.items():
                (group / name).write_text(value)
            self.assertEqual(CG.snapshot(group)['memory.peak'], 1000)
            for name, wrong in (('memory.max', '1000'), ('memory.swap.max', '1'), ('memory.oom.group', '1')):
                (group / name).write_text(wrong)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    CG.snapshot(group)
                (group / name).write_text(files[name])

    def test_each_settlement_process_proves_exactly_once(self):
        command = CG.child_command('settlement', Path('fee-settlement-bench'), Path('raw.json'), 1, 'r')
        self.assertEqual(command[command.index('--capacity') + 1], '576')
        self.assertEqual(command[command.index('--trials') + 1], '1')
        trial = {'generation_ms': 20, 'verification_ms': 2, 'proof_bytes': 1000,
                 'private_commitment': 'excluded'}
        report = {'suite': CG.SUITE, 'capacities': [576], 'worker_count': 4,
            'fri_profile': 'transaction-candidate-diagnostic',
            'records': [{'capacity': 576, 'trials': [trial],
                         'shape': {'air_rows': 16}, 'input_digests': ['excluded']}]}
        public = CG.proof_metrics('settlement', report)
        self.assertEqual(public['generation_ns'], 20_000_000)
        self.assertNotIn('input_digests', public)
        self.assertNotIn('private_commitment', str(public))
        report['records'][0]['trials'].append(trial)
        with self.assertRaises(ValueError):
            CG.proof_metrics('settlement', report)

    def test_oom_counters_are_saved_before_scope_recorder_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            group = base / 'cgroup'
            group.mkdir()
            before = self.counters()
            after = self.counters()
            after['memory.events']['oom_kill'] = 1
            config = {'uid': 1001, 'gid': 1001, 'unit': self.UNIT,
                'private_output': str(base / 'raw.json'), 'private_log': str(base / 'raw.log'),
                'executable': '/synthetic/transaction', 'trial': 1, 'run_id': 'test',
                'timeout': 5, 'kind': 'transaction', 'result': str(base / 'result.json')}
            process = mock.Mock()
            process.wait.return_value = -9
            process.pid = 100
            def redirected(path):
                if str(path) in ('/proc/self/cgroup', '/proc/self/oom_score_adj'):
                    return base / Path(path).name
                return Path(path)
            (base / 'cgroup').mkdir(exist_ok=True)
            # Membership is read before the group resolver; provide a harmless
            # fixture instead of relying on the unit-test host's kernel.
            membership = base / 'membership'
            membership.write_text('0::/system.slice/' + self.UNIT)
            def mapped(path):
                if str(path) == '/proc/self/cgroup':
                    return membership
                return redirected(path)
            with mock.patch.object(CG.os, 'geteuid', return_value=0), \
                 mock.patch.object(CG, 'Path', side_effect=mapped), \
                 mock.patch.object(CG, 'scoped_group', return_value=group), \
                 mock.patch.object(CG, 'snapshot', side_effect=[before, after]), \
                 mock.patch.object(CG, 'member_pids', return_value=set()), \
                 mock.patch.object(CG.subprocess, 'Popen', return_value=process):
                self.assertEqual(CG.run_in_scope(config), 1)
            saved = json.loads((base / 'result.json').read_text())
            self.assertEqual(saved['memory']['after']['memory.events']['oom_kill'], 1)
            self.assertEqual(saved['event_deltas']['oom_kill'], 1)
            self.assertEqual(saved['exit_code'], -9)
            self.assertFalse(saved['resource_control_pass'])
            self.assertFalse(saved['proof_report_valid'])
            self.assertEqual((base / 'oom_score_adj').read_text(), '-1000')

    def test_unverified_or_wrong_parameter_transaction_is_rejected(self):
        report = {'suite': CG.SUITE, 'verified': True, 'workers': 4,
            'operation': 'four_worker', 'production_selection_allowed': False,
            'parameters': dict(CG.PARAMETERS), 'setup_ns': 1, 'generation_ns': 2,
            'verification_ns': 3, 'proof_body_bytes': 4, 'private_source_path': 'excluded'}
        self.assertNotIn('private_source_path', CG.proof_metrics('transaction', report))
        for key, value in (('verified', False), ('workers', 1),
                           ('production_selection_allowed', True), ('generation_ns', -1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                CG.proof_metrics('transaction', {**report, key: value})
        report['parameters']['num_queries'] = 1
        with self.assertRaises(ValueError):
            CG.proof_metrics('transaction', report)


if __name__ == '__main__':
    unittest.main()
