"""Reject limit events and escaped/living descendants even when exit is zero."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('cg', Path(__file__).parents[1] / 'measure-proof-cgroup.py')
CG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CG)


class CgroupAssessmentTests(unittest.TestCase):
    def test_event_or_lifetime_peak_failure_cannot_be_hidden(self):
        before = {'max': 0, 'oom': 0, 'oom_kill': 0}
        for event in before:
            after = dict(before, **{event: 1})
            self.assertFalse(CG.assess(before, after, 100, 0, 0, False, [])['resource_control_pass'])
        for peak, swap, code, timeout, remaining in [
                (CG.BUDGET + 1, 0, 0, False, []), (0, 0, 0, False, []),
                (100, 1, 0, False, []), (100, 0, 1, False, []),
                (100, 0, 0, True, []), (100, 0, 0, False, ['123'])]:
            self.assertFalse(CG.assess(before, before, peak, swap, code, timeout, remaining)['resource_control_pass'])

    def test_resource_pass_is_never_acceptance(self):
        result = CG.assess({'oom': 0}, {'oom': 0}, 100, 0, 0, False, [])
        self.assertTrue(result['resource_control_pass'])
        self.assertFalse(result['acceptance'])

    def test_counter_reset_is_rejected(self):
        with self.assertRaises(ValueError):
            CG.assess({'oom': 1}, {'oom': 0}, 100, 0, 0, False, [])


class HardwareProfileTests(unittest.TestCase):
    def hardware(self, model='AMD EPYC 7763 64-Core Processor'):
        return {'os': 'Ubuntu 24.04', 'architecture': 'x86_64', 'cpu_model': model,
            'avx2': True, 'logical_cpus': 4, 'affinity_cpus': 4,
            'online_logical_cpus': 4, 'exposed_physical_cores': 2,
            'virtualization_detection': {'result': 'microsoft', 'exit_code': 0}}

    def test_baseline_requires_model_topology_vm_and_avx2(self):
        result = CG.qualify_hardware_profile(self.hardware(), 'epyc7763-baseline')
        self.assertTrue(result['profile_qualified'])
        self.assertEqual(result['role'], 'baseline')
        self.assertFalse(result['same_physical_instance_established'])
        for changed in (
                {'cpu_model': 'AMD EPYC 9V45 96-Core Processor'},
                {'cpu_model': 'Example 7763 CPU'}, {'exposed_physical_cores': 4},
                {'logical_cpus': 8}, {'online_logical_cpus': 8}, {'affinity_cpus': 2},
                {'virtualization_detection': {'result': 'none', 'exit_code': 1}},
                {'avx2': False}, {'os': 'Ubuntu 22.04'}, {'architecture': 'aarch64'}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                CG.qualify_hardware_profile({**self.hardware(), **changed}, 'epyc7763-baseline')

    def test_control_identity_is_separate_from_baseline(self):
        hardware = self.hardware('AMD EPYC 9V45 96-Core Processor')
        result = CG.qualify_hardware_profile(hardware, 'epyc9v45-control')
        self.assertEqual(result['role'], 'control')
        self.assertTrue(result['profile_qualified'])
        with self.assertRaises(ValueError):
            CG.qualify_hardware_profile(hardware, 'epyc7763-baseline')
        with self.assertRaises(ValueError):
            CG.qualify_hardware_profile(self.hardware(), 'epyc9v45-control')

    def test_diagnostic_default_cannot_claim_baseline(self):
        result = CG.qualify_hardware_profile(self.hardware(), 'diagnostic')
        self.assertFalse(result['profile_qualified'])
        self.assertEqual(result['role'], 'diagnostic')
        with self.assertRaises(ValueError):
            CG.qualify_hardware_profile(self.hardware(), 'unknown')

    def test_baseline_rejects_reduced_inherited_cpu_quota(self):
        for profile in ('epyc7763-baseline', 'epyc9v45-control'):
            ancestry = [{'cpu_limit': CG.parse_cpu_max('max 100000')},
                        {'cpu_limit': CG.parse_cpu_max('300000 100000')}]
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                CG.qualify_cpu_profile(ancestry, profile)
        CG.qualify_cpu_profile(ancestry, 'diagnostic')
        CG.qualify_cpu_profile([{'cpu_limit': CG.parse_cpu_max('max 100000')}],
                               'epyc7763-baseline')


class CpuMeasurementTests(unittest.TestCase):
    def test_nested_lscpu_preserves_model_and_hypervisor_fields(self):
        fields = CG.lscpu_fields([{'field': 'CPU(s):', 'data': '4', 'children': [
            {'field': 'Model name:', 'data': 'Example CPU'},
            {'field': 'Hypervisor vendor:', 'data': 'Example VM'}]}])
        self.assertEqual(fields['Model name'], 'Example CPU')
        self.assertEqual(fields['Hypervisor vendor'], 'Example VM')

    def test_thread_snapshot_includes_owned_descendant_scopes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            group, proc = base / 'group', base / 'proc'
            (group / 'child').mkdir(parents=True)
            (group / 'cgroup.procs').write_text('100\n999\n')
            (group / 'child' / 'cgroup.procs').write_text('200\n')
            fields = ['R'] + ['0'] * 36
            for pid in ('100', '200'):
                task = proc / pid / 'task' / pid
                task.mkdir(parents=True)
                (task / 'stat').write_text(pid + ' (worker) ' + ' '.join(fields))
            snapshot = CG.thread_snapshot(group, proc)
            self.assertEqual({row['pid'] for row in snapshot['threads']}, {100, 200})
            self.assertEqual(snapshot['exited_during_sample'], 1)

    def test_online_topology_counts_unique_socket_core_pairs(self):
        text = '# CPU,Core,Socket,Online\n0,0,0,Y\n1,0,0,Y\n2,0,1,Y\n3,2,1,N\n'
        self.assertEqual(CG.topology_counts(text), {
            'online_logical_cpus': 3, 'exposed_physical_cores': 2, 'exposed_sockets': 2})

    def test_nested_ancestor_quota_limits_visible_capacity(self):
        with tempfile.TemporaryDirectory() as temporary:
            mount = Path(temporary)
            parent, group = mount / 'parent', mount / 'parent' / 'owned'
            group.mkdir(parents=True)
            for directory, quota in ((mount, 'max 100000'), (parent, '150000 100000'),
                                     (group, 'max 100000')):
                (directory / 'cpu.max').write_text(quota)
                (directory / 'cpu.stat').write_text('usage_usec 100\nnr_periods 10\n')
            ancestry = CG.cpu_ancestry(group, mount)
            result = CG.cpu_summary({'usage_usec': 0, 'nr_periods': 0, 'nr_throttled': 0},
                {'usage_usec': 1500000, 'nr_periods': 10, 'nr_throttled': 2},
                1000000000, ancestry, 4, [], 100)
            self.assertEqual(result['effective_visible_cpu_capacity'], 1.5)
            self.assertEqual(result['capacity_utilization_percent'], 100)
            self.assertEqual(result['throttled_period_percent'], 20)
            self.assertEqual([row['path'] for row in ancestry], [str(group), str(parent), str(mount)])

    def test_invalid_cpu_quota_and_reset_are_rejected(self):
        for value in ('max 0', '0 100000', '-1 100000'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CG.parse_cpu_max(value)
        with self.assertRaises(ValueError):
            CG.counter_delta({'usage_usec': 2}, {'usage_usec': 1})

    def test_thread_stat_handles_spaces_parentheses_and_process_reuse(self):
        fields = ['R'] + ['0'] * 36
        for index, value in ((11, '25'), (12, '8'), (19, '1234'), (36, '3')):
            fields[index] = value
        parsed = CG.parse_thread_stat('42 (a worker (name)) ' + ' '.join(fields))
        self.assertEqual(parsed, {'state': 'R', 'user_ticks': 25, 'system_ticks': 8,
                                 'start_ticks': 1234, 'processor': 3})
        def sample(ticks, epoch):
            return {'process_threads': {'threads': [{'pid': 42, 'tid': 42,
                'start_ticks': epoch, 'user_ticks': ticks, 'system_ticks': 0}]}}
        result = CG.cpu_summary({'usage_usec': 0}, {'usage_usec': 1000000},
            1000000000, [], 2, [sample(100, 1), sample(120, 1), sample(500, 2)], 100)
        self.assertEqual(result['sampled_thread_cpu_seconds_lower_bound'], 0.2)
        self.assertEqual(result['maximum_sampled_active_threads'], 1)

    def test_private_process_and_cgroup_data_are_not_printed(self):
        report = {'schema': 2, 'cpu_summary': {'average_cpu_cores': 1.5},
                  'cgroup_id': 'private-scope', 'hardware_evidence': {'lscpu_text': 'private'},
                  'samples': [{'pid': 123}], 'cpu_ancestry_before': [{'path': '/private'}],
                  'error': 'private/path', 'monotonic_started_ns': 1}
        self.assertEqual(CG.public_summary(report), {
            'schema': 2, 'cpu_summary': {'average_cpu_cores': 1.5}})


if __name__ == '__main__':
    unittest.main()
