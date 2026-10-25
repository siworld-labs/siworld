"""Reject limit events and escaped/living descendants even when exit is zero."""
import importlib.util
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
