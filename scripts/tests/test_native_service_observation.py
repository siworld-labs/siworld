"""Observation safety tests with synthetic status files and clocks."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'observe-native-service.py'
SPEC = importlib.util.spec_from_file_location('native_observation', SCRIPT)
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)
WALL = 1_700_000_000_000


def status(ms=0, **changes):
    value = {'schema_version': 1, 'run_id': '1' * 64, 'process_id': 123,
             'network_id': '2' * 64, 'binary_sha256': '3' * 64,
             'configuration_sha256': '4' * 64, 'sequence': ms // 5000 + 1,
             'phase': 'mining', 'height': ms // 300000,
             'tip': format(ms // 300000, '064x'),
             'cumulative_work': format(ms // 300000, '0128x'),
             'state_fingerprint': format(ms // 300000, '064x'),
             'state_available': True, 'updated_unix_ms': WALL + ms,
             'started_unix_ms': WALL, 'elapsed_monotonic_ms': ms + 100,
             'observation_elapsed_ms': ms + 1, 'observation_target_ms': OBS.TARGET_MS,
             'observation_complete': ms >= OBS.TARGET_MS,
             'error_code': None, 'pow_attempts': ms + 1,
             'progress_sequence': ms // 5000 + 1, 'last_progress_elapsed_ms': ms + 100}
    value.update(changes)
    return value


def event(**changes):
    value = {'schema_version': 1, 'run_id': '1' * 64, 'sequence': 1,
             'event': 'block_accepted', 'height': 1, 'tip': '5' * 64,
             'elapsed_monotonic_ms': 1000, 'error_code': None}
    value.update(changes)
    return value


class WindowTests(unittest.TestCase):
    def window(self, **kwargs):
        return OBS.Window(status(), 'process-identity', 0, WALL, **kwargs)

    def observe(self, window, ms, **changes):
        return window.observe(status(ms, **changes), 'process-identity', ms, WALL + ms, 123456)

    def test_full_real_monotonic_window_and_final_replay_remains_required(self):
        window = self.window()
        for ms in range(5000, OBS.TARGET_MS + 1, 5000):
            result = self.observe(window, ms)
            self.assertEqual(result['observation_complete'], ms == OBS.TARGET_MS)
        self.assertEqual(result['elapsed_observed_ms'], 86_400_000)
        self.assertTrue(result['final_replay_required'])
        self.assertEqual(result['sampled_peak_rss_bytes'], 123456)

    def test_service_completion_and_wall_clock_cannot_accelerate_observer(self):
        window = self.window()
        current = status(5000, updated_unix_ms=WALL + OBS.TARGET_MS,
                         elapsed_monotonic_ms=OBS.TARGET_MS + 100,
                         observation_elapsed_ms=OBS.TARGET_MS, observation_complete=True)
        result = window.observe(current, 'process-identity', 5000, WALL + OBS.TARGET_MS, 1)
        self.assertFalse(result['observation_complete'])
        self.assertEqual(result['elapsed_observed_ms'], 5000)

    def test_observer_sampling_gap_cannot_backfill_elapsed_time(self):
        with self.assertRaisesRegex(OBS.ObservationError, 'observation_gap'):
            self.observe(self.window(), 60_000)

    def test_restart_artifact_network_and_pid_changes_are_rejected(self):
        changes = {'run_id': 'a' * 64, 'process_id': 124, 'network_id': 'a' * 64,
                   'binary_sha256': 'a' * 64, 'configuration_sha256': 'a' * 64,
                   'started_unix_ms': WALL + 1}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaisesRegex(OBS.ObservationError, 'service_identity_changed'):
                self.observe(self.window(), 5000, **{key: value})
        with self.assertRaisesRegex(OBS.ObservationError, 'process_identity_changed'):
            self.window().observe(status(5000), 'reused-pid', 5000, WALL + 5000, 1)

    def test_stale_heartbeat_and_stopped_or_error_service_are_rejected(self):
        window = self.window()
        for ms in (5000, 10000, 15000):
            self.observe(window, ms, sequence=1)
        with self.assertRaisesRegex(OBS.ObservationError, 'heartbeat_stalled'):
            self.observe(window, 20000, sequence=1)
        for phase in ('stopped', 'stopping', 'error'):
            with self.subTest(phase=phase), self.assertRaisesRegex(OBS.ObservationError, 'service_failed_or_stopped'):
                self.observe(self.window(), 5000, phase=phase)

    def test_same_height_state_change_and_regressions_fail(self):
        for changes, code in (({'tip': 'e' * 64}, 'same_height_state_changed'),
                              ({'state_fingerprint': 'e' * 64}, 'same_height_state_changed'),
                              ({'progress_sequence': 0}, 'status_progress_regressed'),
                              ({'pow_attempts': 0}, 'status_progress_regressed')):
            with self.subTest(changes=changes), self.assertRaisesRegex(OBS.ObservationError, code):
                self.observe(self.window(), 5000, **changes)

    def test_long_stochastic_block_gap_is_healthy_with_real_pow_progress(self):
        window = self.window()
        for ms in range(5000, 3_600_001, 5000):
            result = self.observe(window, ms, height=0, tip='0' * 64,
                                  cumulative_work='0' * 128, state_fingerprint='0' * 64)
        self.assertEqual(result['state'], 'observing')

    def test_two_hour_accepted_height_stall_fails_despite_fresh_pow_progress(self):
        window = self.window()
        for ms in range(5000, 7_200_000, 5000):
            self.observe(window, ms, height=0, tip='0' * 64,
                         cumulative_work='0' * 128, state_fingerprint='0' * 64)
        with self.assertRaisesRegex(OBS.ObservationError, 'accepted_height_stalled'):
            self.observe(window, 7_200_000, height=0, tip='0' * 64,
                         cumulative_work='0' * 128, state_fingerprint='0' * 64)

    def test_accepted_block_resets_the_operational_gap(self):
        window = self.window()
        for ms in range(5000, 10_800_001, 5000):
            height = 0 if ms < 5_400_000 else 1
            result = self.observe(window, ms, height=height, tip=format(height, '064x'),
                                  cumulative_work=format(height, '0128x'),
                                  state_fingerprint=format(height, '064x'))
        self.assertEqual(result['state'], 'observing')

    def test_startup_does_not_start_ready_observation_or_accepted_height_clock(self):
        initial = status(observation_elapsed_ms=0, phase='starting', state_available=False)
        window = OBS.Window(initial, 'process-identity', 0, WALL)
        for ms in range(5000, 7_200_001, 5000):
            current = status(ms, height=0, tip='0' * 64, cumulative_work='0' * 128,
                             state_fingerprint='0' * 64, observation_elapsed_ms=0,
                             phase='preparing', state_available=False)
            result = window.observe(current, 'process-identity', ms, WALL + ms, 1)
        self.assertEqual(result['elapsed_observed_ms'], 0)
        current = status(7_205_000, observation_elapsed_ms=1)
        result = window.observe(current, 'process-identity', 7_205_000, WALL + 7_205_000, 1)
        self.assertEqual(result['elapsed_observed_ms'], 0)

    def test_fresh_heartbeat_without_work_progress_eventually_fails(self):
        window = self.window()
        for ms in range(5000, OBS.PROGRESS_STALE_MS + 1, 5000):
            self.observe(window, ms, progress_sequence=1, pow_attempts=1, last_progress_elapsed_ms=100)
        with self.assertRaisesRegex(OBS.ObservationError, 'work_progress_stalled'):
            self.observe(window, OBS.PROGRESS_STALE_MS + 5000,
                         progress_sequence=1, pow_attempts=1, last_progress_elapsed_ms=100)

    def test_cgroup_oom_counter_increase_fails(self):
        window = self.window(oom={'oom': 0, 'oom_kill': 0})
        with self.assertRaisesRegex(OBS.ObservationError, 'cgroup_oom_counter_changed'):
            window.observe(status(5000), 'process-identity', 5000, WALL + 5000,
                           1, {'oom': 1, 'oom_kill': 0})

    def test_new_collector_does_not_credit_old_service_time(self):
        late = status(43_200_000)
        window = OBS.Window(late, 'process-identity', 100, WALL + 43_200_000)
        result = window.observe(status(43_205_000), 'process-identity', 5100,
                                WALL + 43_205_000, 1)
        self.assertEqual(result['elapsed_observed_ms'], 5000)

    def test_schema_rejects_private_fields_invalid_types_and_short_targets(self):
        for changes in ({'private_opening': 'excluded'}, {'height': True},
                        {'observation_target_ms': 1000}, {'error_code': '/private/untrusted'},
                        {'observation_complete': True}, {'phase': []}):
            with self.subTest(changes=changes), self.assertRaises(OBS.ObservationError):
                OBS.validate_status(status(**changes))


class EvidenceTests(unittest.TestCase):
    def test_saved_observing_summary_must_be_fresh_for_followup(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            OBS.write_json(directory / 'summary.json', {
                'schema_version': 1, 'state': 'observing', 'observation_complete': False,
                'updated_unix_ms': WALL, 'observer_process_id': 123})
            with mock.patch.object(OBS.sys, 'argv', [str(SCRIPT), 'inspect', '--output', str(directory)]), \
                    mock.patch.object(OBS.time, 'time_ns', return_value=(WALL + OBS.STALE_MS + 1) * 1_000_000):
                with self.assertRaisesRegex(OBS.ObservationError, 'observer_summary_stale'):
                    OBS.main()

    def test_private_atomic_summary_and_append_keep_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            summary = directory / 'summary.json'
            OBS.write_json(summary, {'state': 'observing'})
            OBS.write_json(summary, {'state': 'incomplete'})
            self.assertEqual(OBS.read_json(summary), {'state': 'incomplete'})
            self.assertEqual(summary.stat().st_mode & 0o777, 0o600)
            journal = directory / 'journal.jsonl'
            OBS.append_json(journal, {'sequence': 1})
            OBS.append_json(journal, {'sequence': 2})
            self.assertEqual(len(journal.read_text().splitlines()), 2)
            self.assertEqual(journal.stat().st_mode & 0o777, 0o600)

    def test_symlink_world_readable_and_duplicate_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / 'target'
            target.write_text('{}')
            os.chmod(target, 0o600)
            link = directory / 'link'
            link.symlink_to(target)
            with self.assertRaisesRegex(OBS.ObservationError, 'private_file_required'):
                OBS.read_json(link)
            os.chmod(target, 0o644)
            with self.assertRaisesRegex(OBS.ObservationError, 'private_file_required'):
                OBS.read_json(target)
        with self.assertRaisesRegex(OBS.ObservationError, 'duplicate_json_key'):
            OBS.decode_json('{"height":1,"height":2}')

    def test_events_preserve_partial_line_and_reject_truncation_replacement_and_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'service-events.jsonl'
            OBS.append_json(path, event())
            reader = OBS.EventReader(path, '1' * 64)
            self.assertEqual(len(reader.read()), 1)
            with path.open('ab') as stream:
                stream.write(json.dumps(event(sequence=2)).encode())
            self.assertEqual(reader.read(), [])
            with path.open('ab') as stream:
                stream.write(b'\n')
            self.assertEqual(reader.read()[0]['sequence'], 2)
            path.write_text('')
            with self.assertRaisesRegex(OBS.ObservationError, 'event_file_truncated'):
                reader.read()
            OBS.append_json(path, event(event='service_error', error_code='proof_failed'))
            with self.assertRaisesRegex(OBS.ObservationError, 'service_event_failure'):
                OBS.EventReader(path, '1' * 64).read()
            replacement = path.with_name('replacement')
            OBS.append_json(replacement, event())
            os.replace(replacement, path)
            with self.assertRaisesRegex(OBS.ObservationError, 'event_file_replaced'):
                reader.read()

    def test_previous_run_events_do_not_satisfy_or_fail_current_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'service-events.jsonl'
            OBS.append_json(path, event(run_id='f' * 64, event='service_error', error_code='old_failure'))
            OBS.append_json(path, event())
            result = OBS.EventReader(path, '1' * 64).read()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['run_id'], '1' * 64)

    def test_process_owner_uses_os_identity_and_executable(self):
        def ps(arguments, **_):
            value = str(SCRIPT) if arguments[-1] == 'comm=' else 'fixed process start identity'
            return OBS.subprocess.CompletedProcess(arguments, 0, value, '')
        with mock.patch.object(OBS.sys, 'platform', 'darwin'), mock.patch.object(OBS.subprocess, 'run', side_effect=ps):
            value = OBS.process_identity(123, SCRIPT)
            self.assertRegex(value, '^[0-9a-f]{64}$')
            with self.assertRaisesRegex(OBS.ObservationError, 'process_executable_mismatch'):
                OBS.process_identity(123, Path(__file__))


if __name__ == '__main__':
    unittest.main()
