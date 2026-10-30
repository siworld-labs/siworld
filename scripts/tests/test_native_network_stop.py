"""Synthetic guarded-stop contracts; these tests never launch a node or prover."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'native-network-stop.py'
SPEC = importlib.util.spec_from_file_location('native_network_stop', SCRIPT)
STOP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STOP)
WALL = 1_700_000_010_000
RUN = '1' * 64


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NetworkStopTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / 'network'
        self.directory.mkdir(mode=0o700)
        self.release = self.root / 'release'
        (self.release / 'bin').mkdir(parents=True)
        (self.release / 'libexec').mkdir()
        self.launcher = self.release / 'bin/siworld-native-node'
        self.launcher.write_bytes(b'synthetic baseline launcher')
        self.binary = self.release / 'libexec/siworld-native-node'
        self.binary.write_bytes(b'synthetic immutable executable')
        self.configuration = self.directory / 'engineering-network.bin'
        self.configuration.write_bytes(b'synthetic public rules')
        self.peer_configuration = self.root / 'peer-config.json'
        self.peer_configuration.write_bytes(b'synthetic private peer configuration')
        self.configuration.chmod(0o600)
        self.peer_configuration.chmod(0o600)
        self.runtime = {
            'schema_version': 1, 'run_id': RUN, 'process_id': 123,
            'network_id': '2' * 64, 'binary_sha256': digest(self.binary),
            'configuration_sha256': digest(self.configuration),
            'peer_configuration_sha256': digest(self.peer_configuration),
            'sequence': 8, 'phase': 'networking', 'height': 2, 'tip': '3' * 64,
            'state_fingerprint': '4' * 64, 'cumulative_work': '0' * 127 + '2',
            'state_available': True, 'updated_unix_ms': WALL - 500,
            'started_unix_ms': WALL - 60_000, 'elapsed_monotonic_ms': 60_000,
            'observation_elapsed_ms': 0, 'observation_target_ms': 86_400_000,
            'observation_complete': False, 'pow_attempts': 7,
            'progress_sequence': 9, 'last_progress_elapsed_ms': 59_000,
            'error_code': None,
            'network': {'configured': 1, 'pending': 0, 'connected': 1,
                        'closing': 0, 'disabled': 0, 'workers': 1,
                        'authenticated_connections': 2, 'closed_connections': 1,
                        'mining': False},
        }
        self.status_file = self.directory / 'service-status.json'
        run_directory = self.directory / 'service-runs' / RUN
        run_directory.mkdir(parents=True, mode=0o700)
        (self.directory / 'service-runs').chmod(0o700)
        self.run_file = run_directory / 'run.json'
        self.final_file = run_directory / 'final.json'
        self.save()
        self.save_json(self.run_file, {key: self.runtime[key] for key in STOP.STATUS.RUN_KEYS})
        self.process = (12345, True)
        self.process_patch = patch.object(STOP, 'process_identity', side_effect=lambda *_: self.process)
        self.process_patch.start()
        self.addCleanup(self.process_patch.stop)
        self.status_patch = patch.object(STOP.STATUS, 'verify_process', return_value=None)
        self.status_patch.start()
        self.addCleanup(self.status_patch.stop)
        self.wall_patch = patch.object(STOP.STATUS.time, 'time_ns', return_value=WALL * 1_000_000)
        self.wall_patch.start()
        self.addCleanup(self.wall_patch.stop)
        self.commands = []
        self.replay = {'schema': 1, 'height': 3, 'tip': '5' * 64,
                       'state_fingerprint': '6' * 64, 'proof_replay_checked': True,
                       'local_reward_receipts_checked': 2,
                       'validation_scope': 'indexed-local-rewards'}

    def save_json(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def save(self):
        self.save_json(self.status_file, self.runtime)

    def finish(self):
        self.runtime.update(sequence=10, phase='stopped', height=3,
                            tip='5' * 64, state_fingerprint='6' * 64,
                            cumulative_work='0' * 127 + '3')
        self.save()
        self.save_json(self.final_file, self.runtime)
        self.process = None

    def command(self, arguments, deadline, monitor):
        self.commands.append(arguments)
        monitor()
        if arguments[1] == 'stop':
            self.finish()
            return b''
        self.assertEqual(arguments[1:], ['check', str(self.directory), '--json'])
        return json.dumps(self.replay).encode()

    def stop(self, **overrides):
        arguments = dict(network_dir=self.directory, launcher=self.launcher, binary=self.binary,
                         configuration=self.configuration, peer_configuration=self.peer_configuration,
                         expected_pid=123, expected_run_id=RUN, timeout_seconds=5)
        arguments.update(overrides)
        with patch.object(STOP, 'run_command', side_effect=self.command):
            return STOP.stop_network(**arguments)

    def test_exact_run_stop_wait_and_independent_replay_are_required(self):
        result = self.stop()
        self.assertEqual(self.commands, [
            [str(self.launcher.resolve()), 'stop', str(self.directory), RUN],
            [str(self.launcher.resolve()), 'check', str(self.directory), '--json']])
        self.assertEqual(result['state'], 'stopped_verified')
        self.assertEqual(result['height'], 3)
        self.assertEqual(result['local_reward_receipts_checked'], 2)
        self.assertFalse(result['process_exit_code_verified'])
        self.assertFalse(result['observation_qualified'])
        self.assertNotIn(str(self.directory), json.dumps(result))

    def test_final_receipt_does_not_allow_replay_before_owned_worker_exits(self):
        finish = self.finish
        def pending_exit():
            finish()
            self.process = (12345, True)
        def exited(_):
            self.assertEqual(len(self.commands), 1)
            self.process = None
        with patch.object(self, 'finish', side_effect=pending_exit), \
                patch.object(STOP.time, 'sleep', side_effect=exited) as waited:
            self.assertEqual(self.stop()['state'], 'stopped_verified')
        waited.assert_called_once()

    def test_explicit_expected_run_and_exact_package_mapping_are_required(self):
        for override in ({'expected_run_id': None}, {'expected_run_id': 'A' * 64},
                         {'expected_run_id': 'a' * 64}, {'expected_pid': 124},
                         {'launcher': self.binary}):
            with self.subTest(override=override), self.assertRaises(STOP.STATUS.StatusError):
                self.stop(**override)
        self.assertEqual(self.commands, [])

    def test_replacement_run_or_pid_never_receives_a_stop_request(self):
        original = self.command
        def changed(arguments, deadline, monitor):
            self.runtime['run_id'] = 'a' * 64
            self.save()
            monitor()
            return original(arguments, deadline, monitor)
        with patch.object(self, 'command', side_effect=changed), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'run_identity_changed'):
            self.stop()
        self.assertEqual(self.commands, [])

    def test_process_start_reuse_is_rejected_even_with_same_pid_and_binary(self):
        def changed(arguments, deadline, monitor):
            self.process = (12346, True)
            monitor()
            return b''
        with patch.object(self, 'command', side_effect=changed), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'process_identity_changed'):
            self.stop()

    def test_changed_launcher_worker_rules_peers_or_run_receipt_fail_closed(self):
        for path in (self.launcher, self.binary, self.configuration, self.peer_configuration, self.run_file):
            original = path.read_bytes()
            def changed(arguments, deadline, monitor):
                path.write_bytes(original + b'changed')
                monitor()
                return b''
            with self.subTest(path=path.name), patch.object(self, 'command', side_effect=changed), \
                    self.assertRaisesRegex(STOP.STATUS.StatusError, 'frozen_artifact_changed'):
                self.stop()
            path.write_bytes(original)

    def test_replacing_runtime_directory_with_a_symlink_is_rejected(self):
        retained = self.root / 'retained-network'
        def changed(arguments, deadline, monitor):
            self.directory.rename(retained)
            self.directory.symlink_to(retained, target_is_directory=True)
            monitor()
            return b''
        try:
            with patch.object(self, 'command', side_effect=changed), \
                    self.assertRaisesRegex(STOP.STATUS.StatusError, 'directory_shape'):
                self.stop()
        finally:
            if self.directory.is_symlink():
                self.directory.unlink()
                retained.rename(self.directory)

    def test_failure_or_missing_state_in_final_is_not_success(self):
        finish = self.finish
        for change in ({'phase': 'error', 'error_code': 'service_failed'},
                       {'state_available': False}, {'run_id': 'a' * 64}, {'phase': 'stopping'}):
            def bad_final():
                finish()
                final = dict(self.runtime)
                final.update(change)
                self.save_json(self.final_file, final)
            with self.subTest(change=change), patch.object(self, 'finish', side_effect=bad_final), \
                    self.assertRaises(STOP.STATUS.StatusError):
                self.stop()
            self.runtime.update(phase='networking', state_available=True, run_id=RUN,
                                error_code=None)
            self.save()
            self.process = (12345, True)

    def test_final_status_disagreement_and_backward_sequence_are_rejected(self):
        finish = self.finish
        for change in ({'tip': 'a' * 64}, {'sequence': 7}):
            def changed_final():
                finish()
                value = dict(self.runtime)
                value.update(change)
                self.save_json(self.final_file, value)
            with self.subTest(change=change), patch.object(self, 'finish', side_effect=changed_final), \
                    self.assertRaises(STOP.STATUS.StatusError):
                self.stop()
            self.runtime.update(phase='networking', sequence=8)
            self.save()
            self.process = (12345, True)

    def test_replay_schema_head_and_explicit_reward_checks_are_required(self):
        original = dict(self.replay)
        for key, value in (('schema', True), ('height', True), ('height', 4),
                           ('tip', 'a' * 64), ('state_fingerprint', 'a' * 64),
                           ('proof_replay_checked', False), ('local_reward_receipts_checked', True),
                           ('validation_scope', 'unchecked'), ('private_data', 'must-not-escape')):
            self.replay = dict(original)
            self.replay[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(STOP.STATUS.StatusError):
                self.stop()
            self.runtime.update(phase='networking', sequence=8)
            self.save()
            self.process = (12345, True)

    def test_empty_malformed_duplicate_and_nonfinite_replay_output_is_rejected(self):
        final = {'height': 3, 'tip': '5' * 64, 'state_fingerprint': '6' * 64}
        for data in (b'', b'not-json', b'{"schema":1,"schema":1}', b'{"schema":NaN}'):
            with self.subTest(data=data), self.assertRaisesRegex(STOP.STATUS.StatusError, 'replay_schema'):
                STOP.parse_check(data, final)

    def test_network_stop_rejects_legacy_reward_scope_even_with_matching_empty_head(self):
        final = {'height': 0, 'tip': '5' * 64, 'state_fingerprint': '6' * 64}
        replay = dict(self.replay, height=0, local_reward_receipts_checked=0,
                      validation_scope='strict-legacy-rewards')
        with self.assertRaisesRegex(STOP.STATUS.StatusError, 'replay_schema'):
            STOP.parse_check(json.dumps(replay).encode(), final)

    def test_immutable_final_receipt_cannot_be_changed_during_replay(self):
        original = self.command
        def changed(arguments, deadline, monitor):
            result = original(arguments, deadline, monitor)
            if arguments[1] == 'check':
                self.final_file.write_text(self.final_file.read_text() + ' ')
            return result
        with patch.object(self, 'command', side_effect=changed), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'frozen_artifact_changed'):
            self.stop()

    def test_replacement_during_offline_replay_cannot_be_adopted(self):
        original = self.command
        def changed(arguments, deadline, monitor):
            result = original(arguments, deadline, monitor)
            if arguments[1] == 'check':
                self.runtime['run_id'] = 'a' * 64
                self.save()
            return result
        with patch.object(self, 'command', side_effect=changed), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'run_identity_changed'):
            self.stop()

    def test_stale_export_and_dead_owned_process_fail_before_command(self):
        self.runtime['updated_unix_ms'] = WALL - 15_001
        self.save()
        with self.assertRaisesRegex(STOP.STATUS.StatusError, 'live_service_required'):
            self.stop()
        self.runtime['updated_unix_ms'] = WALL
        self.save()
        self.process = None
        with self.assertRaisesRegex(STOP.STATUS.StatusError, 'live_service_required'):
            self.stop()
        self.assertEqual(self.commands, [])

    def test_timeout_preserves_owned_process_and_all_runtime_data(self):
        before = {path: path.read_bytes() for path in self.directory.rglob('*') if path.is_file()}
        def no_progress(arguments, deadline, monitor):
            self.commands.append(arguments)
            return b''
        clock = iter([0, 0, 6])
        with patch.object(self, 'command', side_effect=no_progress), \
                patch.object(STOP.time, 'monotonic', side_effect=lambda: next(clock)), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'stop_deadline_operator_review'):
            self.stop()
        after = {path: path.read_bytes() for path in self.directory.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(self.process, (12345, True))
        self.assertEqual(len(self.commands), 1)

    def test_process_probe_requires_exact_linux_lifetime_and_worker(self):
        self.process_patch.stop()
        process = self.root / 'proc/123'
        process.mkdir(parents=True)
        record = '123 (synthetic worker) S ' + ' '.join(['0'] * 18 + ['12345'] + ['0'] * 5)
        (process / 'stat').write_text(record)
        (process / 'exe').symlink_to(self.binary)
        with patch.object(STOP.sys, 'platform', 'linux'):
            self.assertEqual(STOP.process_identity(123, self.binary, self.root / 'proc'), (12345, True))
            (process / 'stat').write_text(record.replace(') S ', ') Z '))
            self.assertEqual(STOP.process_identity(123, self.binary, self.root / 'proc'), (12345, False))
            (process / 'stat').unlink()
            self.assertIsNone(STOP.process_identity(123, self.binary, self.root / 'proc'))

    def test_cli_error_is_static_and_never_emits_private_arguments(self):
        output = io.StringIO()
        with patch.object(STOP.sys, 'argv', ['native-network-stop.py', '--private-marker']), \
                patch.object(STOP.sys, 'stdout', output):
            self.assertEqual(STOP.main(), 1)
        value = json.loads(output.getvalue())
        self.assertEqual(value['diagnostic'], 'arguments_invalid')
        self.assertTrue(value['operator_review_required'])
        self.assertNotIn('private-marker', output.getvalue())


class CommandTests(unittest.TestCase):
    def command(self, output=b'', returncode=0, running=False):
        class Process:
            def poll(self):
                return None if running else returncode
            def kill(self):
                raise AssertionError('must not kill')
            def terminate(self):
                raise AssertionError('must not signal')
            def wait(self, *args, **kwargs):
                raise AssertionError('must not block waiting')
        def launch(arguments, **kwargs):
            self.assertNotIn('shell', kwargs)
            self.assertNotIn('preexec_fn', kwargs)
            kwargs['stdout'].write(output)
            kwargs['stdout'].flush()
            return Process()
        return patch.object(STOP.subprocess, 'Popen', side_effect=launch)

    def test_success_captures_bounded_output_and_checks_monitor(self):
        checked = []
        with self.command(b'{"schema":1}'), patch.object(STOP.time, 'monotonic', return_value=0):
            result = STOP.run_command(['synthetic-command'], 1, lambda: checked.append(True))
        self.assertEqual(result, b'{"schema":1}')
        self.assertTrue(checked)

    def test_nonzero_excessive_output_and_spawn_errors_are_static(self):
        for output, code, diagnostic in ((b'private-marker', 1, 'command_failed_operator_review'),
                                          (b'x' * 65_537, 0, 'command_output_operator_review')):
            with self.subTest(code=code), self.command(output, code), \
                    patch.object(STOP.time, 'monotonic', return_value=0), \
                    self.assertRaisesRegex(STOP.STATUS.StatusError, diagnostic):
                STOP.run_command(['synthetic-command'], 1, lambda: None)
        with patch.object(STOP.subprocess, 'Popen', side_effect=OSError('private-marker')), \
                patch.object(STOP.time, 'monotonic', return_value=0), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'command_spawn_operator_review'):
            STOP.run_command(['synthetic-command'], 1, lambda: None)

    def test_command_deadline_does_not_kill_terminate_or_wait(self):
        with self.command(running=True), \
                patch.object(STOP.time, 'monotonic', side_effect=[0, 2]), \
                patch.object(STOP.time, 'sleep'), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'command_deadline_operator_review'):
            STOP.run_command(['synthetic-command'], 1, lambda: None)

    def test_command_completion_after_deadline_is_not_accepted(self):
        with self.command(), patch.object(STOP.time, 'monotonic', side_effect=[0, 2]), \
                self.assertRaisesRegex(STOP.STATUS.StatusError, 'command_deadline_operator_review'):
            STOP.run_command(['synthetic-command'], 1, lambda: None)


if __name__ == '__main__':
    unittest.main()
