"""Read-only network health checks against synthetic current-schema exports."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'native-network-status.py'
SPEC = importlib.util.spec_from_file_location('native_network_status', SCRIPT)
STATUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATUS)
WALL = 1_700_000_010_000
RUN = '1' * 64


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NetworkStatusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / 'network'
        self.directory.mkdir(mode=0o700)
        self.binary = self.root / 'siworld-native-node'
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
        self.save()
        self.process = patch.object(STATUS, 'verify_process', return_value=None)
        self.process_check = self.process.start()
        self.addCleanup(self.process.stop)

    def save(self, receipt=True):
        self.status_file.write_text(json.dumps(self.runtime))
        self.status_file.chmod(0o600)
        if receipt:
            self.run_file.write_text(json.dumps({key: self.runtime[key] for key in STATUS.RUN_KEYS}))
            self.run_file.chmod(0o600)

    def read(self, **overrides):
        arguments = dict(network_dir=self.directory, binary=self.binary,
                         configuration=self.configuration,
                         peer_configuration=self.peer_configuration,
                         expected_pid=123, expected_run_id=RUN, now_ms=WALL)
        arguments.update(overrides)
        return STATUS.inspect_status(**arguments)

    def test_current_network_schema_is_live_without_claiming_replay_or_soak(self):
        result = self.read()
        self.assertEqual(result['state'], 'ready')
        self.assertTrue(result['live'])
        self.assertEqual(result['height'], 2)
        self.assertEqual(result['network']['connected'], 1)
        self.assertEqual(result['reward_health'], 'requires_independent_replay')
        self.assertFalse(result['observation_qualified'])
        self.process_check.assert_called_once_with(123, self.binary)

    def test_optional_supply_and_resource_objects_are_not_forwarded(self):
        self.runtime.update(supply={'internal_marker': 'must-not-escape'},
                            process_resources={'private_path': 'must-not-escape'})
        self.save()
        result = self.read()
        self.assertEqual(result['state'], 'ready')
        self.assertNotIn('must-not-escape', json.dumps(result))
        self.assertNotIn('supply', result)
        self.assertNotIn('process_resources', result)
        for name in ('supply', 'process_resources'):
            self.runtime[name] = 'invalid extension shape'
            self.save()
            with self.assertRaisesRegex(STATUS.StatusError, 'status_schema'):
                self.read()
            self.runtime[name] = {}

    def test_expected_process_and_run_and_immutable_receipt_must_match(self):
        with self.assertRaisesRegex(STATUS.StatusError, 'expected_process_mismatch'):
            self.read(expected_pid=124)
        with self.assertRaisesRegex(STATUS.StatusError, 'expected_run_mismatch'):
            self.read(expected_run_id='a' * 64)
        self.runtime['started_unix_ms'] -= 1
        self.save(receipt=False)
        with self.assertRaisesRegex(STATUS.StatusError, 'run_receipt_mismatch'):
            self.read()

    def test_binary_rules_and_peer_configuration_are_bound_to_the_run(self):
        for path in (self.binary, self.configuration, self.peer_configuration):
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            with self.subTest(path=path.name), self.assertRaisesRegex(STATUS.StatusError, 'artifact_hash_mismatch'):
                self.read()
            path.write_bytes(original)

    def test_stale_future_and_unavailable_process_exports_never_report_ready(self):
        self.runtime['updated_unix_ms'] = WALL - 15_001
        self.save()
        self.assertEqual(self.read()['state'], 'stale')
        self.runtime['updated_unix_ms'] = WALL + 1
        self.save()
        with self.assertRaisesRegex(STATUS.StatusError, 'status_clock_mismatch'):
            self.read()
        self.runtime['updated_unix_ms'] = WALL
        self.save()
        self.process_check.side_effect = STATUS.StatusError('process_unavailable')
        with self.assertRaisesRegex(STATUS.StatusError, 'process_unavailable'):
            self.read()

    def test_stopped_and_error_exports_are_distinct_and_do_not_probe_dead_processes(self):
        for phase, code in (('stopped', None), ('error', 'service_operation_failed')):
            self.runtime.update(phase=phase, error_code=code, updated_unix_ms=WALL - 60_000)
            self.save()
            result = self.read()
            self.assertEqual(result['state'], phase)
            self.assertFalse(result['live'])
            self.assertEqual(result['reward_health'], 'requires_independent_replay')
        self.process_check.assert_not_called()

    def test_starting_and_disconnected_network_are_not_ready(self):
        self.runtime.update(phase='starting', network=None, state_available=False)
        self.save()
        self.assertEqual(self.read()['state'], 'starting')
        self.runtime.update(phase='networking', state_available=True)
        self.runtime['network'] = {'configured': 1, 'pending': 1, 'connected': 0,
                                  'closing': 0, 'disabled': 0, 'workers': 1,
                                  'authenticated_connections': 0, 'closed_connections': 0,
                                  'mining': True}
        self.save()
        result = self.read()
        self.assertEqual(result['state'], 'degraded')
        self.assertEqual(result['diagnostic'], 'no_authenticated_peers')

    def test_malformed_oversized_unknown_or_noncanonical_exports_fail_closed(self):
        for payload in (b'not-json', b' ' * 65_537,
                        b'{"schema_version":1,"schema_version":1}',
                        b'{"unsupported":NaN}'):
            self.status_file.write_bytes(payload)
            with self.subTest(payload=payload[:30]), self.assertRaises(STATUS.StatusError):
                self.read()
        self.save()
        self.runtime['private_unexpected_field'] = 'must-not-escape'
        self.save()
        with self.assertRaisesRegex(STATUS.StatusError, 'status_schema'):
            self.read()

    def test_noncanonical_field_types_and_receipt_booleans_are_rejected(self):
        for key, value in (('phase', []), ('height', True), ('network', [])):
            original = self.runtime[key]
            self.runtime[key] = value
            self.save()
            with self.subTest(key=key), self.assertRaises(STATUS.StatusError):
                self.read()
            self.runtime[key] = original
        self.save()
        receipt = json.loads(self.run_file.read_text())
        receipt['schema_version'] = True
        self.run_file.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(STATUS.StatusError, 'run_receipt_mismatch'):
            self.read()

    def test_symlink_status_receipt_binary_and_configuration_are_rejected(self):
        for path in (self.status_file, self.run_file, self.binary,
                     self.configuration, self.peer_configuration):
            target = path.with_name(path.name + '.target')
            path.rename(target)
            path.symlink_to(target)
            with self.subTest(path=path.name), self.assertRaisesRegex(STATUS.StatusError, 'file_shape'):
                self.read()
            path.unlink()
            target.rename(path)

    def test_public_permissions_hard_links_and_network_field_leaks_are_rejected(self):
        self.status_file.chmod(0o644)
        with self.assertRaisesRegex(STATUS.StatusError, 'private_file_required'):
            self.read()
        self.status_file.chmod(0o600)
        alias = self.directory / 'status-alias'
        os.link(self.status_file, alias)
        with self.assertRaisesRegex(STATUS.StatusError, 'file_shape'):
            self.read()
        alias.unlink()
        self.runtime['network']['endpoint'] = 'must-not-escape'
        self.save()
        with self.assertRaisesRegex(STATUS.StatusError, 'network_schema'):
            self.read()

    def test_status_never_opens_database_receipts_or_changes_runtime_files(self):
        forbidden = self.directory / 'chain.redb'
        forbidden.write_bytes(b'not a database; opening it would fail')
        private = self.directory / 'reward-synthetic.secret'
        private.write_bytes(b'private sentinel')
        before = {path: path.read_bytes() for path in self.directory.rglob('*') if path.is_file()}
        self.read()
        after = {path: path.read_bytes() for path in self.directory.rglob('*') if path.is_file()}
        self.assertEqual(before, after)

    def test_linux_process_probe_checks_the_executable_and_process_lifetime(self):
        self.process.stop()
        process_root = self.root / 'proc'
        process = process_root / '123'
        process.mkdir(parents=True)
        record = '123 (synthetic worker) S ' + ' '.join(['0'] * 18 + ['12345'] + ['0'] * 5)
        (process / 'stat').write_text(record)
        (process / 'exe').symlink_to(self.binary)
        with patch.object(STATUS.sys, 'platform', 'linux'):
            STATUS.verify_process(123, self.binary, process_root)
            wrong = self.root / 'different-executable'
            wrong.write_bytes(b'synthetic different executable')
            with self.assertRaisesRegex(STATUS.StatusError, 'process_identity_mismatch'):
                STATUS.verify_process(123, wrong, process_root)
            with patch.object(Path, 'read_text', side_effect=[record, record.replace('12345', '12346')]):
                with self.assertRaisesRegex(STATUS.StatusError, 'process_identity_mismatch'):
                    STATUS.verify_process(123, self.binary, process_root)

    def test_cli_errors_have_static_diagnostics_without_paths_or_exception_text(self):
        output = io.StringIO()
        with patch.object(STATUS.sys, 'argv', ['native-network-status.py', '--invalid-private-marker']), \
                patch.object(STATUS.sys, 'stdout', output):
            self.assertEqual(STATUS.main(), 1)
        value = json.loads(output.getvalue())
        self.assertEqual(value['diagnostic'], 'arguments_invalid')
        self.assertNotIn('private-marker', output.getvalue())


if __name__ == '__main__':
    unittest.main()
