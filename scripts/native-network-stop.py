#!/usr/bin/env python3
"""Stop one pinned native peer run and independently replay its final state.

The helper never signals, restarts or repairs a service. A deadline or command
failure requires operator review; an already started command is left untouched.
Successful final evidence does not establish a service-manager exit code or a
continuous observation qualification. Use an immutable versioned release.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


SPEC = importlib.util.spec_from_file_location(
    'native_network_status', Path(__file__).with_name('native-network-status.py'))
STATUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATUS)
POLL_SECONDS = 0.25
CHECK_KEYS = {'schema', 'height', 'tip', 'state_fingerprint', 'proof_replay_checked',
              'local_reward_receipts_checked', 'validation_scope'}


def process_identity(pid, binary, process_root=Path('/proc')):
    """Return Linux start ticks and liveness, or None after the process is gone."""
    STATUS.require(sys.platform.startswith('linux'), 'linux_process_identity_required')
    process = process_root / str(pid)
    try:
        before = (process / 'stat').read_text()
    except FileNotFoundError:
        return None
    except OSError:
        raise STATUS.StatusError('process_unavailable') from None
    try:
        fields = before[before.rfind(')') + 2:].split()
        STATUS.require(len(fields) > 19 and int(before.split(' ', 1)[0]) == pid,
                       'process_identity_changed')
        start = int(fields[19])
        STATUS.require(start > 0, 'process_identity_changed')
        active = fields[0] not in ('Z', 'X')
        if active:
            STATUS.require((process / 'exe').resolve(strict=True) == binary.resolve(strict=True),
                           'process_identity_changed')
        after = (process / 'stat').read_text()
        after_fields = after[after.rfind(')') + 2:].split()
        STATUS.require(len(after_fields) > 19 and int(after_fields[19]) == start,
                       'process_identity_changed')
        return start, after_fields[0] not in ('Z', 'X')
    except STATUS.StatusError:
        raise
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise STATUS.StatusError('process_unavailable') from None


def run_command(arguments, deadline, monitor):
    """Poll a trusted executable without any implicit timeout cancellation.

    Anonymous stdout storage avoids a blocked pipe and bounds memory use. A
    faulty command may retain that descriptor after a deadline; the helper does
    not terminate it. Raw output and stderr are never included in diagnostics.
    """
    STATUS.require(time.monotonic() < deadline, 'command_deadline_operator_review')
    monitor()
    try:
        with tempfile.TemporaryFile() as output:
            try:
                process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=subprocess.DEVNULL,
                                           close_fds=True)
            except OSError:
                raise STATUS.StatusError('command_spawn_operator_review') from None
            while True:
                monitor()
                STATUS.require(time.monotonic() < deadline, 'command_deadline_operator_review')
                STATUS.require(os.fstat(output.fileno()).st_size <= STATUS.MAX_JSON,
                               'command_output_operator_review')
                code = process.poll()
                if code is not None:
                    STATUS.require(code == 0, 'command_failed_operator_review')
                    output.seek(0)
                    result = output.read(STATUS.MAX_JSON + 1)
                    STATUS.require(len(result) <= STATUS.MAX_JSON, 'command_output_operator_review')
                    return result
                remaining = deadline - time.monotonic()
                STATUS.require(remaining > 0, 'command_deadline_operator_review')
                time.sleep(min(POLL_SECONDS, remaining))
    except OSError:
        raise STATUS.StatusError('command_io_operator_review') from None


def parse_check(data, final):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            STATUS.require(key not in result, 'replay_schema')
            result[key] = value
        return result
    def constant(_):
        raise STATUS.StatusError('replay_schema')
    try:
        value = json.loads(data, object_pairs_hook=unique, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, STATUS.StatusError):
            raise
        raise STATUS.StatusError('replay_schema') from None
    STATUS.require(isinstance(value, dict) and set(value) == CHECK_KEYS, 'replay_schema')
    STATUS.require(type(value['schema']) is int and value['schema'] == 1
                   and STATUS.integer(value['height'])
                   and STATUS.hexadecimal(value['tip'])
                   and STATUS.hexadecimal(value['state_fingerprint'])
                   and value['proof_replay_checked'] is True
                   and STATUS.integer(value['local_reward_receipts_checked'])
                   and value['validation_scope'] == 'indexed-local-rewards',
                   'replay_schema')
    STATUS.require(all(value[key] == final[key]
                       for key in ('height', 'tip', 'state_fingerprint')), 'replay_head_mismatch')
    return value


def stop_network(network_dir, launcher, binary, configuration, peer_configuration,
                 expected_pid, expected_run_id, timeout_seconds=600):
    STATUS.require(STATUS.hexadecimal(expected_run_id), 'expected_run_invalid')
    STATUS.require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 3600,
                   'deadline_invalid')
    initial_health = STATUS.inspect_status(network_dir, binary, configuration,
                                           peer_configuration, expected_pid, expected_run_id)
    STATUS.require(initial_health['live'], 'live_service_required')
    # Validate terminal components before canonicalizing the immutable release.
    STATUS.read_file(launcher, 512 * 1024 * 1024, hashing=True)
    try:
        launcher = launcher.resolve(strict=True)
        binary = binary.resolve(strict=True)
        STATUS.require(launcher.name == 'siworld-native-node' and launcher.parent.name == 'bin'
                       and binary == launcher.parent.parent / 'libexec' / launcher.name,
                       'release_mapping_mismatch')
    except OSError:
        raise STATUS.StatusError('release_unavailable') from None
    initial = STATUS.validate_status(STATUS.read_json(network_dir / 'service-status.json'))
    STATUS.require(initial['run_id'] == expected_run_id and initial['process_id'] == expected_pid,
                   'run_identity_changed')
    frozen_run = {key: initial[key] for key in STATUS.RUN_KEYS}
    run_directory = network_dir / 'service-runs' / expected_run_id
    run_file = run_directory / 'run.json'
    directories = []
    for path in (network_dir, network_dir / 'service-runs', run_directory):
        STATUS.private_directory(path)
        metadata = path.lstat()
        directories.append((path, (metadata.st_dev, metadata.st_ino,
                                   metadata.st_uid, metadata.st_mode)))
    receipt = STATUS.read_json(run_file)
    STATUS.require(isinstance(receipt, dict) and set(receipt) == STATUS.RUN_KEYS
                   and all(type(receipt[key]) is type(frozen_run[key])
                           and receipt[key] == frozen_run[key] for key in STATUS.RUN_KEYS),
                   'run_identity_changed')
    artifacts = []
    for path, maximum, private in (
            (launcher, 512 * 1024 * 1024, False),
            (binary, 512 * 1024 * 1024, False),
            (configuration, 1024 * 1024, True),
            (peer_configuration, 1024 * 1024, True),
            (run_file, STATUS.MAX_JSON, True)):
        digest = STATUS.read_file(path, maximum, private=private, hashing=True)
        artifacts.append((path, maximum, private, digest, STATUS.signature(path.lstat())))
    for _, key, index in ((binary, 'binary_sha256', 1),
                          (configuration, 'configuration_sha256', 2),
                          (peer_configuration, 'peer_configuration_sha256', 3)):
        STATUS.require(artifacts[index][3] == frozen_run[key], 'run_identity_changed')
    lifetime = process_identity(expected_pid, binary)
    STATUS.require(lifetime is not None and lifetime[1], 'live_service_required')
    deadline = time.monotonic() + timeout_seconds
    last_sequence = initial['sequence']

    def monitor(final=None):
        nonlocal last_sequence
        for path, identity in directories:
            STATUS.private_directory(path)
            metadata = path.lstat()
            STATUS.require((metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode)
                           == identity, 'directory_identity_changed')
        for path, maximum, private, digest, signature in artifacts:
            STATUS.require(STATUS.signature(path.lstat()) == signature
                           and STATUS.read_file(path, maximum, private=private, hashing=True) == digest,
                           'frozen_artifact_changed')
        current = STATUS.validate_status(STATUS.read_json(network_dir / 'service-status.json'))
        STATUS.require(all(type(current[key]) is type(frozen_run[key])
                           and current[key] == frozen_run[key] for key in STATUS.RUN_KEYS),
                       'run_identity_changed')
        STATUS.require(current['sequence'] >= last_sequence, 'status_sequence_regressed')
        last_sequence = current['sequence']
        STATUS.require(current['phase'] != 'error' and current['error_code'] is None,
                       'service_failed_operator_review')
        identity = process_identity(expected_pid, binary)
        STATUS.require(identity is None or identity[0] == lifetime[0], 'process_identity_changed')
        if final is not None:
            STATUS.require(current == final, 'final_status_changed')
            STATUS.require(identity is None or not identity[1], 'owned_process_still_running')
        return current, identity

    run_command([str(launcher), 'stop', str(network_dir), expected_run_id], deadline,
                lambda: monitor())
    final_file = run_directory / 'final.json'
    while True:
        current, identity = monitor()
        final = None
        try:
            final_file.lstat()
        except FileNotFoundError:
            pass
        else:
            final = STATUS.validate_status(STATUS.read_json(final_file))
            STATUS.require(all(type(final[key]) is type(frozen_run[key])
                               and final[key] == frozen_run[key] for key in STATUS.RUN_KEYS),
                           'final_run_mismatch')
            STATUS.require(final['phase'] == 'stopped' and final['error_code'] is None
                           and final['state_available'] and final['sequence'] >= initial['sequence'],
                           'final_verification_failed')
            STATUS.require(current == final, 'final_status_changed')
        if final is not None and (identity is None or not identity[1]):
            break
        remaining = deadline - time.monotonic()
        STATUS.require(remaining > 0, 'stop_deadline_operator_review')
        time.sleep(min(POLL_SECONDS, remaining))
    # Pin the immutable final receipt too. Neither its deletion nor replacement
    # after the replay command may be accepted as the original stopped run.
    final_digest = STATUS.read_file(final_file, STATUS.MAX_JSON, private=True, hashing=True)
    artifacts.append((final_file, STATUS.MAX_JSON, True, final_digest,
                      STATUS.signature(final_file.lstat())))
    replay = parse_check(run_command([str(launcher), 'check', str(network_dir), '--json'],
                                     deadline, lambda: monitor(final)), final)
    monitor(final)
    return {'schema_version': 1, 'state': 'stopped_verified', 'height': final['height'],
            'tip': final['tip'], 'state_fingerprint': final['state_fingerprint'],
            'cumulative_work': final['cumulative_work'], 'proof_replay_checked': True,
            'local_reward_receipts_checked': replay['local_reward_receipts_checked'],
            'validation_scope': replay['validation_scope'], 'process_exit_code_verified': False,
            'observation_qualified': False, 'operator_review_required': False}


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise STATUS.StatusError('arguments_invalid')


def main():
    try:
        parser = Parser(description=__doc__)
        for name in ('network-dir', 'launcher', 'binary', 'config', 'peer-config'):
            parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--expected-pid', type=int, required=True)
        parser.add_argument('--expected-run-id', required=True)
        parser.add_argument('--timeout-seconds', type=int, default=600)
        args = parser.parse_args()
        result = stop_network(args.network_dir, args.launcher, args.binary, args.config,
                              args.peer_config, args.expected_pid, args.expected_run_id,
                              args.timeout_seconds)
    except (STATUS.StatusError, OSError) as error:
        result = {'schema_version': 1, 'state': 'unavailable',
                  'diagnostic': str(error) if isinstance(error, STATUS.StatusError) else 'file_unavailable',
                  'operator_review_required': True, 'process_exit_code_verified': False,
                  'observation_qualified': False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['state'] == 'stopped_verified' else 1


if __name__ == '__main__':
    sys.exit(main())
