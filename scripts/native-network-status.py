#!/usr/bin/env python3
"""Read-only health for a pinned native engineering service, without database access.

This one-shot exported-status check is not independent replay, reward auditing,
chain synchronization acceptance or a continuous observation qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MAX_JSON = 65_536
STALE_MS = 15_000
TARGET_MS = 86_400_000
RUN_KEYS = {'schema_version', 'run_id', 'process_id', 'network_id',
            'binary_sha256', 'configuration_sha256', 'started_unix_ms',
            'observation_target_ms', 'peer_configuration_sha256'}
STATUS_KEYS = RUN_KEYS | {
    'sequence', 'phase', 'height', 'tip', 'state_fingerprint', 'cumulative_work',
    'state_available', 'updated_unix_ms', 'elapsed_monotonic_ms',
    'observation_elapsed_ms', 'observation_complete', 'pow_attempts',
    'progress_sequence', 'last_progress_elapsed_ms', 'error_code', 'network'}
EXTENSIONS = {'supply', 'process_resources'}
NETWORK_KEYS = {'configured', 'pending', 'connected', 'closing', 'disabled',
                'workers', 'authenticated_connections', 'closed_connections', 'mining'}
PHASES = {'starting', 'replaying', 'preparing', 'refilling', 'mining',
          'committing', 'networking', 'stopping', 'stopped', 'error'}


class StatusError(ValueError):
    """Static diagnostic without filenames or untrusted exception text."""


def require(condition, code):
    if not condition:
        raise StatusError(code)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= (1 << 64) - 1


def hexadecimal(value, size=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def private_directory(path):
    try:
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode), 'directory_shape')
        require(metadata.st_uid == os.geteuid() and metadata.st_mode & 0o077 == 0,
                'private_directory_required')
    except OSError:
        raise StatusError('directory_unavailable') from None


def signature(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_file(path, maximum, private=False, hashing=False):
    try:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'file_shape')
        require(0 < before.st_size <= maximum, 'file_size_limit')
        if private:
            require(before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0,
                    'private_file_required')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            require(signature(opened) == signature(before), 'file_changed')
            if hashing:
                result = hashlib.sha256()
                size = 0
                for chunk in iter(lambda: stream.read(65_536), b''):
                    size += len(chunk)
                    require(size <= maximum, 'file_size_limit')
                    result.update(chunk)
                result = result.hexdigest()
            else:
                result = stream.read(maximum + 1)
                require(len(result) <= maximum, 'file_size_limit')
            require(signature(os.fstat(stream.fileno())) == signature(opened), 'file_changed')
        require(signature(path.lstat()) == signature(before), 'file_changed')
        return result
    except OSError:
        raise StatusError('file_unavailable') from None


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def bad_constant(_):
        raise StatusError('json_number')
    data = read_file(path, MAX_JSON, private=True)
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, StatusError):
            raise
        raise StatusError('json_malformed') from None


def validate_status(value):
    require(isinstance(value, dict) and STATUS_KEYS <= value.keys()
            and value.keys() <= STATUS_KEYS | EXTENSIONS, 'status_schema')
    require(all(isinstance(value[key], dict) for key in EXTENSIONS & value.keys()), 'status_schema')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'status_schema')
    for key in ('run_id', 'network_id', 'binary_sha256', 'configuration_sha256',
                'peer_configuration_sha256', 'tip', 'state_fingerprint'):
        require(hexadecimal(value[key]), 'status_digest')
    require(hexadecimal(value['cumulative_work'], 128), 'status_work')
    for key in ('sequence', 'height', 'updated_unix_ms', 'started_unix_ms',
                'elapsed_monotonic_ms', 'observation_elapsed_ms', 'pow_attempts',
                'progress_sequence', 'last_progress_elapsed_ms'):
        require(integer(value[key]), 'status_integer')
    require(integer(value['process_id'], 1) and value['process_id'] < 1 << 31, 'status_process')
    require(type(value['observation_target_ms']) is int
            and value['observation_target_ms'] == TARGET_MS, 'status_observation')
    require(isinstance(value['phase'], str) and value['phase'] in PHASES, 'status_phase')
    require(type(value['state_available']) is bool and type(value['observation_complete']) is bool,
            'status_boolean')
    require(value['error_code'] is None or (isinstance(value['error_code'], str)
            and re.fullmatch('[a-z][a-z0-9_]{0,63}', value['error_code']) is not None), 'status_error')
    require(value['observation_elapsed_ms'] <= value['elapsed_monotonic_ms']
            and value['last_progress_elapsed_ms'] <= value['elapsed_monotonic_ms'], 'status_elapsed')
    require(not value['observation_complete'] or value['observation_elapsed_ms'] >= TARGET_MS,
            'status_observation')
    network = value['network']
    require(network is None or (isinstance(network, dict) and set(network) == NETWORK_KEYS),
            'network_schema')
    if network is not None:
        require(type(network['mining']) is bool and all(integer(network[key])
                for key in NETWORK_KEYS - {'mining'}), 'network_schema')
        require(network['configured'] <= 64 and network['workers'] <= 16
                and sum(network[key] for key in ('pending', 'connected', 'closing', 'disabled'))
                <= network['configured'] and network['connected'] <= network['workers'],
                'network_schema')
    return value


def verify_process(pid, binary, process_root=Path('/proc')):
    require(sys.platform.startswith('linux'), 'linux_process_identity_required')
    process = process_root / str(pid)
    try:
        before = (process / 'stat').read_text()
        fields = before[before.rfind(')') + 2:].split()
        require(len(fields) > 19 and fields[0] not in ('Z', 'X'), 'process_unavailable')
        require(int(before.split(' ', 1)[0]) == pid, 'process_identity_mismatch')
        executable = (process / 'exe').resolve(strict=True)
        require(executable == binary.resolve(strict=True), 'process_identity_mismatch')
        after = (process / 'stat').read_text()
        after_fields = after[after.rfind(')') + 2:].split()
        require(len(after_fields) > 19 and after_fields[19] == fields[19]
                and after_fields[0] not in ('Z', 'X'), 'process_identity_mismatch')
    except StatusError:
        raise
    except (OSError, ValueError):
        raise StatusError('process_unavailable') from None


def inspect_status(network_dir, binary, configuration, peer_configuration,
                   expected_pid, expected_run_id=None, now_ms=None):
    require(integer(expected_pid, 1) and expected_pid < 1 << 31, 'expected_process_invalid')
    require(expected_run_id is None or hexadecimal(expected_run_id), 'expected_run_invalid')
    private_directory(network_dir)
    current = validate_status(read_json(network_dir / 'service-status.json'))
    require(current['process_id'] == expected_pid, 'expected_process_mismatch')
    require(expected_run_id is None or current['run_id'] == expected_run_id, 'expected_run_mismatch')
    runs = network_dir / 'service-runs'
    private_directory(runs)
    run = runs / current['run_id']
    private_directory(run)
    receipt = read_json(run / 'run.json')
    require(isinstance(receipt, dict) and set(receipt) == RUN_KEYS
            and all(type(receipt[key]) is type(current[key]) and receipt[key] == current[key]
                    for key in RUN_KEYS), 'run_receipt_mismatch')
    for path, key, maximum, private in (
            (binary, 'binary_sha256', 512 * 1024 * 1024, False),
            (configuration, 'configuration_sha256', 1024 * 1024, True),
            (peer_configuration, 'peer_configuration_sha256', 1024 * 1024, True)):
        require(read_file(path, maximum, private=private, hashing=True) == receipt[key],
                'artifact_hash_mismatch')
    now_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    require(integer(now_ms), 'status_clock_mismatch')
    age = now_ms - current['updated_unix_ms']
    result = {'schema_version': 1, 'state': 'starting', 'live': False,
              'diagnostic': 'service_starting', 'phase': current['phase'],
              'height': current['height'], 'tip': current['tip'],
              'state_fingerprint': current['state_fingerprint'],
              'cumulative_work': current['cumulative_work'],
              'sequence': current['sequence'], 'age_ms': max(age, 0),
              'network': {} if current['network'] is None else dict(current['network']),
              'reward_health': 'requires_independent_replay', 'observation_qualified': False}
    if current['phase'] == 'error' or current['error_code'] is not None:
        result.update(state='error', diagnostic='service_error')
        return result
    if current['phase'] == 'stopped':
        result.update(state='stopped', diagnostic='service_stopped')
        return result
    require(age >= 0, 'status_clock_mismatch')
    if age > STALE_MS:
        result.update(state='stale', diagnostic='status_stale')
        return result
    verify_process(expected_pid, binary)
    result['live'] = True
    if current['phase'] == 'stopping':
        result.update(state='stopping', diagnostic='service_stopping')
    elif current['phase'] == 'networking' and current['state_available'] and current['network'] is not None:
        if current['network']['connected'] > 0:
            result.update(state='ready', diagnostic='exported_networking')
        else:
            result.update(state='degraded', diagnostic='no_authenticated_peers'
                          if current['network']['configured'] else 'no_configured_peers')
    return result


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise StatusError('arguments_invalid')


def main():
    try:
        parser = Parser(description=__doc__)
        for name in ('network-dir', 'binary', 'config', 'peer-config'):
            parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--expected-pid', type=int, required=True)
        parser.add_argument('--expected-run-id')
        arguments = parser.parse_args()
        result = inspect_status(arguments.network_dir, arguments.binary, arguments.config,
                                arguments.peer_config, arguments.expected_pid, arguments.expected_run_id)
    except StatusError as error:
        result = {'schema_version': 1, 'state': 'unavailable', 'live': False,
                  'diagnostic': str(error), 'reward_health': 'requires_independent_replay',
                  'observation_qualified': False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['state'] == 'ready' else 1


if __name__ == '__main__':
    sys.exit(main())
