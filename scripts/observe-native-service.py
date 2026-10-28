#!/usr/bin/env python3
"""Read-only, real-time observation of an isolated native engineering service.

Completion requires one continuous 24-hour process identity and a subsequent
offline replay. The observer never opens the chain database or controls a node.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

TARGET_MS = 86_400_000
STALE_MS = 15_000
PROGRESS_STALE_MS = 1_800_000
ACCEPTED_HEIGHT_GAP_MS = 7_200_000
MAX_JSON = 65_536
MAX_EVENTS = 64 * 1024 * 1024
PHASES = {'starting', 'replaying', 'preparing', 'refilling', 'mining',
          'committing', 'stopping', 'stopped', 'error'}
STATUS_KEYS = {'schema_version', 'run_id', 'process_id', 'network_id',
               'binary_sha256', 'configuration_sha256', 'sequence', 'phase',
               'height', 'tip', 'cumulative_work', 'state_fingerprint',
               'state_available', 'updated_unix_ms', 'started_unix_ms',
               'elapsed_monotonic_ms', 'observation_elapsed_ms',
               'observation_target_ms', 'observation_complete', 'error_code',
               'pow_attempts', 'progress_sequence', 'last_progress_elapsed_ms'}
EVENT_KEYS = {'schema_version', 'run_id', 'sequence', 'event', 'height', 'tip',
              'elapsed_monotonic_ms', 'error_code'}
RUN_KEYS = {'schema_version', 'run_id', 'process_id', 'network_id',
            'binary_sha256', 'configuration_sha256', 'started_unix_ms',
            'observation_target_ms'}
FROZEN_KEYS = ('run_id', 'process_id', 'network_id', 'binary_sha256',
               'configuration_sha256', 'started_unix_ms', 'observation_target_ms')


class ObservationError(ValueError):
    """Static diagnostic code without paths or untrusted error text."""


def require(condition, code):
    if not condition:
        raise ObservationError(code)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= (1 << 64) - 1


def hexadecimal(value, size=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def error_code(value):
    return value is None or (isinstance(value, str)
                             and re.fullmatch('[a-z][a-z0-9_]{0,63}', value) is not None)


def validate_status(value):
    require(isinstance(value, dict) and set(value) == STATUS_KEYS, 'status_schema')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'status_schema')
    for key in ('run_id', 'network_id', 'binary_sha256', 'configuration_sha256', 'tip', 'state_fingerprint'):
        require(hexadecimal(value[key]), 'status_digest')
    require(hexadecimal(value['cumulative_work'], 128), 'status_work')
    for key in ('sequence', 'height', 'updated_unix_ms', 'started_unix_ms',
                'elapsed_monotonic_ms', 'observation_elapsed_ms', 'pow_attempts',
                'progress_sequence', 'last_progress_elapsed_ms'):
        require(integer(value[key]), 'status_integer')
    require(integer(value['process_id'], 1) and value['process_id'] <= (1 << 31) - 1, 'status_process')
    require(type(value['observation_target_ms']) is int
            and value['observation_target_ms'] == TARGET_MS, 'observation_target')
    require(isinstance(value['phase'], str) and value['phase'] in PHASES, 'status_phase')
    require(type(value['state_available']) is bool
            and type(value['observation_complete']) is bool, 'status_boolean')
    require(error_code(value['error_code']), 'status_error_code')
    require(value['observation_elapsed_ms'] <= value['elapsed_monotonic_ms']
            and value['last_progress_elapsed_ms'] <= value['elapsed_monotonic_ms'], 'status_elapsed')
    require(not value['observation_complete'] or value['observation_elapsed_ms'] >= TARGET_MS,
            'premature_service_completion')
    return value


def signature(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def private_regular(path, maximum=None):
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_mode & 0o077 == 0, 'private_file_required')
    require(maximum is None or meta.st_size <= maximum, 'file_size_limit')
    return meta


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def bad_constant(_):
        raise ObservationError('json_number')
    return json.loads(data, object_pairs_hook=unique, parse_constant=bad_constant)


def read_json(path):
    private_regular(path, MAX_JSON)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_mode & 0o077 == 0
                and opened.st_size <= MAX_JSON, 'private_file_required')
        data = stream.read(MAX_JSON + 1)
        require(signature(os.fstat(stream.fileno())) == signature(opened), 'file_changed')
    require(len(data) <= MAX_JSON, 'file_size_limit')
    return decode_json(data)


def digest_file(path):
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), 'artifact_not_regular')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        require(signature(os.fstat(stream.fileno())) == signature(before), 'artifact_changed')
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    require(signature(path.stat()) == signature(before), 'artifact_changed')
    return digest.hexdigest(), signature(before)


def process_identity(pid, binary):
    """Read process identity without retaining its command line or environment."""
    if sys.platform.startswith('linux'):
        proc = Path('/proc') / str(pid)
        raw = (proc / 'stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        require(len(fields) > 19 and fields[0] not in ('Z', 'X'), 'process_unavailable')
        executable = (proc / 'exe').resolve(strict=True)
        start = fields[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    else:
        def ps(field):
            completed = subprocess.run(['ps', '-p', str(pid), '-o', field + '='],
                                       capture_output=True, text=True, timeout=5, check=False)
            require(completed.returncode == 0 and completed.stdout.strip(), 'process_unavailable')
            return completed.stdout.strip()
        executable = Path(ps('comm')).resolve(strict=True)
        start, boot = ps('lstart'), ''
    require(executable == binary.resolve(strict=True), 'process_executable_mismatch')
    return hashlib.sha256((str(pid) + '\0' + start + '\0' + boot).encode()).hexdigest()


def process_rss(pid):
    if sys.platform.startswith('linux'):
        for line in (Path('/proc') / str(pid) / 'status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
        raise ObservationError('process_memory_unavailable')
    completed = subprocess.run(['ps', '-p', str(pid), '-o', 'rss='],
                               capture_output=True, text=True, timeout=5, check=False)
    require(completed.returncode == 0 and completed.stdout.strip().isdigit(), 'process_memory_unavailable')
    return int(completed.stdout.strip()) * 1024


def cgroup_memory_events(pid):
    if not sys.platform.startswith('linux'):
        return None
    for line in (Path('/proc') / str(pid) / 'cgroup').read_text().splitlines():
        if line.startswith('0::'):
            parts = Path(line[3:]).parts
            require('..' not in parts, 'cgroup_path')
            path = Path('/sys/fs/cgroup').joinpath(*[p for p in parts if p != '/']) / 'memory.events'
            if not path.is_file():
                return None
            values = dict(row.split() for row in path.read_text().splitlines())
            return {key: int(values[key]) for key in ('oom', 'oom_kill')}
    return None


class EventReader:
    def __init__(self, path, run_id):
        self.path, self.run_id = path, run_id
        self.offset, self.identity, self.last_sequence = 0, None, None

    def read(self):
        meta = private_regular(self.path, MAX_EVENTS)
        identity = (meta.st_dev, meta.st_ino)
        require(self.identity is None or identity == self.identity, 'event_file_replaced')
        require(meta.st_size >= self.offset, 'event_file_truncated')
        descriptor = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == identity, 'event_file_changed')
            stream.seek(self.offset)
            data = stream.read(MAX_EVENTS + 1)
        require(len(data) <= MAX_EVENTS, 'event_size_limit')
        complete = data.rfind(b'\n') + 1
        require(len(data) - complete <= MAX_JSON, 'event_line_size')
        result = []
        for line in data[:complete].splitlines():
            require(0 < len(line) <= MAX_JSON, 'event_line_size')
            value = decode_json(line)
            require(isinstance(value, dict) and set(value) == EVENT_KEYS
                    and type(value['schema_version']) is int and value['schema_version'] == 1, 'event_schema')
            require(hexadecimal(value['run_id']) and hexadecimal(value['tip']), 'event_digest')
            require(all(integer(value[key]) for key in ('sequence', 'height', 'elapsed_monotonic_ms')), 'event_integer')
            require(value['event'] in ('phase_changed', 'block_accepted', 'service_stopped', 'service_error')
                    and error_code(value['error_code']), 'event_type')
            if value['run_id'] != self.run_id:
                continue
            require(self.last_sequence is None or value['sequence'] >= self.last_sequence, 'event_sequence_regressed')
            self.last_sequence = value['sequence']
            require(value['event'] not in ('service_stopped', 'service_error')
                    and value['error_code'] is None, 'service_event_failure')
            result.append(value)
        self.offset += complete
        self.identity = identity
        return result


class Window:
    def __init__(self, initial, identity, now_ms, wall_ms, oom=None):
        validate_status(initial)
        self.frozen = {key: initial[key] for key in FROZEN_KEYS}
        self.identity, self.previous = identity, None
        self.last_sequence_ms = now_ms
        self.last_observed_ms = now_ms
        self.started_ms, self.last_progress_ms = None, now_ms
        self.last_accept_ms = None
        self.initial_height, self.peak_rss = initial['height'], 0
        self.oom, self.samples = oom, 0
        self.observe(initial, identity, now_ms, wall_ms, 0, oom)

    def observe(self, current, identity, now_ms, wall_ms, rss, oom=None):
        validate_status(current)
        require(all(current[key] == value for key, value in self.frozen.items()), 'service_identity_changed')
        require(identity == self.identity, 'process_identity_changed')
        require(current['phase'] not in ('stopping', 'stopped', 'error')
                and current['error_code'] is None, 'service_failed_or_stopped')
        require(0 <= wall_ms - current['updated_unix_ms'] <= STALE_MS, 'status_not_fresh')
        if self.oom is not None:
            require(oom is not None and all(oom[key] == self.oom[key] for key in self.oom), 'cgroup_oom_counter_changed')
        previous = self.previous
        if previous is not None:
            require(0 <= now_ms - self.last_observed_ms <= STALE_MS, 'observation_gap')
            for key in ('sequence', 'height', 'elapsed_monotonic_ms', 'observation_elapsed_ms',
                        'pow_attempts', 'progress_sequence', 'last_progress_elapsed_ms'):
                require(current[key] >= previous[key], 'status_progress_regressed')
            require(int(current['cumulative_work'], 16) >= int(previous['cumulative_work'], 16), 'work_regressed')
            if (current['height'] == previous['height'] and previous['state_available']
                    and current['state_available']):
                require(all(current[key] == previous[key] for key in
                            ('tip', 'cumulative_work', 'state_fingerprint')), 'same_height_state_changed')
            if current['sequence'] != previous['sequence']:
                self.last_sequence_ms = now_ms
            require(now_ms - self.last_sequence_ms <= STALE_MS, 'heartbeat_stalled')
            if current['progress_sequence'] > previous['progress_sequence'] or current['pow_attempts'] > previous['pow_attempts']:
                self.last_progress_ms = now_ms
            if self.started_ms is not None and current['height'] > previous['height']:
                self.last_accept_ms = now_ms
        if self.started_ms is None and current['observation_elapsed_ms'] > 0:
            self.started_ms = now_ms
            self.last_accept_ms = now_ms
            self.initial_height = current['height']
        elapsed = 0 if self.started_ms is None else now_ms - self.started_ms
        require(elapsed >= 0, 'observer_clock_regressed')
        require(now_ms - self.last_progress_ms <= PROGRESS_STALE_MS, 'work_progress_stalled')
        if self.last_accept_ms is not None:
            # Operational observation policy, independent of consensus validity
            # and of the stochastic 300-second work target.
            require(now_ms - self.last_accept_ms < ACCEPTED_HEIGHT_GAP_MS, 'accepted_height_stalled')
        self.peak_rss = max(self.peak_rss, rss)
        self.last_observed_ms = now_ms
        self.previous = current.copy()
        self.samples += 1
        complete = (elapsed >= TARGET_MS and current['observation_elapsed_ms'] >= TARGET_MS
                    and current['observation_complete'] and current['state_available']
                    and current['height'] > self.initial_height)
        return {'schema_version': 1, 'run_id': current['run_id'],
                'observation_complete': complete, 'final_replay_required': True,
                'elapsed_observed_ms': elapsed, 'target_ms': TARGET_MS,
                'sample_count': self.samples, 'height': current['height'],
                'tip': current['tip'], 'state_fingerprint': current['state_fingerprint'],
                'cumulative_work': current['cumulative_work'], 'sampled_peak_rss_bytes': self.peak_rss,
                'updated_unix_ms': wall_ms, 'observer_process_id': os.getpid(),
                'oom_counters_available': self.oom is not None,
                'state': 'observation_complete' if complete else 'observing', 'error_code': None}


def private_directory(path, new=False):
    if new:
        path.mkdir(mode=0o700)
    meta = path.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_mode & 0o077 == 0, 'private_directory_required')


def write_json(path, value):
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def append_json(path, value):
    if path.exists():
        private_regular(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'a') as stream:
        stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def observe(args):
    import fcntl
    private_directory(args.network_dir)
    private_directory(args.output, new=True)
    with (args.output / 'observer.lock').open('x') as lock:
        os.chmod(args.output / 'observer.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        summary = {'schema_version': 1, 'observation_complete': False,
                   'final_replay_required': True, 'state': 'starting', 'error_code': None}
        try:
            status_path = args.network_dir / 'service-status.json'
            initial = validate_status(read_json(status_path))
            run_path = args.network_dir / 'service-runs' / initial['run_id'] / 'run.json'
            receipt = read_json(run_path)
            require(isinstance(receipt, dict) and set(receipt) == RUN_KEYS
                    and all(receipt[key] == initial[key] for key in RUN_KEYS), 'run_receipt_mismatch')
            artifacts = {}
            for path, key in ((args.binary, 'binary_sha256'), (args.config, 'configuration_sha256')):
                digest, meta = digest_file(path)
                require(digest == initial[key], 'artifact_hash_mismatch')
                artifacts[key] = {'sha256': digest, 'signature': meta}
            identity = process_identity(initial['process_id'], args.binary)
            events = EventReader(args.network_dir / 'service-events.jsonl', initial['run_id'])
            oom = cgroup_memory_events(initial['process_id'])
            window = Window(initial, identity, time.monotonic_ns() // 1_000_000,
                            time.time_ns() // 1_000_000, oom)
            write_json(args.output / 'frozen.json', {'schema_version': 1,
                       **window.frozen, 'process_identity_sha256': identity,
                       'observer_source_sha256': digest_file(Path(__file__))[0]})
            while True:
                status = validate_status(read_json(status_path))
                for path, key in ((args.binary, 'binary_sha256'), (args.config, 'configuration_sha256')):
                    if signature(path.stat()) != artifacts[key]['signature']:
                        require(digest_file(path)[0] == artifacts[key]['sha256'], 'artifact_hash_changed')
                        artifacts[key]['signature'] = signature(path.stat())
                require(read_json(run_path) == receipt, 'run_receipt_changed')
                current_events = events.read()
                now_ms = time.monotonic_ns() // 1_000_000
                summary = window.observe(status, process_identity(status['process_id'], args.binary), now_ms,
                                         time.time_ns() // 1_000_000, process_rss(status['process_id']),
                                         cgroup_memory_events(status['process_id']))
                append_json(args.output / 'observations.jsonl', {'schema_version': 1,
                            'observer_monotonic_ms': now_ms, 'status': status,
                            'summary': summary, 'events': current_events})
                write_json(args.output / 'summary.json', summary)
                if summary['observation_complete']:
                    print(json.dumps(summary, sort_keys=True))
                    return 0
                time.sleep(5)
        except (KeyboardInterrupt, ObservationError, OSError, ValueError, subprocess.SubprocessError) as error:
            code = (str(error) if isinstance(error, ObservationError) else
                    'observer_interrupted' if isinstance(error, KeyboardInterrupt) else 'observation_unavailable')
            summary.update(observation_complete=False, state='incomplete', error_code=code)
            append_json(args.output / 'observer-events.jsonl', {'schema_version': 1,
                        'event': 'observation_incomplete', 'error_code': code})
            write_json(args.output / 'summary.json', summary)
            print(json.dumps({'state': 'incomplete', 'error_code': code}), file=sys.stderr)
            return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    watch = commands.add_parser('watch', help='Observe an existing service for a real 24 hours')
    for name in ('network-dir', 'binary', 'config', 'output'):
        watch.add_argument('--' + name, type=Path, required=True)
    inspect = commands.add_parser('inspect', help='Read the saved summary without accessing a service')
    inspect.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'inspect':
        private_directory(args.output)
        value = read_json(args.output / 'summary.json')
        allowed = {'schema_version', 'observation_complete', 'final_replay_required', 'state',
                   'error_code', 'elapsed_observed_ms', 'target_ms', 'sample_count', 'height', 'tip',
                   'state_fingerprint', 'cumulative_work', 'sampled_peak_rss_bytes',
                   'oom_counters_available', 'run_id', 'updated_unix_ms', 'observer_process_id'}
        require(isinstance(value, dict) and set(value) <= allowed, 'summary_schema')
        if value.get('state') == 'observing':
            updated = value.get('updated_unix_ms')
            require(integer(updated) and 0 <= time.time_ns() // 1_000_000 - updated <= STALE_MS,
                    'observer_summary_stale')
        print(json.dumps(value, sort_keys=True))
        return 0
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    return observe(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ObservationError, OSError, ValueError):
        print(json.dumps({'state': 'incomplete', 'error_code': 'observation_unavailable'}), file=sys.stderr)
        sys.exit(1)
