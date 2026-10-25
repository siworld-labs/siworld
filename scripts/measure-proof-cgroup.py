#!/usr/bin/env python3
"""Measure one process tree in an owned cgroup v2; never claim proof acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import uuid

BUDGET = 5368709120
SAMPLE_SECONDS = 0.1


def read_numbers(path):
    return {k: int(v) for k, v in (line.split() for line in path.read_text().splitlines())}


def topology_counts(output):
    """Count exposed online topology, which is not the physical host in a VM."""
    cores, sockets, cpus = set(), set(), set()
    for line in output.splitlines():
        if not line or line.startswith('#'):
            continue
        cpu, core, socket, online = line.split(',')
        if online != 'Y':
            continue
        cpus.add(int(cpu))
        if core != '-' and socket != '-':
            cores.add((int(socket), int(core)))
            sockets.add(int(socket))
    return {'online_logical_cpus': len(cpus), 'exposed_physical_cores': len(cores) or None,
            'exposed_sockets': len(sockets) or None}


def lscpu_fields(rows):
    fields = {}
    for row in rows:
        fields[row['field'].rstrip(':')] = row.get('data')
        fields.update(lscpu_fields(row.get('children', [])))
    return fields


def qualify():
    release = platform.freedesktop_os_release()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('Requires native Linux x86_64')
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '24.04':
        raise ValueError('Requires Ubuntu 24.04')
    cpus = Path('/proc/cpuinfo').read_text().split('\n\n')
    flags = [set(line.split(':', 1)[1].split()) for cpu in cpus
             for line in cpu.splitlines() if line.startswith('flags')]
    if not flags or any('avx2' not in f for f in flags):
        raise ValueError('AVX2 must be exposed on every CPU')
    env = {**os.environ, 'LC_ALL': 'C'}

    def lscpu(*options):
        return subprocess.run(['lscpu', *options], env=env, text=True,
                              capture_output=True, check=True).stdout

    full, structured, topology = lscpu(), lscpu('--json'), lscpu('--parse=CPU,CORE,SOCKET,ONLINE')
    fields = lscpu_fields(json.loads(structured)['lscpu'])
    try:
        virt = subprocess.run(['systemd-detect-virt', '--vm'], env=env, text=True,
                              capture_output=True, check=False)
        virtualization = {'result': virt.stdout.strip(), 'exit_code': virt.returncode}
    except FileNotFoundError:
        virtualization = {'result': 'unavailable', 'exit_code': None}
    hardware = {'os': 'Ubuntu 24.04', 'architecture': platform.machine(),
        'kernel': platform.release(), 'cpu_model': fields.get('Model name'),
        'avx2': True, 'avx512f': all('avx512f' in f for f in flags),
        'avx512_features': sorted(set.intersection(*flags) &
                                 {f for f in set.union(*flags) if f.startswith('avx512')}),
        'logical_cpus': os.cpu_count(), 'affinity_cpus': len(os.sched_getaffinity(0)),
        **topology_counts(topology), 'hypervisor_vendor': fields.get('Hypervisor vendor'),
        'virtualization_type': fields.get('Virtualization type'),
        'virtualization_detection': virtualization,
        'github_actions_ci': os.environ.get('GITHUB_ACTIONS') == 'true',
        'host_tenancy': 'unknown; virtual topology does not establish exclusive host access'}
    evidence = {'lscpu_text': full, 'lscpu_json': json.loads(structured),
                'lscpu_topology': topology, 'affinity_cpu_ids': sorted(os.sched_getaffinity(0)),
                'self_cgroup': Path('/proc/self/cgroup').read_text()}
    return hardware, evidence


def parse_cpu_max(value):
    quota, period = value.split()
    period = int(period)
    if period <= 0 or (quota != 'max' and int(quota) <= 0):
        raise ValueError('Invalid cpu.max')
    return {'quota_usec': None if quota == 'max' else int(quota), 'period_usec': period,
            'quota_cores': None if quota == 'max' else int(quota) / period}


def cpu_ancestry(group, mount):
    """Read visible ancestors without changing any controller or inherited limit."""
    result = []
    scope = group
    while True:
        row = {'path': str(scope)}
        for name in ('cpu.max', 'cpu.max.burst', 'cpuset.cpus.effective'):
            file = scope / name
            row[name] = file.read_text().strip() if file.is_file() else None
        row['cpu_limit'] = parse_cpu_max(row['cpu.max']) if row['cpu.max'] else None
        stat = scope / 'cpu.stat'
        row['cpu.stat'] = read_numbers(stat) if stat.is_file() else None
        result.append(row)
        if scope == mount:
            break
        if mount not in scope.parents:
            raise ValueError('Cgroup ancestry escaped its mount')
        scope = scope.parent
    return result


def parse_thread_stat(text):
    # The command field may contain spaces and parentheses. Fields after its
    # closing parenthesis retain their documented /proc stat offsets.
    tail = text[text.rindex(')') + 2:].split()
    return {'state': tail[0], 'user_ticks': int(tail[11]), 'system_ticks': int(tail[12]),
            'start_ticks': int(tail[19]), 'processor': int(tail[36])}


def thread_snapshot(group, proc=Path('/proc')):
    rows, raced = [], 0
    # All proof descendants inherit the owned scope. Inspect subscopes too,
    # without depending on parent/child process snapshots taken at one instant.
    for membership in group.rglob('cgroup.procs'):
        for pid in membership.read_text().split():
            try:
                tasks = list((proc / pid / 'task').iterdir())
            except (FileNotFoundError, ProcessLookupError):
                raced += 1
                continue
            for task in tasks:
                try:
                    rows.append({'pid': int(pid), 'tid': int(task.name),
                                 **parse_thread_stat((task / 'stat').read_text())})
                except (FileNotFoundError, ProcessLookupError):
                    raced += 1
    return {'threads': rows, 'exited_during_sample': raced}


def counter_delta(before, after):
    delta = {key: after[key] - value for key, value in before.items() if key in after}
    if any(value < 0 for value in delta.values()):
        raise ValueError('Nonmonotonic CPU counters')
    return delta


def cpu_summary(before, after, elapsed_ns, ancestry, affinity, samples, tick_hz):
    delta = counter_delta(before, after)
    quotas = [row['cpu_limit']['quota_cores'] for row in ancestry
              if row['cpu_limit'] and row['cpu_limit']['quota_cores'] is not None]
    capacity = min([affinity, *quotas])
    elapsed_usec = elapsed_ns / 1000
    average_cores = delta['usage_usec'] / elapsed_usec
    previous, tick_total, busiest = {}, 0, 0
    for sample in samples:
        current, active = {}, 0
        for thread in sample['process_threads']['threads']:
            key = (thread['pid'], thread['tid'], thread['start_ticks'])
            ticks = thread['user_ticks'] + thread['system_ticks']
            current[key] = ticks
            if key in previous:
                change = ticks - previous[key]
                if change < 0:
                    raise ValueError('Nonmonotonic thread CPU ticks')
                tick_total += change
                active += change > 0
        busiest = max(busiest, active)
        previous = current
    periods, throttled = delta.get('nr_periods', 0), delta.get('nr_throttled', 0)
    return {'cpu_stat_delta': delta, 'average_cpu_cores': average_cores,
        'affinity_cpu_count': affinity, 'minimum_visible_quota_cores': min(quotas) if quotas else None,
        'effective_visible_cpu_capacity': capacity,
        'capacity_utilization_percent': 100 * average_cores / capacity,
        'throttled_period_percent': 100 * throttled / periods if periods else 0,
        'throttled_usec_over_wall_percent': 100 * delta.get('throttled_usec', 0) / elapsed_usec,
        'sample_period_seconds': SAMPLE_SECONDS, 'thread_tick_hz': tick_hz,
        'sampled_thread_cpu_seconds_lower_bound': tick_total / tick_hz,
        'maximum_sampled_active_threads': busiest,
        'accounting_scope': 'owned cgroup and its descendants; visible ancestor quotas only',
        'throttling_limit': 'Kernel throttled time can accumulate across CPUs; it is not a wall-time fraction.',
        'thread_sampling_limit': 'Thread exits and short intervals can be missed; phase attribution is approximate.'}


def assess(before, after, peak, swap_peak, exit_code, timed_out, remaining):
    delta = {k: after[k] - before[k] for k in before}
    if any(v < 0 for v in delta.values()):
        raise ValueError('Nonmonotonic memory.events')
    ok = (exit_code == 0 and not timed_out and not remaining and 0 < peak <= BUDGET
          and swap_peak == 0 and not any(delta.get(k, 0) for k in
                                        ('max', 'oom', 'oom_kill', 'oom_group_kill')))
    return {'resource_control_pass': ok, 'memory_events_delta': delta,
            'acceptance': False}


def measure(args):
    hardware, hardware_evidence = qualify()
    if os.geteuid() != 0:
        raise ValueError('Requires cgroup delegation or a privileged supervisor')
    if args.uid == 0 or args.gid == 0:
        raise ValueError('Proof worker must run as an unprivileged user')
    parent = Path('/sys/fs/cgroup')
    if not (parent / 'cgroup.controllers').is_file():
        raise ValueError('Unified cgroup v2 is required')
    # Do not change the parent controllers or unrelated scopes. Fail closed
    # when the host has not enabled the memory controller for child scopes.
    group = parent / ('siworld-proof-' + uuid.uuid4().hex)
    args.output.mkdir(parents=True, exist_ok=False)
    group.mkdir(mode=0o755)
    process = None
    report = {'schema': 2, 'purpose': 'measurement harness validation',
              'acceptance': False, 'hardware': hardware, 'hardware_evidence': hardware_evidence,
              'memory_max': BUDGET, 'memory_swap_max': 0, 'cgroup_id': group.name,
              'samples': [], 'command_executable_sha256': hashlib.sha256(
                  Path(args.command[0]).resolve(strict=True).read_bytes()).hexdigest()}
    report_path = args.output / 'measurement.json'
    try:
        for name, value in [('memory.max', BUDGET), ('memory.swap.max', 0),
                            ('memory.oom.group', 1)]:
            (group / name).write_text(str(value))
            if int((group / name).read_text()) != value:
                raise ValueError('Cgroup limit readback mismatch: ' + name)
        if not (group / 'memory.peak').is_file():
            raise ValueError('Kernel lifetime memory.peak is required')
        before = read_numbers(group / 'memory.events')
        report['memory_events_before'] = before
        report['memory_stat_before'] = read_numbers(group / 'memory.stat')
        report['cpu_ancestry_before'] = cpu_ancestry(group, parent)
        cpu_before = read_numbers(group / 'cpu.stat')
        tick_hz = os.sysconf('SC_CLK_TCK')
        report['cpu_stat_before'] = cpu_before
        report['worker_environment'] = {name: os.environ.get(name) for name in
            ('RAYON_NUM_THREADS', 'SIWORLD_COMPOSITION_HIDING_WORKERS')}

        def enter():
            # Place before exec, then drop privileges. Descendants inherit the
            # scope; no proof code or helper executes outside the limit.
            os.setsid()
            (group / 'cgroup.procs').write_text(str(os.getpid()))
            os.setgroups([])
            os.setgid(args.gid)
            os.setuid(args.uid)

        started = time.monotonic_ns()
        report['monotonic_started_ns'] = started
        with (args.output / 'stdout.jsonl').open('x') as out, \
                (args.output / 'stderr.log').open('x') as err:
            process = subprocess.Popen(args.command, stdout=out, stderr=err,
                                       preexec_fn=enter, close_fds=True)
            timed_out = False
            while True:
                now = time.monotonic_ns()
                report['samples'].append({'elapsed_ns': now - started,
                    'memory_current': int((group / 'memory.current').read_text()),
                    'swap_current': int((group / 'memory.swap.current').read_text()),
                    'cpu_stat': read_numbers(group / 'cpu.stat'),
                    'process_threads': thread_snapshot(group)})
                if process.poll() is not None:
                    break
                if (now - started) / 1e9 > args.timeout:
                    timed_out = True
                    (group / 'cgroup.kill').write_text('1')
                    process.wait(timeout=10)
                    break
                time.sleep(SAMPLE_SECONDS)
        remaining = (group / 'cgroup.procs').read_text().split()
        if remaining:
            (group / 'cgroup.kill').write_text('1')
        after = read_numbers(group / 'memory.events')
        peak = int((group / 'memory.peak').read_text())
        swap_peak = int((group / 'memory.swap.peak').read_text())
        elapsed_ns = time.monotonic_ns() - started
        cpu_after = read_numbers(group / 'cpu.stat')
        report['cpu_ancestry_after'] = cpu_ancestry(group, parent)
        before_limits = [(row['path'], row['cpu.max'], row['cpuset.cpus.effective'])
                         for row in report['cpu_ancestry_before']]
        after_limits = [(row['path'], row['cpu.max'], row['cpuset.cpus.effective'])
                        for row in report['cpu_ancestry_after']]
        if before_limits != after_limits:
            raise ValueError('CPU quota or cpuset changed during measurement')
        report.update({'elapsed_ns': elapsed_ns,
            'exit_code': process.returncode, 'timed_out': timed_out,
            'remaining_descendants': bool(remaining), 'memory_peak': peak,
            'swap_peak': swap_peak, 'memory_events_after': after,
            'memory_stat_after': read_numbers(group / 'memory.stat'),
            'cpu_stat_after': cpu_after,
            'cpu_summary': cpu_summary(cpu_before, cpu_after, elapsed_ns,
                report['cpu_ancestry_before'], hardware['affinity_cpus'], report['samples'], tick_hz),
            **assess(before, after, peak, swap_peak, process.returncode, timed_out, remaining)})
        return report
    except BaseException as error:
        report['resource_control_pass'] = False
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        if process is not None and process.poll() is None:
            (group / 'cgroup.kill').write_text('1')
            process.wait(timeout=10)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        # Keep evidence on any failure; never remove another scope or retry a proof.
        try:
            group.rmdir()
        except OSError:
            pass


def public_summary(report):
    # Private records include host topology, cgroup paths and process/thread
    # identifiers. An explicit allowlist prevents them from entering CI logs.
    keys = ('schema', 'purpose', 'acceptance', 'hardware', 'memory_max', 'memory_swap_max',
            'elapsed_ns', 'exit_code', 'timed_out', 'remaining_descendants', 'memory_peak',
            'swap_peak', 'resource_control_pass', 'memory_events_delta', 'cpu_summary',
            'command_executable_sha256', 'worker_environment')
    return {key: report[key] for key in keys if key in report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ['--']:
        args.command = args.command[1:]
    if not args.command or args.timeout <= 0:
        parser.error('A command and positive timeout are required')
    report = measure(args)
    print(json.dumps(public_summary(report), indent=2))
    raise SystemExit(0 if report['resource_control_pass'] else 1)


if __name__ == '__main__':
    main()
