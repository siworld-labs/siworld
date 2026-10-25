#!/usr/bin/env python3
"""Measure one process tree in an owned cgroup v2; never claim proof acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time
import uuid

BUDGET = 5368709120


def read_numbers(path):
    return {k: int(v) for k, v in (line.split() for line in path.read_text().splitlines())}


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
    return {'os': 'Ubuntu 24.04', 'architecture': platform.machine(),
            'kernel': platform.release(), 'avx2': True,
            'logical_cpus': os.cpu_count(), 'affinity_cpus': len(os.sched_getaffinity(0))}


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
    hardware = qualify()
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
    report = {'schema': 1, 'purpose': 'measurement harness validation',
              'acceptance': False, 'hardware': hardware, 'memory_max': BUDGET,
              'memory_swap_max': 0, 'cgroup_id': group.name,
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

        def enter():
            # Place before exec, then drop privileges. Descendants inherit the
            # scope; no proof code or helper executes outside the limit.
            os.setsid()
            (group / 'cgroup.procs').write_text(str(os.getpid()))
            os.setgroups([])
            os.setgid(args.gid)
            os.setuid(args.uid)

        started = time.monotonic_ns()
        with (args.output / 'stdout.jsonl').open('x') as out, \
                (args.output / 'stderr.log').open('x') as err:
            process = subprocess.Popen(args.command, stdout=out, stderr=err,
                                       preexec_fn=enter, close_fds=True)
            timed_out = False
            while True:
                now = time.monotonic_ns()
                report['samples'].append({'elapsed_ns': now - started,
                    'memory_current': int((group / 'memory.current').read_text()),
                    'swap_current': int((group / 'memory.swap.current').read_text())})
                if process.poll() is not None:
                    break
                if (now - started) / 1e9 > args.timeout:
                    timed_out = True
                    (group / 'cgroup.kill').write_text('1')
                    process.wait(timeout=10)
                    break
                time.sleep(0.1)
        remaining = (group / 'cgroup.procs').read_text().split()
        if remaining:
            (group / 'cgroup.kill').write_text('1')
        after = read_numbers(group / 'memory.events')
        peak = int((group / 'memory.peak').read_text())
        swap_peak = int((group / 'memory.swap.peak').read_text())
        report.update({'elapsed_ns': time.monotonic_ns() - started,
            'exit_code': process.returncode, 'timed_out': timed_out,
            'remaining_descendants': bool(remaining), 'memory_peak': peak,
            'swap_peak': swap_peak, 'memory_events_after': after,
            'memory_stat_after': read_numbers(group / 'memory.stat'),
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
    print(json.dumps({k: v for k, v in report.items() if k not in
                      ('samples', 'memory_stat_before', 'memory_stat_after')}, indent=2))
    raise SystemExit(0 if report['resource_control_pass'] else 1)


if __name__ == '__main__':
    main()
