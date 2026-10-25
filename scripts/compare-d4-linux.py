#!/usr/bin/env python3
"""Measure x86-64-v3 D4-B controls, optionally comparing a diagnostic scalar build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FLAGS = {
    'scalar': '-C target-cpu=x86-64 -C target-feature=-avx2,-avx512f',
    'avx2': '-C target-cpu=x86-64-v3',
}


def proof_worker(binary, mode):
    """Run a baseline launcher while inspecting its separately installed optimized worker."""
    if mode == 'scalar':
        return binary
    if binary.parent.name != 'bin':
        raise ValueError('Normal AVX2 controls require a CPU-check launcher in a release bin directory')
    package = binary.parent.parent
    worker = package / 'libexec' / binary.name
    worker = worker.resolve(strict=True)
    receipt = json.loads((package / 'build-receipt.json').read_text())
    if receipt.get('worker_isa') != 'x86-64-v3' or receipt.get('bootstrap_isa') != 'x86-64':
        raise ValueError('Release ISA metadata does not match the CPU-check launcher package')
    entries = [entry for entry in receipt.get('workers', []) if entry.get('name') == binary.name]
    if len(entries) != 1 or entries[0].get('worker_sha256') != hashlib.sha256(worker.read_bytes()).hexdigest():
        raise ValueError('Release worker checksum does not match its package receipt')
    if receipt.get('bootstrap_sha256') != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError('CPU-check launcher checksum does not match its package receipt')
    if receipt.get('repository_config_sha256') != hashlib.sha256((ROOT / '.cargo/config.toml').read_bytes()).hexdigest():
        raise ValueError('Release package target configuration differs from the repository')
    return worker


def verify_build_receipt(build, inspected, mode):
    if build.get('binary_sha256') != inspected['binary_sha256']:
        raise ValueError('Binary compiler receipt checksum mismatch')
    if mode == 'avx2':
        if (build.get('effective_rustflags') != FLAGS[mode]
                or build.get('cargo_working_directory') != 'repository-root'
                or build.get('diagnostic_only') is not False
                or build.get('repository_config_sha256') != hashlib.sha256(
                    (ROOT / '.cargo/config.toml').read_bytes()).hexdigest()):
            raise ValueError('Optimized build must use the fixed repository x86-64-v3 configuration')
    elif build.get('effective_rustflags', build.get('build_environment', {}).get('RUSTFLAGS')) != FLAGS[mode]:
        raise ValueError('Scalar diagnostic compiler flag receipt mismatch')


def inspect_binary(binary, output, mode):
    """Retain instruction evidence for the actual prover, not its supervisor."""
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    counts = {'ymm_montgomery_multiply': 0}
    examples = []
    with (output / 'disassembly.txt').open('x') as stream:
        process = subprocess.Popen(['objdump', '-d', '-C', '-M', 'intel', str(binary)],
                                   stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            stream.write(line)
            if re.search(r'\bvpmulu?dq\b.*\bymm\d+', line):
                counts['ymm_montgomery_multiply'] += 1
                if len(examples) < 4:
                    examples.append(line.strip())
        if process.wait() != 0:
            raise ValueError('Disassembly failed')
    if mode == 'avx2' and not counts['ymm_montgomery_multiply']:
        raise ValueError('No AVX2 packed multiply instructions found')
    return {'binary_sha256': digest, 'expected_rustflags': FLAGS[mode],
            'instruction_counts': counts, 'instruction_examples': examples}


def read_trial(directory, mode):
    if mode not in FLAGS:
        raise ValueError('Unknown build mode')
    measurement = json.loads((directory / 'measurement.json').read_text())
    values = []
    for line in (directory / 'stdout.jsonl').read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('verified') is True:
            values.append(row)
    if len(values) != 1 or not measurement.get('resource_control_pass'):
        raise ValueError('Failed/incomplete trial; no automatic retry')
    row = values[0]
    expected_width = 8 if mode == 'avx2' else 1
    runtime = row.get('runtime', {})
    if (type(runtime.get('packing_width')) is not int
            or runtime['packing_width'] != expected_width):
        raise ValueError('Compiled field packing does not match build mode')
    if (runtime.get('compiled_avx2') is not (mode == 'avx2')
            or runtime.get('compiled_avx512f') is not False):
        raise ValueError('Compiled target features do not match build mode')
    if runtime.get('global_rayon_threads') != 2:
        raise ValueError('Actual global Rayon pool does not contain two workers')
    if (row.get('runtime', {}).get('rayon_num_threads') != '2'
            or row.get('runtime', {}).get('composition_hiding_workers') != '2'):
        raise ValueError('Worker environment mismatch')
    if (row.get('leaf_profile') != 'b' or row.get('jobs') != 1
            or row.get('topology') != 'fanin8' or row.get('slots') != 16
            or row.get('parameters') != {'suite': 'D4-W16', 'log_blowup': 2,
                                         'queries': 92, 'grinding': 16}
            or row.get('leaf_parameters') != {'suite': 'D4-W16', 'log_blowup': 4,
                                             'queries': 46, 'grinding': 16}):
        raise ValueError('D4-B configuration mismatch')
    qualification = measurement.get('hardware_qualification', {
        'profile': 'diagnostic', 'role': 'diagnostic', 'profile_qualified': False,
        'same_physical_instance_established': False})
    return {'mode': mode, 'verified': True, 'runtime': row['runtime'],
            'acceptance': False, 'hardware_qualification': qualification,
            'diagnostic_only': mode == 'scalar' or not qualification['profile_qualified'],
            'stages': row['stages'], 'batch_node_wall_ns': row['batch_node_wall_ns'],
            'batch_node_cpu_ticks': row.get('batch_node_cpu_ticks'),
            'proof_and_verify_ns': row['proof_and_verify_ns'],
            'cold_wall_ns': row['cold_wall_ns'],
            'memory_peak': measurement['memory_peak'],
            'swap_peak': measurement['swap_peak'],
            'memory_events_delta': measurement['memory_events_delta'],
            'cpu_summary': measurement.get('cpu_summary'),
            'cpu_limits': [{'scope': 'owned' if i == 0 else 'ancestor-' + str(i),
                'cpu.max': x['cpu.max'], 'cpuset.cpus.effective': x['cpuset.cpus.effective']}
                for i, x in enumerate(measurement['cpu_ancestry_before'])],
            'clock_ticks_per_second': os.sysconf('SC_CLK_TCK')}


def aggregate(trials):
    stages = [set(x['phase'] for x in row['stages']) for row in trials]
    if any(x != stages[0] for x in stages):
        raise ValueError('Inconsistent stage labels')
    return {'trials': len(trials), 'proof_and_verify_median_ns': statistics.median(
                row['proof_and_verify_ns'] for row in trials),
            'cold_median_ns': statistics.median(row['cold_wall_ns'] for row in trials),
            'memory_peak_median': statistics.median(row['memory_peak'] for row in trials),
            'memory_peak_max': max(row['memory_peak'] for row in trials),
            'stage_medians_ns': {phase: statistics.median(next(
                x['wall_ns'] for x in row['stages'] if x['phase'] == phase)
                for row in trials) for phase in sorted(stages[0])},
            'merge_medians_ns': [statistics.median(row['batch_node_wall_ns'][i]
                                  for row in trials) for i in range(2)]}


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scalar', type=Path,
        help='Explicit diagnostic-only scalar binary; omitted with --avx2-only')
    parser.add_argument('--avx2', type=Path, required=True)
    parser.add_argument('--avx2-only', action='store_true',
        help='Run only the three x86-64-v3 trials; do not run a scalar control')
    parser.add_argument('--hardware-profile',
        choices=('diagnostic', 'epyc7763-baseline', 'epyc9v45-control'), default='diagnostic')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.avx2_only and args.scalar is not None:
        parser.error('--scalar conflicts with --avx2-only')
    if not args.avx2_only and args.scalar is None:
        parser.error('Provide --scalar for a diagnostic comparison or select --avx2-only')
    return args


def main():
    args = parse_arguments()
    if os.geteuid() == 0:
        raise ValueError('Run orchestration as the unprivileged runner user')
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {'purpose': 'D4-B SIMD and resource-control comparison',
               'acceptance': False, 'same_live_runner': True,
               'original_runner_reused': False, 'hardware_profile': args.hardware_profile,
               'scalar_diagnostic_requested': not args.avx2_only, 'builds': {}, 'observations': []}
    builds = [('avx2', args.avx2)] if args.avx2_only else [('scalar', args.scalar), ('avx2', args.avx2)]
    for mode, binary in builds:
        binary = binary.resolve(strict=True)
        evidence = args.output / mode
        evidence.mkdir()
        worker = proof_worker(binary, mode)
        receipt['builds'][mode] = inspect_binary(worker, evidence, mode)
        receipt['builds'][mode]['cpu_check_launcher_sha256'] = (
            hashlib.sha256(binary.read_bytes()).hexdigest() if mode == 'avx2' else None)
        build = json.loads((ROOT / '.local/d4-build-evidence' / (mode + '-receipt.json')).read_text())
        verify_build_receipt(build, receipt['builds'][mode], mode)
        receipt['builds'][mode]['provenance'] = build
        for trial in range(1 if mode == 'scalar' else 3):
            directory = evidence / ('trial-' + str(trial + 1))
            command = ['sudo', '--preserve-env=RAYON_NUM_THREADS,SIWORLD_COMPOSITION_HIDING_WORKERS,SIWORLD_BENCH_PROFILE,GITHUB_ACTIONS',
                sys.executable, str(ROOT / 'scripts/measure-proof-cgroup.py'),
                '--output', str(directory), '--uid', str(os.getuid()),
                '--gid', str(os.getgid()), '--timeout', '900',
                '--hardware-profile', args.hardware_profile, '--',
                sys.executable, str(ROOT / 'scripts/validate-d4-cgroup.py'),
                '--binary', str(binary)]
            subprocess.run(command, check=True)
            value = read_trial(directory, mode)
            receipt['observations'].append(value)
            (args.output / 'comparison.json').write_text(json.dumps(receipt, indent=2) + '\n')
            print(json.dumps({'event': 'd4_trial', 'trial': trial + 1, **value}), flush=True)
    receipt['avx2_medians'] = aggregate([row for row in receipt['observations'] if row['mode'] == 'avx2'])
    if not args.avx2_only:
        scalar = receipt['observations'][0]['proof_and_verify_ns']
        receipt['same_runner_speedup'] = scalar / receipt['avx2_medians']['proof_and_verify_median_ns']
    (args.output / 'comparison.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'event': 'd4_comparison', **receipt}, indent=2))


if __name__ == '__main__':
    main()
