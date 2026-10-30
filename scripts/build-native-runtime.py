#!/usr/bin/env python3
"""Build the isolated Linux native runtime behind the baseline CPU admission guard."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
NETWORK_COMMANDS = ['genesis-id', 'init-peer', 'peer-pin', 'run-network']

def package(worker, output, receipt, release, *, native_p2p=False):
    if output.exists():
        raise ValueError('Refusing to overwrite a release directory')
    if worker.name != 'siworld-native-node' or not worker.is_file() or not os.access(worker, os.X_OK):
        raise ValueError('Expected the native runtime executable')
    with worker.open('rb') as source:
        header = source.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
        raise ValueError('Expected Linux x86_64 ELF')
    release.validate_receipt(worker, receipt, release.digest(ROOT / '.cargo/config.toml'))
    features = ['native-p2p'] if native_p2p else []
    if receipt.get('cargo_default_features') is not True:
        raise ValueError('Native runtime build receipt mismatch: cargo_default_features')
    if receipt.get('cargo_features') != features:
        raise ValueError('Native runtime build receipt mismatch: cargo_features')
    expected = receipt['binary_sha256']
    isa = release.inspect_proof(worker)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-package-', dir=output.parent) as temporary:
        staging = Path(temporary) / 'release'
        (staging / 'bin').mkdir(parents=True)
        (staging / 'libexec').mkdir()
        launcher = staging / 'bin/siworld-native-node'
        subprocess.run(['rustc', str(ROOT / 'scripts/native-runtime-launcher.rs'),
                        '--edition=2021', '-O', '-D', 'warnings', '-C', 'target-cpu=x86-64',
                        '-o', str(launcher)], cwd=ROOT, check=True)
        installed = staging / 'libexec/siworld-native-node'
        shutil.copy2(worker, installed)
        if expected != release.digest(worker) or expected != release.digest(installed) or isa['binary_sha256'] != expected:
            raise ValueError('Native worker changed during packaging')
        bootstrap_sha256 = release.digest(launcher)
        help_smoke = None
        if native_p2p:
            result = subprocess.run([str(launcher), '--help'], cwd=staging, check=True,
                                    capture_output=True, text=True, timeout=30)
            commands = {line.split()[0] for line in result.stdout.splitlines() if line.split()}
            if not set(NETWORK_COMMANDS).issubset(commands):
                raise ValueError('Packaged native peer help is missing required commands')
            if (expected != release.digest(worker) or expected != release.digest(installed)
                    or bootstrap_sha256 != release.digest(launcher)):
                raise ValueError('Native worker or bootstrap changed during packaging')
            help_smoke = {
                'required_commands': NETWORK_COMMANDS,
                'help_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
                'worker_sha256': expected, 'bootstrap_sha256': bootstrap_sha256,
            }
        (staging / 'build-receipt.json').write_text(json.dumps({
            'worker': 'siworld-native-node', 'worker_isa': 'x86-64-v3',
            'bootstrap_isa': 'x86-64', 'bootstrap_sha256': bootstrap_sha256,
            'worker_build_receipt': receipt, 'isa_inspection': isa,
            'packaged_help_smoke': help_smoke,
        }, indent=2) + '\n')
        if output.exists():
            raise ValueError('Refusing to overwrite a release directory')
        staging.rename(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-p2p', action='store_true',
                        help='Include the opt-in pinned-peer listener and verify packaged peer commands')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('controlled_release', ROOT / 'scripts/build-prover-release.py')
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    release.validate_platform()
    release.validate_environment(os.environ)
    release.validate_config(tomllib.loads((ROOT / '.cargo/config.toml').read_text()))
    if args.output.exists():
        raise ValueError('Refusing to overwrite a release directory')
    manifest = ROOT / 'crates/native-node/Cargo.toml'
    features = ['native-p2p'] if args.native_p2p else []
    command = ['cargo', 'build', '--release', '--locked', '--manifest-path', str(manifest),
               '--bin', 'siworld-native-node']
    if features:
        command.extend(['--features', ','.join(features)])
    subprocess.run(command, cwd=ROOT, check=True)
    target = Path(os.environ.get('CARGO_TARGET_DIR', str(manifest.parent / 'target')))
    if not target.is_absolute():
        target = ROOT / target
    worker = target / 'release/siworld-native-node'
    receipt = {
        'binary_sha256': release.digest(worker),
        'effective_rustflags': ' '.join(release.V3_FLAGS),
        'cargo_working_directory': 'repository-root',
        'repository_config_sha256': release.digest(ROOT / '.cargo/config.toml'),
        'cargo_default_features': True,
        'cargo_features': features,
    }
    package(worker, args.output.resolve(), receipt, release, native_p2p=args.native_p2p)
    print(json.dumps({'worker': 'siworld-native-node', 'packaged': True}))

if __name__ == '__main__':
    main()
