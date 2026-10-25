#!/usr/bin/env python3
"""Run the historical D4 B control exactly once; output is not acceptance."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('SIWORLD_COMPOSITION_HIDING_WORKERS') != '2':
        raise ValueError('Requires the isolated two-worker build')
    binary = str(args.binary.resolve(strict=True))
    base = [binary, '--topology', 'fanin8', '--jobs', '1', '--queries', '92',
            '--leaf-profile', 'b']
    with tempfile.TemporaryDirectory(prefix='siworld-d4-control-') as tmp:
        pin = str(Path(tmp) / 'leaf-pin.json')
        subprocess.run([*base, '--export-leaf-pin', pin], check=True, timeout=120)
        # No retry, smoke-parameter fallback or memory-budget override.
        subprocess.run([*base, '--leaf-pin', pin], check=True, timeout=750)
    print(json.dumps({'event': 'd4_harness_control_complete', 'acceptance': False,
                      'reason': 'D4/W16 fails security and lacks production readiness markers'}))


if __name__ == '__main__':
    main()
