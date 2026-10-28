#!/usr/bin/env python3
"""Print only synthetic phase/resource aggregates; never upload raw logs."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    memory = json.loads((args.directory / 'measurement.json').read_text())
    values = []
    for line in (args.directory / 'stdout.jsonl').read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('verified') is True:
            values.append(row)
    if len(values) != 1 or not memory.get('resource_control_pass'):
        raise SystemExit('Control failed or incomplete; inspect retained runner evidence; no retry')
    row = values[0]
    if row['leaf_profile'] != 'b' or row['parameters']['queries'] != 92 or row['jobs'] != 1:
        raise SystemExit('Control configuration mismatch')
    print(json.dumps({'purpose': 'D4-B measurement-script validation only', 'acceptance': False,
        'verified': True, 'stages': row['stages'], 'batch_node_wall_ns': row['batch_node_wall_ns'],
        'cold_wall_ns': row['cold_wall_ns'], 'proof_and_verify_ns': row['proof_and_verify_ns'],
        'memory_peak': memory['memory_peak'], 'memory_events_delta': memory['memory_events_delta'],
        'hardware': memory['hardware']}, indent=2))


if __name__ == '__main__':
    main()
