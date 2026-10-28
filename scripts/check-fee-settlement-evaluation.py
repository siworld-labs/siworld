#!/usr/bin/env python3
"""Validate a native confidential-fee settlement measurement bundle.

This is an evidence validator only. It never starts a prover, changes a node,
or turns the research Scheme B direction into a consensus rule. Keep bundles
under an ignored private evidence directory; only this validator and its
schema belong in the repository.
"""

import argparse
import json
import sys
from pathlib import Path


SUITE = "KoalaBear-D8-Poseidon2-W24-digest12"
CAPACITIES = (64, 128, 256, 384, 512, 576)
TRIAL_FIELDS = (
    "generation_ms",
    "verification_ms",
    "proof_bytes",
    "prover_peak_bytes",
    "verifier_peak_bytes",
)
SHAPE_FIELDS = (
    "air_rows",
    "main_columns",
    "preprocessed_columns",
    "constraint_count",
    "max_constraint_degree",
)


def schema():
    return {
        "schema": 1,
        "suite": SUITE,
        "commitment_bytes_per_transaction": 48,
        "capacities": list(CAPACITIES),
        "records": [
            {
                "capacity": 576,
                "shape": {field: 0 for field in SHAPE_FIELDS},
                "trials": [{field: 0 for field in TRIAL_FIELDS} for _ in range(3)],
                "artifacts": {
                    "air_source_sha256": "<64 lowercase hex>",
                    "verifier_key_sha256": "<64 lowercase hex>",
                    "binary_sha256": "<64 lowercase hex>",
                },
            }
        ],
        "measurement": {
            "memory_max_bytes": None,
            "swap_max_bytes": None,
            "setup_excluded": True,
        },
    }


def integer(value, field):
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")


def validate(data):
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("schema must be 1")
    if data.get("suite") != SUITE:
        raise ValueError("suite must be D8/W24/digest12")
    if data.get("commitment_bytes_per_transaction") != 48:
        raise ValueError("the fee commitment must be 48 bytes")
    measurement = data.get("measurement")
    if not isinstance(measurement, dict):
        raise ValueError("measurement section is required")
    for field in ("memory_max_bytes", "swap_max_bytes"):
        value = measurement.get(field)
        if value is not None:
            integer(value, f"measurement.{field}")
    if measurement.get("setup_excluded") is not True:
        raise ValueError("one-time setup must be excluded only when resident")
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError("records must be a list")
    by_capacity = {record.get("capacity"): record for record in records
                   if isinstance(record, dict)}
    if set(by_capacity) != set(CAPACITIES):
        raise ValueError(f"records must cover capacities {CAPACITIES}")
    for capacity in CAPACITIES:
        record = by_capacity[capacity]
        shape = record.get("shape")
        if not isinstance(shape, dict):
            raise ValueError(f"shape missing for capacity {capacity}")
        for field in SHAPE_FIELDS:
            integer(shape.get(field), f"{capacity}.shape.{field}")
        trials = record.get("trials")
        if not isinstance(trials, list) or len(trials) != 3:
            raise ValueError(f"capacity {capacity} needs exactly three trials")
        for index, trial in enumerate(trials):
            if not isinstance(trial, dict):
                raise ValueError(f"trial {capacity}/{index} is not an object")
            for field in TRIAL_FIELDS:
                integer(trial.get(field), f"{capacity}/{index}.{field}")
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ValueError(f"artifacts missing for capacity {capacity}")
        for field in ("air_source_sha256", "verifier_key_sha256", "binary_sha256"):
            value = artifacts.get(field)
            if not isinstance(value, str) or len(value) != 64 or any(
                    character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{capacity}.artifacts.{field} must be SHA-256")
    return by_capacity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", type=Path)
    parser.add_argument("--schema", action="store_true")
    args = parser.parse_args()
    if args.schema:
        print(json.dumps(schema(), indent=2, sort_keys=True))
        return 0
    if args.bundle is None:
        parser.error("a private measurement bundle is required unless --schema is used")
    try:
        data = json.loads(args.bundle.read_text(encoding="utf-8"))
        validate(data)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"invalid settlement evidence: {error}", file=sys.stderr)
        return 1
    print("Settlement evidence schema and three-trial capacity coverage validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
