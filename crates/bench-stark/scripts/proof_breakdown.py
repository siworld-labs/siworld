#!/usr/bin/env python3
"""Splits a root proof (written by `--acc --dump-root PATH`) into Merkle digests, extension-field
values, and opened trace rows, counting field elements in each, to model how wider digests or a
larger extension change the size (docs/benchmarks.md).
Run: python3 scripts/proof_breakdown.py root.json [more.json ...]
"""

import json
import sys


def count_ints(x):
    if isinstance(x, int):
        return 1
    if isinstance(x, list):
        return sum(count_ints(e) for e in x)
    if isinstance(x, dict):
        return sum(count_ints(v) for k, v in x.items() if k not in ("_marker", "_phantom"))
    return 0


def classify(x, key, out):
    """Adds the field-element count of x to out[class]."""
    if key in ("sibling_hashes", "cap"):
        out["digests"] += count_ints(x)
    elif key == "value":
        out["extension values"] += count_ints(x)
    elif key == "opened_values" and isinstance(x, list) and x and isinstance(x[0], list):
        # input openings: per query, per matrix, one row of base-field values
        out["opened rows"] += count_ints(x)
    elif isinstance(x, dict):
        for k, v in x.items():
            classify(v, k, out)
    elif isinstance(x, list):
        for e in x:
            classify(e, key, out)
    elif isinstance(x, int):
        out["other"] += 1


def main():
    for path in sys.argv[1:]:
        proof = json.load(open(path))["proof"]
        out = {"digests": 0, "extension values": 0, "opened rows": 0, "other": 0}
        classify(proof, None, out)
        total = sum(out.values())
        print(f"{path}: {total} field elements ({total * 4 / 1024:.1f} KiB at 4 B each)")
        for k, v in out.items():
            print(f"  {k:<17}{v:>8}  {100 * v / total:5.1f}%")


if __name__ == "__main__":
    main()
