#!/usr/bin/env python3
"""Extract internal D4 control shapes and pinned classical security reports.

Runs one isolated analysis process at a time. This is not a benchmark, a quantum
proof, or a production acceptance tool. Outputs and logs remain private.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
LAYERS = (("leaf", 16), ("eight_input", 2), ("root", 1))


def union_bits(terms):
    minimum = min(bits for bits, count in terms if count)
    return minimum - math.log2(sum(count * 2 ** (minimum - bits)
                                   for bits, count in terms))


def summarize(report):
    """Charge every named term and proof; never substitute UDR for Johnson."""
    summary = {"acceptance": False, "layers": {}}
    all_terms = {"conjectured": [], "proven_johnson": []}
    quantum_terms = []
    hash_ceiling = 8 * math.log2(2130706433) / 3
    for layer, count in LAYERS:
        data = report[layer]["report"]
        summary["layers"][layer] = {}
        for regime in all_terms:
            r = data[regime]
            if r is None:
                raise ValueError(f"Missing {regime} report: {layer}")
            terms = [(t["bits"], count) for t in r["terms"]
                     if isinstance(t["bits"], (int, float))]
            if not terms:
                raise ValueError("Empty finite security report")
            all_terms[regime].extend(terms)
            summary["layers"][layer][regime] = {
                "weakest_term": r["weakest_term"],
                "minimum_term_bits": r["minimum_term_bits"],
                "union_bits_one_proof": union_bits([(b, 1) for b, _ in terms]),
            }
        for term in data["conjectured"]["terms"]:
            if isinstance(term["bits"], (int, float)):
                bits = hash_ceiling if term["label"] == "commitment-collision" else term["bits"] / 2
                quantum_terms.append((bits, count))
    summary["composition_union_bits"] = {
        regime: union_bits(terms) for regime, terms in all_terms.items()
    }
    summary["illustrative_quantum_halving_screen_union_bits"] = union_bits(quantum_terms)
    summary["ideal_bht_collision_ceiling_bits"] = hash_ceiling
    summary["conclusion"] = "D4/W16 does not meet the post-quantum target"
    summary["limitations"] = [
        "common-domain batch envelopes are conservative screening inputs, not an exact batch theorem",
        "halving classical terms is an illustrative selected-model screen, not a QROM theorem",
        "grinding, transcript composition and multiplicity assumptions require independent analysis",
    ]
    return summary


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--leaf-b-pin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    pin = args.leaf_b_pin.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": 1, "binary_sha256": digest(binary),
               "b_pin_sha256": digest(pin), "script_sha256": digest(Path(__file__)),
               "p3_security_version": "0.9.0-rc.2", "runs": [],
               "measurement": False, "acceptance": False}
    for name, queries, profile in (("q42", 42, "uniform"),
                                   ("q92", 92, "uniform"), ("b", 92, "b")):
        target = output / f"{name}.json"
        command = [str(binary), "--topology", "fanin8", "--jobs", "1",
                   "--queries", str(queries), "--leaf-profile", profile,
                   "--security-output", str(target)]
        if profile == "b":
            command.extend(["--leaf-pin", str(pin)])
        with (output / f"{name}.stdout").open("x") as stdout, \
                (output / f"{name}.stderr").open("x") as stderr:
            result = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr,
                                    timeout=600, env={**os.environ, "RAYON_NUM_THREADS": "2",
                                    "SIWORLD_COMPOSITION_HIDING_WORKERS": "1"})
        run = {"profile": name, "exit_code": result.returncode, "command": command,
               "purpose": "actual shape extraction; one native hiding worker; not timing evidence"}
        receipt["runs"].append(run)
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if result.returncode != 0:
            raise SystemExit(f"{name} analysis failed; inspect private logs; no retry")
        report = json.loads(target.read_text())
        if report["p3_security_version"] != "0.9.0-rc.2" or report["parent_queries"] != queries:
            raise SystemExit("analysis configuration mismatch")
        run["report_sha256"] = digest(target)
        (output / f"{name}-summary.json").write_text(json.dumps(summarize(report), indent=2) + "\n")
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"{name}: shape report complete; D4/W16 rejected", flush=True)


if __name__ == "__main__":
    main()
