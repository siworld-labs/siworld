#!/usr/bin/env python3
"""Validate and select from a native V1 transaction-proof measurement bundle.

This tool consumes measurements; it does not launch a prover or change a network.
Every artifact reference is {"path": "bundle-relative-path", "sha256": "..."}.
The manifest pins AIR source, dependency lock, codec and executable artifacts.
Each of the 15 rows pins its actual AIR shape, verification key, p3-security
report, failing q-1 report and three trials for each measurement operation.

Reports contain the raw conjectured and Johnson term lists from p3-security,
not a recursive checkpoint screen. The selected-model quantum ledger halves
Johnson challenge exponents and converts classical collision exponents to BHT
exponents by 2/3. This is a screening model, not an independent security review,
a QROM theorem, consensus activation or a production acceptance certificate.

Use --schema to inspect the required fields before collecting evidence. Keep
raw measurements and the output under an ignored private evidence directory.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys


SCOPE = "v1-production-transaction-air"
SUITE = "KoalaBear-D8-Poseidon2-W24-digest12"
P3_SECURITY = "0.9.0-rc.2"
ACCOUNTING = "single-proof-johnson-halving-bht-v1"
BLOWUPS = tuple(range(4, 9))
GRINDING = (16, 20, 24)
TRIAL_WORKERS = {"single_worker": 1, "four_worker": 4, "verification": 1}
REQUIRED_ARTIFACTS = ("air_source", "dependencies", "codec", "binary")
REQUIRED_SHAPE = ("base_trace_rows", "main_width", "preprocessed_width",
    "public_values", "num_constraints", "max_constraint_degree",
    "num_quotient_chunks", "num_batched_functions", "log_committed_trace_length",
    "challenge_field_bits_floor", "classical_collision_bits_floor")
REQUIRED_JOHNSON_TERMS = {"air-composition", "deep-ali", "low-degree-test",
    "batch-combination", "commitment-collision"}
REQUIRED_DOMAIN_TERMS = {"ood-deep-ali-domain", "fri-folding-domain"}
MAX_GENERATION_NS = 2_000_000_000
LINK_BPS = 20_000_000
BLOCK_SECONDS = 300
RELAY_FACTOR = 3
DIRECTED_BODY_CAPS = {576: 431029, 512: 485283}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
APPLICATION_BINDING = {
    "algorithm": "BLAKE3-256",
    "digest_bytes": 32,
    "nominal_classical_collision_bits": 128,
    "nominal_bht_collision_bits": 256 / 3,
    "included_in_p3_security_report": False,
    "model_status": "nominal-collision-model-requires-review",
}


def canonical_digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()
    return hashlib.sha256(data).hexdigest()


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def equal(value, expected, name):
    if type(value) is not type(expected) or value != expected:
        raise ValueError(f"{name} differs from the pinned value")


def bundle_file(base, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ValueError("artifact path must be bundle-relative")
    if ".." in Path(name).parts:
        raise ValueError("artifact path cannot escape the bundle")
    root = base.resolve(strict=True)
    try:
        result = (root / name).resolve(strict=True)
    except OSError as error:
        raise ValueError("artifact path is missing") from error
    if root not in result.parents or not result.is_file():
        raise ValueError("artifact path cannot escape the bundle")
    return result


def artifact(base, ref):
    if not isinstance(ref, dict) or not SHA256.fullmatch(str(ref.get("sha256", ""))):
        raise ValueError("artifact needs a lowercase SHA-256 hash")
    path = bundle_file(base, ref.get("path"))
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != ref["sha256"]:
        raise ValueError(f"artifact hash mismatch: {ref['path']}")
    return data


def json_artifact(base, ref):
    try:
        data = json.loads(artifact(base, ref))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("artifact is not valid JSON") from error
    if not isinstance(data, dict):
        raise ValueError("evidence JSON must be an object")
    return data


def finite_bits(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a nonnegative finite bit bound")
    return float(value)


def union_bits(values):
    finite = [v for v in values if math.isfinite(v)]
    if not finite:
        raise ValueError("security terms contain no finite bound")
    minimum = min(finite)
    return minimum - math.log2(sum(2 ** (minimum - v) for v in finite))


def body_capacity(positions, fixed_len):
    """Integer proof-body cap; fixed fields are counted exactly once."""
    integer(positions, "positions", 1)
    integer(fixed_len, "tx_fixed_len", 1)
    return LINK_BPS * BLOCK_SECONDS // (positions * 8 * RELAY_FACTOR) - fixed_len


def validate_parameters(params):
    if not isinstance(params, dict):
        raise ValueError("missing FRI parameters")
    for name in ("log_blowup", "num_queries", "query_pow_bits", "batch_pow_bits",
                 "commit_pow_bits", "max_log_arity", "log_final_poly_len"):
        integer(params.get(name), name)
    if params["log_blowup"] not in BLOWUPS or params["query_pow_bits"] not in GRINDING:
        raise ValueError("parameters are outside the 15-pair scan grid")
    equal(params["batch_pow_bits"], params["query_pow_bits"], "batch grinding")
    equal(params["commit_pow_bits"], 0, "commit grinding")
    equal(params["log_final_poly_len"], 0, "final polynomial length")
    if not 1 <= params["max_log_arity"] <= 3 or params["num_queries"] < 2:
        raise ValueError("invalid FRI arity or query count")


def validate_shape(shape):
    if not isinstance(shape, dict) or shape.get("status") != "actual-extracted":
        raise ValueError("AIR shape must be actual-extracted")
    for name in REQUIRED_SHAPE:
        integer(shape.get(name), f"shape.{name}", 0 if name == "preprocessed_width" else 1)
    for name in ("base_trace_rows", "num_quotient_chunks"):
        if shape[name] & (shape[name] - 1):
            raise ValueError(f"shape.{name} must be a power of two")
    equal(shape["challenge_field_bits_floor"], 247, "D8 challenge field")
    # KoalaBear's 12-element digest/capacity has >371 entropy bits. The
    # p3-security collision input conservatively floors half of that to 185.
    equal(shape["classical_collision_bits_floor"], 185, "W24/digest12 collision floor")
    if 2 ** shape["log_committed_trace_length"] < shape["base_trace_rows"]:
        raise ValueError("committed trace cannot be shorter than the base trace")


def validate_binding(data, binding):
    for name, expected in binding.items():
        equal(data.get(name), expected, name)
    equal(data.get("schema"), 1, "evidence schema")
    equal(data.get("scope"), SCOPE, "evidence scope")
    equal(data.get("actual_production_air"), True, "actual_production_air")


def terms(report, name, required):
    if not isinstance(report, dict) or not isinstance(report.get("terms"), list):
        raise ValueError(f"missing {name} terms; Johnson cannot use a UDR substitute")
    result = {}
    for term in report["terms"]:
        if not isinstance(term, dict):
            raise ValueError(f"invalid {name} term")
        label = text(term.get("label"), f"{name} label")
        if label in result:
            raise ValueError(f"duplicate {name} term")
        result[label] = finite_bits(term.get("bits"), f"{name}.{label}")
    if not required <= result.keys():
        raise ValueError(f"missing {name} terms: {sorted(required - result.keys())}")
    return result


def summarize_security(data, binding, shape):
    validate_binding(data, binding)
    equal(data.get("p3_security_version"), P3_SECURITY, "p3-security version")
    equal(data.get("accounting"), ACCOUNTING, "single-proof security accounting")
    equal(data.get("application_binding"), APPLICATION_BINDING, "application binding")
    equal(data.get("shape"), shape, "actual AIR security shape")
    equal(data.get("fri"), binding["parameters"], "actual FRI security parameters")
    grinding = data.get("grinding_sites", {})
    equal(grinding.get("batch_combination"), binding["parameters"]["batch_pow_bits"],
          "actual batching grinding")
    equal(grinding.get("out_of_domain"), 0, "actual OOD grinding")
    equal(grinding.get("lookup_challenge"), 0, "actual lookup grinding")
    conjectured = terms(data.get("conjectured"), "conjectured", {"air-composition",
        "deep-ali", "batch-combination", "commitment-collision"})
    johnson = terms(data.get("proven_johnson"), "Johnson", REQUIRED_JOHNSON_TERMS)
    fri_terms = terms({"terms": data.get("johnson_fri_terms")}, "Johnson FRI",
                      {"fri-folding", "fri-query"})
    folds = integer(data.get("fri_folding_rounds"), "FRI folding round upper bound", 1)
    equal(folds, shape["log_committed_trace_length"] + 1, "FRI folding round upper bound")
    domain = terms({"terms": data.get("challenge_domain_terms")}, "challenge domain",
                   REQUIRED_DOMAIN_TERMS)
    # Reject a report that silently raises the suite's fixed collision ceiling.
    hash_bits = min(conjectured["commitment-collision"], johnson["commitment-collision"])
    if not math.isfinite(hash_bits) or hash_bits > shape["classical_collision_bits_floor"]:
        raise ValueError("commitment collision report exceeds its fixed suite ceiling")
    # Replace p3's round-by-round LDT minimum by explicit query and folding
    # terms. Charge every possible folding round after halving its exponent;
    # charging log2(rounds) before halving would undercharge multiplicity.
    quantum_terms = {label: bits / 2 for label, bits in johnson.items()
                     if label not in ("commitment-collision", "low-degree-test")}
    quantum_terms["fri-query"] = fri_terms["fri-query"] / 2
    quantum_terms["fri-folding"] = fri_terms["fri-folding"] / 2 - math.log2(folds)
    bht = hash_bits * 2 / 3
    result = {
        "classical_conjectured_union_bits": union_bits(conjectured.values()),
        "classical_johnson_union_bits": union_bits(johnson.values()),
        "quantum_johnson_challenge_union_bits": union_bits(quantum_terms.values()),
        "quantum_johnson_challenge_terms": quantum_terms,
        "quantum_challenge_domain_terms": {label: bits / 2 for label, bits in domain.items()},
        "bht_collision_bits": bht,
        "bht_collision_scope": "W24 PCS commitment only; excludes the application byte binding",
        "application_binding": APPLICATION_BINDING,
        "nominal_minimum_hash_bht_bits": min(bht, APPLICATION_BINDING["nominal_bht_collision_bits"]),
        "weakest_quantum_challenge_term": min(quantum_terms, key=quantum_terms.get),
        "conjectured_terms": conjectured,
        "johnson_terms": johnson,
        "johnson_fri_terms": fri_terms,
        "fri_folding_rounds": folds,
    }
    rejections = []
    for label, actual, target in [
        ("classical conjectured", result["classical_conjectured_union_bits"], 128),
        ("classical Johnson", result["classical_johnson_union_bits"], 100),
        ("quantum Johnson challenge union", result["quantum_johnson_challenge_union_bits"], 80),
        ("BHT collision", bht, 80),
    ]:
        if actual < target:
            rejections.append(f"{label} below {target} bits")
    for label, bits in quantum_terms.items():
        if bits < 80:
            rejections.append(f"quantum Johnson term {label} below 80 bits")
    for label, bits in result["quantum_challenge_domain_terms"].items():
        if bits < 80:
            rejections.append(f"quantum challenge domain {label} below 80 bits")
    return result, rejections


def validate_trial(data, binding, operation, index, manifest, seen):
    validate_binding(data, binding)
    equal(data.get("operation"), operation, "trial operation")
    workers = TRIAL_WORKERS[operation]
    equal(data.get("workers"), workers, "actual workers")
    equal(data.get("rayon_threads"), workers, "actual RAYON_NUM_THREADS")
    equal(data.get("trial_index"), index, "trial_index")
    equal(data.get("exit_code"), 0, "trial exit code")
    equal(data.get("verified"), True, "proof verification")
    equal(data.get("measurement_kind"), "actual-native-proof", "measurement kind")
    equal(data.get("public_transaction_bytes"), 1742, "actual public transaction bytes")
    # An inherited quota can make a four-worker result incomparable even when
    # the child cgroup itself has no limit. Collection must record effective
    # ancestor quota in this field, with max meaning no effective quota.
    quota = text(data.get("cpu_max"), "effective cpu.max").split()
    if len(quota) != 2 or quota[0] != "max" or not quota[1].isdigit():
        raise ValueError("effective cpu.max must be unthrottled for scan trials")
    run_id = text(data.get("run_id"), "trial run_id")
    if run_id in seen:
        raise ValueError("duplicate trial run_id")
    seen.add(run_id)
    for name in ("wall_ns", "memory_peak_bytes", "proof_body_bytes"):
        integer(data.get(name), name, 1)
    equal(data["machine_id"], manifest["measurement_host"]["machine_id"], "same machine")
    return {name: data[name] for name in ("wall_ns", "memory_peak_bytes", "proof_body_bytes")}


def validate_manifest(manifest, base):
    if not isinstance(manifest, dict):
        raise ValueError("scan manifest must be an object")
    for name, value in {"schema": 1, "scope": SCOPE, "suite": SUITE,
        "actual_production_air": True, "public_transaction_bytes": 1742,
        "inputs": 2, "outputs": 2, "anchor_membership_depth": 12,
        "anchor_public_statement": "recent-root-only", "p3_security_version": P3_SECURITY}.items():
        equal(manifest.get(name), value, name)
    for name in ("air_version", "codec_version"):
        text(manifest.get(name), name)
    integer(manifest.get("tx_fixed_len"), "actual tx_fixed_len", 1742)
    host = manifest.get("measurement_host", {})
    equal(host.get("qualified"), True, "qualified measurement host")
    for name in ("machine_id", "cpu_model", "isa"):
        text(host.get(name), f"measurement_host.{name}")
    integer(host.get("vcpus"), "host vcpus", 4)
    pins = manifest.get("artifacts")
    if not isinstance(pins, dict) or not set(REQUIRED_ARTIFACTS) <= pins.keys():
        raise ValueError("missing source/dependency/codec/binary artifact pins")
    for ref in pins.values():
        artifact(base, ref)
    rows = manifest.get("rows")
    if not isinstance(rows, list) or len(rows) != 15:
        raise ValueError("scan requires all 15 log-blowup/grinding pairs")
    pairs = []
    for row in rows:
        validate_parameters(row.get("parameters"))
        pairs.append((row["parameters"]["log_blowup"], row["parameters"]["query_pow_bits"]))
    if len(set(pairs)) != 15 or set(pairs) != {(b, g) for b in BLOWUPS for g in GRINDING}:
        raise ValueError("duplicate or missing scan grid pair")
    return pins


def evaluate(manifest, base):
    pins = validate_manifest(manifest, base)
    rows, seen_runs, seen_paths = [], set(), set()
    for row in manifest["rows"]:
        params, shape = row["parameters"], row.get("air_shape")
        validate_shape(shape)
        if 1 << params["log_blowup"] < shape["max_constraint_degree"]:
            raise ValueError("blowup is insufficient for the actual constraint degree")
        vk = row.get("verification_key")
        artifact(base, vk)
        binding = {"suite": SUITE, "air_version": manifest["air_version"],
            "codec_version": manifest["codec_version"], "parameters": params,
            "air_shape_sha256": canonical_digest(shape),
            "verification_key_sha256": vk["sha256"],
            "machine_id": manifest["measurement_host"]["machine_id"]}
        binding.update({f"{key}_sha256": pins[key]["sha256"] for key in REQUIRED_ARTIFACTS})
        security, rejections = summarize_security(json_artifact(base, row.get("security")), binding, shape)
        previous = json_artifact(base, row.get("previous_query_security"))
        previous_shape = previous.get("shape")
        validate_shape(previous_shape)
        previous_params = {**params, "num_queries": params["num_queries"] - 1}
        previous_binding = {**binding, "parameters": previous_params,
                            "air_shape_sha256": canonical_digest(previous_shape)}
        _, previous_rejections = summarize_security(previous, previous_binding, previous_shape)
        if not previous_rejections:
            raise ValueError("q-1 report passes; minimum query boundary has not been established")
        measurements = {}
        body_lengths = []
        groups = row.get("trials", {})
        for operation in TRIAL_WORKERS:
            refs = groups.get(operation)
            if not isinstance(refs, list) or len(refs) != 3:
                raise ValueError(f"{operation} requires exactly three trials")
            samples = []
            for index, ref in enumerate(refs, 1):
                path = str(bundle_file(base, ref.get("path")))
                if path in seen_paths:
                    raise ValueError("duplicate trial artifact path")
                seen_paths.add(path)
                trial = validate_trial(json_artifact(base, ref), binding, operation,
                                       index, manifest, seen_runs)
                samples.append(trial)
                body_lengths.append(trial["proof_body_bytes"])
            measurements[operation] = {
                "median_ns": int(statistics.median(s["wall_ns"] for s in samples)),
                "max_ns": max(s["wall_ns"] for s in samples),
                "memory_peak_bytes": max(s["memory_peak_bytes"] for s in samples),
                "trials": samples,
            }
        if measurements["four_worker"]["median_ns"] > MAX_GENERATION_NS:
            rejections.append("four-worker generation median exceeds 2 seconds")
        rows.append({"parameters": params, "air_shape_sha256": binding["air_shape_sha256"],
            "verification_key_sha256": vk["sha256"], "security": security,
            "proof_body_bytes_max": max(body_lengths),
            "proof_body_bytes_median": int(statistics.median(body_lengths)),
            "measurements": measurements, "eligible": not rejections,
            "rejections": rejections})
    fixed = manifest["tx_fixed_len"]
    actual_caps = {n: body_capacity(n, fixed) for n in (576, 512)}
    # Retain the explicitly directed 431,029-byte trigger even when the new
    # fixed codec saves bytes. A codec reduction is protocol headroom, not an
    # automatic authorization to raise the selected proof-body threshold.
    caps = {n: min(DIRECTED_BODY_CAPS[n], actual_caps[n]) for n in (576, 512)}
    eligible = [row for row in rows if row["eligible"]]
    # Larger blowups have all been measured before a capacity reduction is
    # allowed. Size is the primary objective; deterministic tie-breaks favor
    # larger blowup, lower runtime, then lower query/batch grinding.
    order = lambda row: (row["proof_body_bytes_max"], -row["parameters"]["log_blowup"],
                        row["measurements"]["four_worker"]["median_ns"],
                        row["parameters"]["query_pow_bits"])
    selected, positions, decision = None, None, "blocked-no-eligible-parameter"
    for n in (576, 512):
        fits = [row for row in eligible if row["proof_body_bytes_max"] <= caps[n]]
        if fits:
            selected, positions = min(fits, key=order), n
            decision = "candidate-selected" if n == 576 else "capacity-reduced-to-512"
            break
    if eligible and selected is None:
        decision = "blocked-bandwidth"
    choice = None
    if selected:
        p = selected["proof_body_bytes_max"]
        verify = selected["measurements"]["verification"]
        choice = {"parameters": selected["parameters"],
            "max_leaf_proof_len_body_bytes": p, "tx_max_len_bytes": fixed + p,
            "generation_four_worker_median_ns": selected["measurements"]["four_worker"]["median_ns"],
            "generation_four_worker_peak_bytes": selected["measurements"]["four_worker"]["memory_peak_bytes"],
            "verification_median_ns": verify["median_ns"],
            "verification_max_ns": verify["max_ns"],
            "verification_peak_bytes": verify["memory_peak_bytes"],
            "mempool_transactions_per_gib_of_encoded_bytes": (1 << 30) // (fixed + p),
            "verification_workers_per_gib_of_measured_peak": (1 << 30) // verify["memory_peak_bytes"],
            "verification_cpu_seconds_per_transaction": verify["median_ns"] / 1_000_000_000,
            "security": selected["security"],
            "air_shape_sha256": selected["air_shape_sha256"],
            "verification_key_sha256": selected["verification_key_sha256"]}
    return {"schema": 1, "scope": SCOPE, "suite": SUITE,
        "air_version": manifest["air_version"], "codec_version": manifest["codec_version"],
        "manifest_sha256": canonical_digest(manifest), "p3_security_version": P3_SECURITY,
        "accounting": ACCOUNTING, "decision": decision, "selected": choice,
        "capacity": {"positions": positions, "block_interval_seconds": BLOCK_SECONDS,
            "link_mbps": 20, "relay_factor": RELAY_FACTOR, "tx_fixed_len": fixed,
            "proof_body_cap_at_576_bytes": caps[576], "proof_body_cap_at_512_bytes": caps[512],
            "directed_body_caps_bytes": {str(n):DIRECTED_BODY_CAPS[n] for n in (576,512)},
            "actual_bandwidth_body_caps_bytes": {str(n):actual_caps[n] for n in (576,512)},
            "relay_mbps": (positions * (fixed + choice["max_leaf_proof_len_body_bytes"]) *
                8 * RELAY_FACTOR / BLOCK_SECONDS / 1_000_000) if choice else None,
            "protocol_headroom_mbps": (20 - positions * (fixed + choice["max_leaf_proof_len_body_bytes"]) *
                8 * RELAY_FACTOR / BLOCK_SECONDS / 1_000_000) if choice else None,
            "requires_owner_report": decision != "candidate-selected"},
        "rows": rows, "cryptographic_approval": False, "network_activation": False,
        "budget_status": "measurement inputs only; choose explicit node CPU/RAM/byte budgets before setting admission constants",
        "limitations": ["Selected-model quantum accounting requires independent review",
            "p3-security does not analyze the external BLAKE3-256 ciphertext-byte binding; its nominal classical collision exponent is 128 and nominal BHT exponent is 256/3",
            "The full relation/PCS/application-hash composition and the external binding assumptions require review; a nominal minimum of hash exponents is not a composition theorem",
            "The largest observed encoded body is a candidate cap; the versioned codec must prove a deterministic maximum",
            "Measured proof size and wall time do not establish mempool or verifier memory bounds",
            "The 20 Mbps calculation has no protocol-traffic reserve; report remaining bandwidth margin"]}


def schema_description():
    return {"schema": 1, "scope": SCOPE, "suite": SUITE,
        "actual_production_air": True, "air_version": "required", "codec_version": "required",
        "public_transaction_bytes": 1742, "inputs": 2, "outputs": 2,
        "anchor_membership_depth": 12, "anchor_public_statement": "recent-root-only",
        "p3_security_version": P3_SECURITY, "accounting": ACCOUNTING,
        "application_binding": APPLICATION_BINDING,
        "artifact_reference": {"path": "relative/path", "sha256": "lowercase SHA-256"},
        "required_artifacts": REQUIRED_ARTIFACTS, "required_shape_fields": REQUIRED_SHAPE,
        "grid": {"log_blowup": BLOWUPS, "query_pow_bits": GRINDING,
            "batch_pow_bits": "same as query_pow_bits", "commit_pow_bits": 0,
            "log_final_poly_len": 0},
        "row_fields": ["parameters", "air_shape", "verification_key", "security",
                       "previous_query_security", "trials"],
        "trials_per_operation": 3, "trial_workers": TRIAL_WORKERS,
        "security_report_fields": ["conjectured.terms", "proven_johnson.terms",
            "johnson_fri_terms", "fri_folding_rounds",
            "challenge_domain_terms", "shape", "fri", "all trial binding fields"],
        "trial_fields": ["schema", "scope", "suite", "actual_production_air", "air_version",
            "codec_version", "parameters", "air_shape_sha256", "air_source_sha256",
            "dependencies_sha256", "codec_sha256", "binary_sha256", "verification_key_sha256",
            "machine_id", "operation", "workers", "rayon_threads", "trial_index", "run_id",
            "exit_code", "verified", "proof_body_bytes", "wall_ns", "memory_peak_bytes",
            "cpu_max", "public_transaction_bytes", "measurement_kind"],
        "measurement_kind": "actual-native-proof", "shape_status": "actual-extracted",
        "required_domain_labels": sorted(REQUIRED_DOMAIN_TERMS),
        "notes": ["No proxy, shape estimate, recursive union or cached screen substitutes",
                  "No network action is performed", "Keep evidence private"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="Private bundle directory containing manifest.json")
    parser.add_argument("--output", type=Path, help="New private output JSON path; stdout if omitted")
    parser.add_argument("--schema", action="store_true", help="Describe the evidence contract")
    args = parser.parse_args()
    if args.schema:
        if args.bundle or args.output:
            parser.error("--schema cannot collect or write measurement evidence")
        print(json.dumps(schema_description(), indent=2))
        return
    if not args.bundle:
        parser.error("--bundle is required unless --schema is used")
    try:
        base = args.bundle.resolve(strict=True)
        manifest = json.loads(bundle_file(base, "manifest.json").read_text())
        result = evaluate(manifest, base)
        data = json.dumps(result, indent=2, allow_nan=False) + "\n"
        if args.output:
            with args.output.open("x") as output:
                output.write(data)
        else:
            sys.stdout.write(data)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        parser.exit(2, f"V1 transaction scan rejected: {error}\n")
    if result["selected"] is None:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
