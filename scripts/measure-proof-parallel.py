#!/usr/bin/env python3
"""Compare serial and two-worker cold-tree aggregation runs.

Build once, then time the same isolated aggregation binary. Process wall time
and peak RSS include setup; aggregation time is reported separately. Synthetic
measurements do not establish a production or 60-second acceptance claim.
"""

import argparse
import json
import os
import re
import hashlib
import signal
import statistics
import subprocess
import sys
import time
import platform
from pathlib import Path


BASELINE_MS = 106_000
DEFAULT_RSS_BUDGET = 3 << 30


def rss_bytes(stderr: str):
    # macOS: "maximum resident set size"; GNU time: "Maximum resident set size (kbytes)".
    match = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", stderr, re.M)
    if match:
        return int(match.group(1))
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
    if match:
        return int(match.group(1)) * 1024
    return None


def run_once(parallel, args):
    command = [str(args.binary), "--slots", str(args.slots), "--parallel", str(parallel)]
    wrapped = ["/usr/bin/time", "-l" if sys.platform == "darwin" else "-v", *command]
    started = time.monotonic()
    process = subprocess.Popen(wrapped, cwd=args.root, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True,
                               env={**os.environ, "RAYON_NUM_THREADS": str(args.rayon_threads)})
    try:
        stdout, stderr = process.communicate(timeout=args.timeout_secs)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        return {"status": "timed_out", "parallel": parallel,
                "stderr_tail": stderr[-2000:]}
    completed = subprocess.CompletedProcess(wrapped, process.returncode, stdout, stderr)
    elapsed_ms = round((time.monotonic() - started) * 1000)
    report = None
    for line in reversed(completed.stdout.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and "schema" in candidate:
            report = candidate
            break
    valid = (isinstance(report, dict) and report.get("schema") == 2
             and report.get("verified") is True and report.get("container_size") == args.slots
             and report.get("parallel") == parallel
             and type(report.get("aggregation_ms")) is int and report["aggregation_ms"] > 0
             and report.get("parameters") == {"suite": "classical-D4-W16", "log_blowup": 2, "queries": 42, "grinding": 16})
    peak_rss = rss_bytes(completed.stderr)
    footprint = re.search(r"^\s*(\d+)\s+peak memory footprint\s*$", completed.stderr, re.M)
    peak_footprint = int(footprint.group(1)) if footprint else None
    memory_complete = sys.platform != "darwin" or (peak_footprint is not None and peak_footprint > 0)
    return {
        "status": "passed" if completed.returncode == 0 and valid and peak_rss is not None and peak_rss > 0 and memory_complete else "failed",
        "parallel": parallel,
        "returncode": completed.returncode,
        "wall_ms": elapsed_ms,
        "peak_rss_bytes": peak_rss,
        "peak_footprint_bytes": peak_footprint,
        "accounted_peak_bytes": max(peak_rss or 0, peak_footprint or 0) or None,
        "pipeline": report,
        "stderr_tail": completed.stderr[-2000:],
    }


def summarize(results, budget):
    passed = [r for r in results if r.get("status") == "passed"]
    walls = [r["pipeline"]["aggregation_ms"] for r in passed]
    rss = [r["peak_rss_bytes"] for r in passed if r.get("peak_rss_bytes") is not None]
    accounted = [r["accounted_peak_bytes"] for r in passed if r.get("accounted_peak_bytes") is not None]
    return {
        "samples": len(passed),
        "aggregation_ms": {
            "p50": statistics.median(walls) if walls else None,
            "p95": sorted(walls)[max(0, (95 * len(walls) + 99) // 100 - 1)] if walls else None,
        },
        "peak_rss_bytes": max(rss) if rss else None,
        "accounted_peak_bytes": max(accounted) if accounted else None,
        "os_rss_samples": len(rss),
        "rss_budget_bytes": budget,
        "rss_budget_status": ("exceeded" if accounted and max(accounted) > budget else (
            "within" if accounted and len(accounted) == len(passed) else "unknown")),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--slots", type=int, default=32)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--rayon-threads", type=int, default=2)
    parser.add_argument("--timeout-secs", type=int, default=1800)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--rss-budget-bytes", type=int, default=DEFAULT_RSS_BUDGET)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if (args.repetitions < 1 or args.slots not in (2, 4, 8, 16, 32, 64, 128)
            or args.rayon_threads < 1 or args.timeout_secs < 1 or args.rss_budget_bytes < 1):
        parser.error("repetitions and slots must be positive")

    if args.binary is None:
        subprocess.run(["cargo", "build", "--release", "--locked", "-p", "siworld-node",
                        "--bin", "siworld-aggregation-bench", "--features", "diagnostics"],
                       cwd=args.root, check=True)
        args.binary = Path(args.root) / "target/release/siworld-aggregation-bench"
    args.binary = args.binary.resolve()
    groups = {"1": [], "2": []}
    for repetition in range(args.repetitions):
        for parallel in ((1, 2) if repetition % 2 == 0 else (2, 1)):
            print(f"measuring cold N={args.slots} parallel={parallel} sample={repetition + 1}", file=sys.stderr, flush=True)
            groups[str(parallel)].append(run_once(parallel, args))
    serial = summarize(groups["1"], args.rss_budget_bytes)
    dual = summarize(groups["2"], args.rss_budget_bytes)
    speedup = None
    if serial["aggregation_ms"]["p50"] and dual["aggregation_ms"]["p50"]:
        speedup = (serial["aggregation_ms"]["p50"] - dual["aggregation_ms"]["p50"]) * 100 / serial["aggregation_ms"]["p50"]
    dual_risk = dual["rss_budget_status"] == "exceeded"
    recommendation = "serial"
    if (speedup is not None and speedup >= 5
            and serial["samples"] == dual["samples"] == args.repetitions
            and dual["rss_budget_status"] == "within"
            and serial["accounted_peak_bytes"] is not None
            and dual["accounted_peak_bytes"] <= serial["accounted_peak_bytes"]):
        recommendation = "parallel-2"
    result = {
        "schema": 1,
        "synthetic_only": True,
        "baseline_ms": BASELINE_MS,
        "baseline_provenance": "Historical 106 s reference without a retained command/source artifact; contextual comparison only",
        "environment": {"system": platform.system(), "release": platform.release(), "architecture": platform.machine(), "logical_cpus": os.cpu_count()},
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "configuration": {"slots": args.slots, "rayon_threads": args.rayon_threads, "cache": "cold", "parameters": "classical-D4-W16"},
        "serial": serial,
        "parallel_2": dual,
        "speedup_percent": speedup,
        "serial_vs_baseline_percent": ((serial["aggregation_ms"]["p50"] - BASELINE_MS) * 100 / BASELINE_MS)
        if serial["aggregation_ms"]["p50"] else None,
        "parallel_2_vs_baseline_percent": ((dual["aggregation_ms"]["p50"] - BASELINE_MS) * 100 / BASELINE_MS)
        if dual["aggregation_ms"]["p50"] else None,
        "recommendation": recommendation,
        "runs": groups,
        "limitations": "Cold synthetic aggregation only; process RSS includes setup; no total-memory, WAN, production or post-quantum acceptance evidence.",
    }
    encoded = json.dumps(result, sort_keys=True, indent=2)
    print(encoded)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
        args.output.chmod(0o600)
    # Missing or failed samples and any RSS overrun fail the measurement gate.
    return 2 if dual_risk or any(r["status"] != "passed" for rows in groups.values() for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
