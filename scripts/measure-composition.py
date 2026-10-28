#!/usr/bin/env python3
"""Bounded macOS process profiling for the isolated N=16 composition binary.

Raw observations are private. The footprint watchdog is sampled, not a kernel
allocation limit. RSS and physical footprint are distinct accounting measures.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import statistics
import subprocess
import sys
import threading
import time


class RUsage(C.Structure):
    _fields_ = [("uuid", C.c_ubyte * 16)] + [(name, C.c_uint64) for name in (
        "user", "system", "idle", "interrupt", "pageins", "wired", "rss", "footprint",
        "start", "exit", "child_user", "child_system", "child_idle", "child_interrupt",
        "child_pageins", "child_elapsed", "read", "written", "qos0", "qos1", "qos2",
        "qos3", "qos4", "qos5", "qos6", "billed", "serviced", "writes",
        "peak_footprint", "instructions", "cycles", "energy", "serviced_energy",
        "interval_peak", "runnable")]


class ThreadInfo(C.Structure):
    _fields_ = [("user", C.c_uint64), ("system", C.c_uint64),
                ("flags", C.c_int32 * 8), ("name", C.c_char * 64)]


class MacSampler:
    def __init__(self):
        self.lib = C.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_pid_rusage.argtypes = [C.c_int, C.c_int, C.c_void_p]
        self.lib.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
        # rusage CPU fields use Mach absolute ticks; threadinfo uses nanoseconds.
        clock = C.CDLL("/usr/lib/libSystem.B.dylib")
        ratio = (C.c_uint32 * 2)()
        if clock.mach_timebase_info(C.byref(ratio)) != 0 or not all(ratio):
            raise OSError("Mach timebase unavailable")
        self.numer, self.denom = ratio

    def snapshot(self, pid, threads):
        usage = RUsage()
        if self.lib.proc_pid_rusage(pid, 4, C.byref(usage)) != 0:
            raise OSError(C.get_errno(), "proc_pid_rusage failed")
        result = {"ns": time.monotonic_ns(), "cpu_ns": (usage.user + usage.system) * self.numer // self.denom,
                  "rss": usage.rss, "footprint": usage.footprint,
                  "peak_footprint": usage.peak_footprint, "threads": {}}
        if threads:
            ids = (C.c_uint64 * 256)()
            size = self.lib.proc_pidinfo(pid, 6, 0, ids, C.sizeof(ids))
            if size <= 0 or size >= C.sizeof(ids):
                raise OSError("thread inventory unavailable or truncated")
            for thread_id in list(ids)[:size // 8]:
                info = ThreadInfo()
                if self.lib.proc_pidinfo(pid, 5, thread_id, C.byref(info), C.sizeof(info)) != C.sizeof(info):
                    continue  # A thread may exit between inventory and sampling.
                result["threads"][thread_id] = info.user + info.system
        return result


def os_peak(stderr, field):
    match = re.search(r"^\s*(\d+)\s+" + re.escape(field) + r"\s*$", stderr, re.M)
    return int(match.group(1)) if match else None


def valid_report(report, topology, jobs, queries):
    return (isinstance(report, dict) and report.get("schema") == 1
            and report.get("verified") is True and report.get("slots") == 16
            and report.get("topology") == topology and report.get("jobs") == jobs
            and report.get("parameters") == {"suite": "D4-W16", "log_blowup": 2,
                                             "queries": queries, "grinding": 16}
            and type(report.get("proof_and_verify_ns")) is int
            and report["proof_and_verify_ns"] > 0)


def run_once(args, topology, jobs, profile=False):
    command = [str(args.binary), "--topology", topology, "--jobs", str(jobs),
               "--queries", str(args.queries)]
    process = subprocess.Popen(["/usr/bin/time", "-l", *command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        env={**os.environ, "RAYON_NUM_THREADS": str(args.threads), "SIWORLD_BENCH_PROFILE": "1",
             "SIWORLD_COMPOSITION_HIDING_WORKERS": str(args.hiding_workers)})
    events = queue.Queue()

    def read(stream, channel):
        for line in stream:
            events.put((channel, line))

    readers = [threading.Thread(target=read, args=(stream, label), daemon=True)
               for stream, label in ((process.stdout, "out"), (process.stderr, "err"))]
    for reader in readers:
        reader.start()
    sampler = MacSampler()
    started = time.monotonic()
    pid = None
    report = None
    stderr = []
    stack = []
    samples = []
    previous = None
    stats = {}
    stopped = None
    sample_errors = 0
    first_sample_error = None

    def drain():
        nonlocal pid, report
        while True:
            try:
                channel, line = events.get_nowait()
            except queue.Empty:
                return
            try:
                item = json.loads(line)
            except ValueError:
                if channel == "err":
                    stderr.append(line)
                continue
            if item.get("event") == "ready":
                pid = item["pid"]
            elif "schema" in item:
                report = item
            elif "phase" in item:
                key = (item["thread"], item["phase"])
                if item["event"] == "start":
                    stack.append(key)
                elif key in stack:
                    stack.remove(key)

    try:
        while process.poll() is None:
            drain()
            if time.monotonic() - started > args.timeout:
                stopped = "timeout"
            if pid:
                try:
                    sample = sampler.snapshot(pid, profile)
                    # Both current and kernel lifetime peaks matter under compression.
                    if max(sample["footprint"], sample["peak_footprint"], sample["rss"]) > args.budget:
                        stopped = "memory_budget_exceeded"
                    phase = "/".join(name for _, name in stack) or "unattributed"
                    active = None
                    if profile and previous:
                        active = sum(value - previous["threads"].get(tid, value) >= 1_000_000
                                     for tid, value in sample["threads"].items())
                        bucket = stats.setdefault(phase, {"wall_ns": 0, "cpu_ns": 0,
                                                          "active_threads": [], "resident_threads": []})
                        bucket["wall_ns"] += sample["ns"] - previous["ns"]
                        bucket["cpu_ns"] += max(0, sample["cpu_ns"] - previous["cpu_ns"])
                        bucket["active_threads"].append(active)
                        bucket["resident_threads"].append(len(sample["threads"]))
                    samples.append({k: v for k, v in sample.items() if k != "threads"})
                    previous = sample
                except OSError as error:
                    sample_errors += 1
                    first_sample_error = first_sample_error or str(error)
                    # Do not proceed without a functioning resource watchdog.
                    if not samples or sample_errors >= 5:
                        stopped = "resource_sampling_failed"
            if stopped:
                os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.1)
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        for reader in readers:
            reader.join(timeout=5)
        drain()
    stderr = "".join(stderr)
    peak_rss = os_peak(stderr, "maximum resident set size")
    peak_footprint = os_peak(stderr, "peak memory footprint")
    for bucket in stats.values():
        bucket["effective_cores"] = bucket["cpu_ns"] / max(1, bucket["wall_ns"])
        bucket["active_threads_p50"] = statistics.median(bucket["active_threads"])
        bucket["active_threads_max"] = max(bucket["active_threads"])
        bucket["resident_threads_max"] = max(bucket["resident_threads"])
        del bucket["active_threads"], bucket["resident_threads"]
    passed = (not stopped and process.returncode == 0 and samples
              and valid_report(report, topology, jobs, args.queries)
              and peak_rss and peak_footprint
              and max(peak_rss, peak_footprint) <= args.budget)
    return {"status": "passed" if passed else (stopped or "failed"),
            "topology": topology, "jobs": jobs, "profile": profile,
            "returncode": process.returncode, "pipeline": report,
            "peak_rss_bytes": peak_rss, "peak_footprint_bytes": peak_footprint,
            "sampled_peak_footprint_bytes": max((s["peak_footprint"] for s in samples), default=None),
            "profile_phases": stats, "samples": samples, "sample_errors": sample_errors,
            "first_sample_error": first_sample_error,
            "stderr_tail": stderr[-4000:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--queries", type=int, choices=(42, 92), default=42)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--budget", type=int, default=4 << 30)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--profile-only", action="store_true")
    parser.add_argument("--hiding-workers", type=int, choices=(1, 2), default=1)
    parser.add_argument("--jobs", type=int, choices=(0, 1, 2), default=0,
                        help="0 alternates both schedules; 1 or 2 measures only that schedule")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this collector requires macOS libproc; use cgroup measurements on Linux")
    if min(args.budget, args.threads, args.timeout, args.repetitions) <= 0:
        parser.error("limits must be positive")
    if args.hiding_workers == 2 and not args.profile_only and args.jobs != 1:
        parser.error("two native workers require one proof at a time (--jobs 1 or --profile-only)")
    args.binary = args.binary.resolve(strict=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    result = {"schema": 1, "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "queries": args.queries, "threads": args.threads, "memory_budget_bytes": args.budget,
              "hiding_workers": args.hiding_workers,
              "budget_enforcement": "100ms sampled RSS and kernel lifetime physical footprint watchdog",
              "runs": []}
    configs = [("binary", 1, True)] if args.profile_only else [
        ("fanin8", jobs, False) for repetition in range(args.repetitions)
        for jobs in ((args.jobs,) if args.jobs else ((1, 2) if repetition % 2 == 0 else (2, 1)))]
    for topology, jobs, profile in configs:
        print(f"measuring {topology} jobs={jobs} q={args.queries}", file=sys.stderr, flush=True)
        run = run_once(args, topology, jobs, profile)
        result["runs"].append(run)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        args.output.chmod(0o600)
        print(json.dumps({k: run[k] for k in ("status", "topology", "jobs", "peak_rss_bytes", "peak_footprint_bytes")}), flush=True)
        if run["status"] != "passed":
            # A budget failure is evidence against this configuration; do not
            # repeatedly exceed the same budget to manufacture three samples.
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
