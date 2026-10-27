# Linux Proof Process Measurement

Status: measurement harness; the D4 control validates instrumentation only.
The required environment is Ubuntu 24.04 x86_64 with x86-64-v3 features exposed
on every available CPU, a unified cgroup v2 hierarchy with the memory controller
enabled, and a privileged supervisor. AVX2 is mandatory. A generic GitHub-hosted
Ubuntu label does not qualify a host or establish the selected CPU model. The
complete D8 acceptance procedure remains separate from the D4 control.

## Baseline and comparison hardware

Use the **EPYC 7763 Ubuntu 24.04 Microsoft virtual-machine profile with two
exposed cores and four vCPUs** as the Linux D8 acceptance baseline. EPYC 9V45 is
the comparison profile. Record full `lscpu`, exposed core/socket/logical topology,
affinity, VM detection, CPU model and ISA flags, RAM, OS/kernel and resource
constraints before each series. Verify the actual baseline model and topology;
do not treat any four-vCPU runner as equivalent. Preserve the non-secret
`GITHUB_ACTIONS` marker through the privileged supervisor.

The original short-lived runner is no longer available. A replacement requires
fresh qualification, and its results identify that new allocation. All three
trials of a configuration must run on one live machine; different jobs or VM
allocations must not be described as the same machine. VM-visible cores do not
prove physical host core count, exclusive access or identical contention. A
missing CI marker means unknown context, not a non-CI host. A comparison host
does not silently replace the EPYC 7763 acceptance baseline.

## Hosted native diagnostics

`.github/workflows/d8-native-cgroup.yml` runs on a GitHub-hosted Ubuntu 24.04
runner. It records the actual CPU model, topology, ISA and VM context without
claiming the EPYC 7763 reference allocation. It builds release x86-64-v3 native
transaction and 576-position settlement executables with pinned dependencies,
checks the generic launcher's CPU guard and inspects their AVX2 instructions.

`scripts/measure-native-cgroup.py` runs three fresh scopes per executable using
`systemd-run --scope -p MemoryMax=5G -p MemorySwapMax=0`. A small privileged
recorder remains inside each owned scope until it saves kernel `memory.peak`,
`memory.events`, CPU counters and exact limit readback. The proof child drops
privileges and has ordinary OOM priority; the protected recorder retains
failure evidence when the proof is killed. Each scope includes setup, proof,
verification and the recorder. Generation timing is reported separately from
whole-process elapsed time. Memory peaks are independent per process and may
not be described as phase-specific generation peaks.

All six diagnostics are attempted. Missing counters, failed proof verification,
OOM/limit events, timeout or surviving descendants fail the measurement after
artifacts are retained. Uploaded JSON contains allowlisted CPU/kernel counters,
executable identities and timings, excluding raw proof logs and synthetic
openings. An explicit status artifact survives earlier build/startup failures.
The 5-GiB limit applies to this diagnostic, not to a selected production memory
budget. These draft-AIR results cannot freeze production parameters or replace
security review, relation coverage and deterministic codec/resource bounds.

## Process-tree memory boundary

`scripts/measure-proof-cgroup.py` creates an exclusively owned scope. Its
5-GiB (`memory.max=5368709120`) default is retained for legacy D4 controls; it
does not define the D8 production budget. The next D8 collector must explicitly
select `--memory-max 10737418240` for its 10-GiB experimental ceiling, then read
back that value, `memory.swap.max=0` and `memory.oom.group=1`. The ceiling is
not production acceptance; select the production budget after actual peak
measurements. The harness places the child before exec, then drops the worker
to an unprivileged UID/GID.
All descendants inherit the scope. The supervisor remains outside it and holds
no circuit, proof state or worker helper. It does not enable parent controllers
or change unrelated scopes. Missing permissions/controllers/peak counters fail
closed. This is a resource harness for trusted proving code, not a sandbox for
arbitrary hostile executables.

Record lifetime `memory.peak`, swap peak, 100-ms charged-memory samples,
`memory.events` and `memory.stat` before/after, exit status, timeout and surviving
descendants. A max/oom/oom_kill event, any swap, cap violation, timeout, failure
or surviving descendant fails the control. The owned scope is killed on timeout
and never used to retry a proof. Limits cover startup and resident preparation;
a lower ready-state sample cannot erase the lifetime peak.

## SIMD and CPU controls

The x86_64 release baseline is fixed to **x86-64-v3**, never
`target-cpu=native`. The CPU and operating system must expose the complete v3
feature set; AVX2 support alone is necessary but not sufficient. Use the release package's generic-baseline launcher, which checks ISA and
OS-state support before executing the internal v3 worker. The launcher must
issue an explicit error for missing features instead of selecting scalar
arithmetic; direct internal-worker startup is unsupported. AVX-512 is not
required and must not silently become a different release baseline.

The original slowdown comparison used a generic x86-64 scalar build and an
explicit AVX2 build on the same newly allocated runner. That scalar build was
a diagnostic control; it is not a supported release fallback. Routine release
and acceptance measurements use the fixed v3 build. All controlled trials use
N=16, one proof job, Rayon two threads and two native hiding workers, with the
same patched sources, release optimization, thin LTO and 16 code-generation
units. Separate build directories and binary identities are required when
comparing diagnostic and release code generation.

Do not override the repository's fixed target with environment flags or profile
overrides. Hardware support alone does not enable Plonky3's compile-time SIMD
selection. Retain verbose compiler commands, effective target cfg,
compiler/dependency/source identities and the actual proving-binary hash. The
binary's compile metadata must report KoalaBear packing width 8 and AVX2, with
the selected two-worker patch and actual worker configuration. Inspect the
release proof binary with `objdump -d -C -M intel` for packed Montgomery
multiply instructions using 256-bit `ymm` registers. CI must fail if release
AVX2 instructions or the matching field-packing metadata are absent. A negative
CPU-emulation test must verify that the generic launcher rejects a CPU without
AVX2 before it starts the v3 worker, rather than terminating on an illegal
instruction.
Instructions confined to unrelated runtime-dispatched libraries do not
establish the field arithmetic path. Preserve disassembly evidence associated
with the inspected binary identity.

Record the owned cgroup and every visible ancestor's `cpu.max`, effective
cpuset and `cpu.stat` before/after. The harness never changes CPU limits.
Sample cgroup CPU time and descendant thread ticks every 100 ms. Report quota,
throttling, average effective CPU cores and capacity utilization. For example,
two CPU seconds per wall second is two effective cores; it does not establish
that exactly two threads performed work. Thread samples can miss short-lived
threads. Per-stage process CPU ticks cover all threads in the proving process,
while cgroup totals also include helper children. Convert stage tick deltas
using the recorded `CLK_TCK`; do not assume a frequency. The two serial merges
have separate wall and CPU records.

Pin export and proof execution remain within each trial's same cgroup lifetime.
Record every leaf, each merge, root, setup and verification phase. Report all
three release results, their medians and maxima; do not substitute a best run.
Historical D4 readiness/timing markers do not satisfy the production
arrival-to-root contract. Every control reports `acceptance=false`, including
when its root verifies and resource enforcement passes. Never relabel D4
results as D8 security or hardware acceptance. If the optimized VM remains
substantially slower than the reference, a physical host or larger instance
comparison remains required; a second unrelated VM is not the same machine.

Runner-local logs and raw samples are not uploaded. Only synthetic phase and
resource aggregates are printed for CI inspection; source commits contain no
run evidence or local audit output. Complete D8 acceptance requires three
prepared-service trials and the [full timing boundary](prover-acceptance.md#timing-boundary-and-service-readiness).

## Checkpoint time and memory reporting

The D8 checkpoint is a joint latency and memory decision. After batch grinding
is complete and the final configuration is frozen, run three trials on the
qualified baseline and project the complete N=16 `16 -> 2 -> 1` service:

| Projected proof latency and peak charged memory | Action |
| --- | --- |
| At most 135 seconds and at most 10 GiB | Continue experiments; production memory acceptance remains open. |
| More than 135 and at most 180 seconds, with peak memory at most 10 GiB | Continue experiments and optimize parameters and circuits in parallel. |
| More than 180 seconds or more than 10 GiB | Pause and report. |

An incorrect proof, OOM or resource-enforcement failure also blocks progression.
Report both remaining experimental memory margin and timing margin. Passing
under the 10-GiB ceiling does not select or satisfy a production memory budget.
Preserve the previous 5-GiB OOM attempt as failure evidence; do not rewrite it
with the larger ceiling or omit it from the attempt record.

For startup/readiness, sixteen leaves, first merge, second merge, root and
handoffs, place wall time and charged-memory peak side by side. Break memory
into prepared circuit/key residency, incremental active workspace, concurrently
retained proofs/input/output buffers and allocator/cache or handoff overlap.
Report each measured component's scope and sampling interval; identify
shape-based estimates for incomplete stages. A process-wide peak cannot provide
exact allocation attribution. Reconcile estimates with phase samples and the
kernel lifetime peak, avoid counting residency twice, and report attribution
uncertainty. Retain startup peaks even though startup time is excluded from the
180-second proof-latency interval. See the complete
[projection model](d8-w24-recursion.md#n16-latency-and-memory-projection).

N=32 is the first separately scoped assessment after the D8 checkpoint passes;
it is not evaluated in the current measurement work.
