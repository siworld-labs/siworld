# Linux Proof Process Measurement

Status: measurement harness; the D4 control validates instrumentation only.
The requested environment is Ubuntu 24.04 x86_64 with AVX2 exposed on every CPU,
a unified cgroup v2 hierarchy with the memory controller enabled, and a
privileged supervisor. GitHub-hosted Ubuntu 24.04 is one reproducible control
environment; it does not qualify all miner hardware. Native target hardware
still requires the complete D8 acceptance procedure.

`scripts/measure-proof-cgroup.py` creates an exclusively owned scope, reads
back `memory.max=5368709120`, `memory.swap.max=0`, and `memory.oom.group=1`,
places the child before exec, then drops the worker to an unprivileged UID/GID.
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

The `Linux proof resource control` workflow uses one newly allocated live runner
for one explicit scalar control and three AVX2-only D4-B trials. The original
short-lived runner cannot be reused. All four trials use N=16, one proof job,
Rayon two threads and two native hiding workers, with the same patched sources,
release optimization, thin LTO and 16 code-generation units. Separate target
directories prevent reuse across compilation modes:

```text
scalar: -C target-cpu=x86-64 -C target-feature=-avx2,-avx512f
AVX2:   -C target-cpu=x86-64 -C target-feature=+avx2,-avx512f
```

Do not set `CARGO_ENCODED_RUSTFLAGS` or profile overrides during this comparison.
Hardware support alone does not enable Plonky3's compile-time SIMD selection.
The actual proof output must report KoalaBear packing width 1 for scalar and 8
for AVX2, AVX2 enabled and AVX-512 disabled in the latter build. Retain verbose
compiler commands, effective target cfg, compiler/dependency/source identities
and actual proving-binary hashes. Inspect that binary with
`objdump -d -C -M intel` for packed Montgomery multiply instructions using
256-bit `ymm` registers. Instructions in unrelated runtime-dispatched libraries
alone do not establish the field arithmetic path; verify both packing metadata
and disassembly.

Record full `lscpu`, exposed core/socket/logical topology, affinity, VM detection,
CPU model and AVX2/AVX-512 flags. VM-visible physical cores are not evidence of
the physical host's core count or exclusive access. GitHub-hosted runners are
virtual CI environments with unverified host tenancy.

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
three optimized results, their medians and maxima; do not substitute a best run.
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
