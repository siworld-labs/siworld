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

The `Linux proof resource control` workflow builds the isolated two-native-worker
D4 benchmark and runs leaf profile B/q92 parents, N=16 and one proof job once.
Pin export and proof execution are both within the same cgroup lifetime. It
records leaf, each merge, root and setup/verification times. Historical D4
readiness/timing markers do not satisfy the production arrival-to-root contract.
Every control reports `acceptance=false`, including when its root verifies and
resource enforcement passes. Never relabel D4 results as D8 security or hardware
acceptance.

Runner-local logs and raw samples are not uploaded. Only synthetic phase and
resource aggregates are printed for CI inspection; source commits contain no
run evidence or local audit output. Complete D8 acceptance requires three
prepared-service trials and the [full timing boundary](prover-acceptance.md#timing-boundary-and-service-readiness).
