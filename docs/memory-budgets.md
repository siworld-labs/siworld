# Memory Measurement Budgets

Status: regression acceptance schema and checker. A declared ceiling does not
implement an allocation bound or establish a limit on historical state growth.

`tools/control-panel/memory_trend.py` accepts aggregate resource samples, retains
a bounded 120-sample window, and computes integer growth slopes. Missing fields
remain unmeasured. Process epoch changes start a new trend. An actual process or
container limit must be supplied; the checker does not invent one.

## Retained-node measurement ceilings

| Category | Measurement ceiling |
| --- | ---: |
| Managed network payload | 128 MiB |
| Codec receive buffers | 256 MiB |
| Codec send buffers | 256 MiB |
| Mempool | 64 MiB |
| Block-store page cache | 64 MiB |
| Payment-journal page cache | 8 MiB |
| Canonical metadata | 256 MiB |
| Nullifier and commitment structures | 512 MiB |
| Side-fork bodies | 128 MiB |
| Proof working set | 1536 MiB |
| Allocator retained memory | 512 MiB |

These declarations apply to the retained node, not the native V1 pool/worker
ledger. Its whole-node measurement ceiling is 3 GiB and must also respect the
supplied process limit. Categories can overlap and must not be summed into estimated
RSS. These thresholds do not show that live nodes expose every category or
that their allocations are independently bounded. Historical metadata, state,
fork bodies, proof workspaces and allocator retention require further bounds.

`python3 scripts/check-memory-budgets.py` validates declarations only. With a
private measurement JSON argument, it requires complete integer categories,
positive actual process limits, stable node membership and increasing sample
times, and rejects missing, invalid or excessive values. Synthetic tests check
the checker, not live memory acceptance.

## Isolated proof process budget

Historical D4 composition controls used a separate 4 GiB whole-process budget,
including setup, prepared circuits, witness generation, proving and
verification. This does not change a node or container limit. On macOS both peak RSS and physical
footprint must fit; compression makes RSS alone insufficient. The collector
checks the kernel lifetime footprint peak and current RSS every 100 ms and
terminates its owned process group on an overrun. Sampling can overshoot the
threshold; it is not a kernel allocation cap. An interrupted sample has no
successful latency result. Linux acceptance requires separate cgroup charged
memory and enforcement; this collector does not claim to provide them.

The older binary comparison tool also requires physical footprint on macOS.
The 106-second historical reference lacks its original command and artifact,
so it cannot support a matched performance claim. Configuration, tree capacity,
query count, CPU allocation, cold setup and online proof time must be explicit.
Recursive D8 checkpoint work is paused V2 research. Its historical experimental
ceiling and leaf/merge/root timing do not set native V1 requirements.
See [proof composition](proof-composition.md) for that research scope.

## Native V1 resource qualification

The [frozen native profile](../crates/bench-d8/artifacts/v1-native-freeze.json)
has independent transaction and fixed-576 settlement measurements. The hosted
5-GiB zero-swap scopes are measurement boundaries, not an approved node/miner
RAM requirement. The [V1 ledger](v1-node-network-plan.md#admission-and-local-resource-policy)
specifies new pool and isolated-verifier policy; it does not change retained
node limits. Its 4-MiB decoder budget bounds declared vectors, not total RSS.

Qualify [candidate hosts](v1-deployment.md) using simultaneous node, generation,
verification and maintenance limits, startup and steady peaks, state/cache
growth and OS/VM reserves. Give memory equal prominence to time. Require the
[sustained and recovery gates](prover-acceptance.md#gate-6-sustained-observation-retention-and-recovery)
before declaring supported hardware. Never sum overlapping sampled categories
or transfer an isolated benchmark to every OS.
