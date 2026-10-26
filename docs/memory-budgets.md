# Memory Measurement Budgets

Status: regression acceptance schema and checker. A declared ceiling does not
implement an allocation bound or establish a limit on historical state growth.

`tools/control-panel/memory_trend.py` accepts aggregate resource samples, retains
a bounded 120-sample window, and computes integer growth slopes. Missing fields
remain unmeasured. Process epoch changes start a new trend. An actual process or
container limit must be supplied; the checker does not invent one.

## Node acceptance ceilings

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

The whole-node acceptance ceiling is 3 GiB and must also respect the supplied
process limit. Categories can overlap and must not be summed into estimated
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
The next D8 checkpoint uses a separate 10-GiB (10,737,418,240-byte) experimental
process-tree ceiling with zero swap, including startup and resident circuits.
This is not a production acceptance budget. Select the production budget after
actual D8 peak measurements, then recompute worker placement and aggregate host
admission. Node category ceilings and retained-network limits remain separate.
See the [D8 resource procedure](prover-acceptance.md#formal-proof-process-budget)
and [proof composition](proof-composition.md) for relation and timing scope.
