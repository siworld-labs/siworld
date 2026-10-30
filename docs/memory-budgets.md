# Memory Measurement Budgets

The `native-v1-economics-1` [monetary profiles](v1-economics.md) have fresh
actual-AIR and reference-host process-tree evidence. Public-key reproduction,
complete CI and independent verifier-only resource qualification remain
release or activation gates as specified below.

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
See [proof composition](v2/proof-composition.md) for that research scope.

## Native V1 resource qualification

The [multi-asset transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
records a maximum setup/prove/verify process-tree peak of 525,234,176 bytes
for the selected b7/q41/g20 EPYC 7763 trials. Four-worker fixed-576 settlement
and three-note issuance peaks are 3,161,432,064 and 211,423,232 bytes,
respectively. All include the recorder and fresh preparation; verification
was not isolated into a verification-only memory scope. Separate measurements
remain in the [evaluation](v1-multi-asset-evaluation.md). The old
[baseline bundle](../crates/bench-d8/artifacts/v1-native-freeze.json) is unchanged.
Hosted 5-GiB zero-swap scopes are measurement boundaries, not approved
node/miner RAM requirements or independent verifier-memory bounds.
The [V1 ledger](v1-node-network-plan.md#admission-and-local-resource-policy)
specifies separate pool and isolated-verifier guards. Its byte ceilings remain
binding when the transaction cap grows to 640 KiB: count limits do not permit
extra allocations. The new decoder requires its own trusted shape and cap;
the old 4-MiB declared-vector budget is not a total RSS bound.

The opt-in resident service retains the 640-MiB shared peer ledger and limits
one full-proof reply to 480 MiB. Its import staging uses a 1-GiB logical
candidate-accounting ceiling, rather than the library default of 640 MiB: a
maximum 576-slot block can own decoded proofs and an encoded durable record
at the same time. This local accounting policy does not change wire caps,
consensus limits or peer-ledger capacity. The maximum-envelope import/replay
regression uses a deliberately synthetic verifier; it checks framing,
resource admission and durable state, not genuine-proof acceptance,
cryptographic soundness or proving performance.

Local production has an independent 512-MiB ownership ledger for at most one
background prover job and one PoW job, each retaining a 256-MiB snapshot/result
reservation with state/work guards. This keeps local-job charges from consuming
the peer ledger during concurrent work. These accounting ceilings are neither
RSS measurements nor a whole-process memory cap. They do not cover every
prover temporary, allocator retention, database mapping or thread allocation,
and must not be summed into a claimed node-memory requirement.

Qualify [candidate hosts](v1-deployment.md) using simultaneous node, generation,
verification and maintenance limits, startup and steady peaks, state/cache
growth and OS/VM reserves. Give memory equal prominence to time. Require the
[sustained and recovery gates](prover-acceptance.md#gate-6-sustained-observation-retention-and-recovery)
before declaring supported hardware. Never sum overlapping sampled categories
or transfer an isolated benchmark to every OS.
