# Native V1 Deployment and Observability

Status: qualification design for the independent native V1 engineering network.
The prior two-output profile is a diagnostic baseline; the multi-asset profile is reopened; node integration, operating
profiles, network capacity and supported deployment platforms remain subject
to acceptance. This document does not change the retained seven-node network.
[Decisions](00-decisions.md), [native transaction design](route-a-v1.md) and the
[node integration plan](v1-node-network-plan.md) define protocol requirements.

## Roles and fault domains

Every full validator applies the same consensus rules and independently verifies
transactions and settlement. A miner adds block production and padding-proof
preparation to that role. There is no privileged main node, master database or
control-panel vote in consensus. Bootstrap services provide peer discovery,
not trusted state, proof validity or finality decisions.

| Role | Responsibilities | Operational separation |
| --- | --- | --- |
| Full validator | Verify, apply, relay and retain the required proof window | Baseline independently operated consensus participant |
| Miner/full validator | Full validation, block assembly, padding and settlement generation | Separate proving processes and keys from monitoring |
| Bootstrap node | Supply authenticated peer-discovery records | At least two independent operators or fault domains |
| Monitoring collector/panel | Receive bounded status telemetry and display incidents | Private service outside consensus; no spend/miner keys |

Distribute validation and mining across independently operated hosts and
networks. Multiple containers on one machine remain one failure domain.
V1 has no archive-node role and does not retain historical proof bodies after
the online retention window. Bootstrap and checkpoint services provide
discovery and an explicitly trusted starting point; neither has consensus
authority.

## Platform qualification

The measured Linux reference is Ubuntu 24.04, AMD EPYC 7763, two exposed cores
and four vCPUs in a Microsoft virtual machine. Host exclusivity is unknown.
Use the fixed `x86-64-v3` release baseline with AVX2 and its startup check;
`target-cpu=native` is not a reproducible release configuration. Record actual
CPU, effective CPU quota, RAM, storage, hypervisor and dependency/source hashes.
A four-vCPU label alone does not establish equivalent physical CPU capacity.

macOS on Apple Silicon and Windows are qualification targets, not accepted
V1 node/miner platforms. A future macOS ARM release needs its own native build,
crypto vectors, resource-isolation policy, storage/recovery and sustained-load
results. A future Windows release needs equivalent native verification and
process-limit tests; Linux under WSL2 remains a Linux VM with separately
measured storage, network and memory overhead. Do not label either path
supported by transferring the Linux benchmark. Wallet-only qualification is
independent of full-node qualification.

## Candidate host profiles

These profiles are starting points for integration testing, not measured
minimums or hardware requirements frozen by the isolated prover experiment.
The 5-GiB zero-swap cgroup was a measurement boundary, not a miner requirement.
Freeze supported hardware only after real maximum-load sustained acceptance.

| Role | Initial qualification profile |
| --- | --- |
| Full validator | Four reference-class vCPUs, 16 GiB RAM, 500 GB usable local SSD minimum; 1 TB recommended |
| Miner/full validator | At least four reference-class vCPUs, 32 GiB RAM, 500 GB usable local SSD minimum; 1 TB recommended |
| Bootstrap or telemetry collector | Separate host; size after peer/load and retention tests |

SSD capacity means usable capacity after filesystem/array overhead, before
allocating separate backups. Disk redundancy does not replace backups. Measure
power-loss behavior, synchronous commits, write amplification and compaction.
The protocol minimum is **30-Mbps uplink**. The deployment recommendation
remains **100 Mbps sustained uplink**. The proposed multi-asset three-copy
payload plus capped settlement uses 24.30537976 Mbps. The
[complete conditional wire budget](v1-network-budget.md) includes control,
authenticated-channel framing, IPv6/TCP/link overhead, reciprocal ACKs,
bounded issuance, handshakes, 2% retransmission and 5% missing-body recovery
reserves: approximately 29.252 Mbps. It leaves 0.748 Mbps (2.49%) additional
margin at 30 Mbps, compared with 70.748 Mbps at 100 Mbps. These are explicit
planning assumptions; measure packet counters and queue growth before accepting
576-position operation. Schedule bulk backup/checkpoint transfers separately.

Account for all simultaneous consumers. Current planned payload/worker ceilings
sum to 1,539 MiB: verified pool 512, unverified queue 64, two verifier workers
256, reconstruction 640, padding payload 65 and two one-MiB caches. These are
policy ceilings, not resident-memory measurements; metadata, decoder copies,
network buffers, database caches, accepted state and allocator overhead are
additional. Avoid double counting shared ownership and count actual duplicate
buffers. Persisted state and caches need separately measured growth limits.

Reserve at least 4 GiB for the OS, monitoring, filesystem activity and service
restart on candidate hosts. Measure the node with its largest legitimate pools,
cold database opening, replay, pruning and compaction. Measure prover setup,
key loading, steady generation and teardown separately and together with node
work. Miner tests must include concurrent settlement and permitted padding
refill. Isolated charged peaks of 393,834,496 B for transaction generation and
2,942,472,192 B for settlement do not bound that aggregate. Neither a clean
single-process run nor spare page cache establishes long-term memory safety.

## Storage ledger and capacity gate

Use [V1 Storage, Retention and Bootstrap](v1-storage-and-sync.md) and reproduce
the explicit planning model with `python3 scripts/v1-storage-budget.py`.
The proposed three-output codec has 2,115 permanent bytes/position. Ordinary
proofs/sidecars require 268.672 GB at the nominal 888-block window; an additional
one-capped-issuance-proof/block allowance brings the rolling budget to
269.138 GB. Include 8 KiB permanent block records and 16 KiB permanent issuance
records/block, 25% of all permanent bytes for indexes/state, 16 GB database
working space, 20 GB system/recovery files, and 20% device free:

| Workload | Device year 1 | Device year 3 | Device year 5 |
| --- | ---: | ---: | ---: |
| Maximum 576 positions/block | 585.555 GB | 993.820 GB | 1,402.085 GB |
| 10,000/day, minimum 64-position blocks | 109.684 GB | 162.223 GB | 214.762 GB |
| 50,000/day, adaptive grouping | 211.567 GB | 340.261 GB | 468.956 GB |
| 50,000/day, uniform 176 positions | 213.781 GB | 344.135 GB | 474.489 GB |

**500 GB usable SSD is the installation minimum; 1 TB is recommended** for
both miners and validators. Under this finite planning scenario, a 1-TB device
provides approximately three years at continuous maximum load; early
10k/50k-per-day usage fits 500 GB for more than five years. These horizons
depend on the final measured overheads and workload. The 1-TB year-three
margin beyond the free reserve is narrow, and 500 GB does not qualify a year
of full load. Publish measured growth and expand storage before reserves are
consumed.

The block/issuance ceilings and database allowance remain proposed engineering
budgets: final encoding must bound headers/PoW, settlement declarations,
reward/fund records and ML-DSA signatures, metadata and initial issued notes.
Measure exact tree/index/redb/WAL/compaction peaks and replace the allowances;
they are not actual measured overheads. Unbounded issuance has no finite
worst case. A compaction scheme needing a full database copy can exceed the
16-GB working reserve and must be changed or separately provisioned. Never
prune public data or unexpired proofs to enforce a capacity target. Faster
blocks increase elapsed-time retention storage.

All nodes retain headers/PoW, commitments/tree state, ciphertexts, nullifiers,
fee commitments, proof-free settlement declarations, reward notes, signed fund
records, issuance records and recent-root snapshots permanently. No V1 archive
role is selected. Permissionless issuance needs bounded metadata and per-block
bytes/work so the added permanent-storage term remains finite.

Alert at candidate 20% free, suspend local production and admission at 15%,
and stop consensus writes safely before an emergency 10% reserve is consumed
if durable persistence cannot continue. Calibrate thresholds using measured
maximum atomic-operation, compaction and recovery peaks. Disk pressure is
local unavailability, not evidence that a valid block is cryptographically
invalid. Backups are separately budgeted and do not replace free-space reserve.

## Resource qualification and recovery

Qualify each candidate hardware profile with 72 continuous hours at maximum
valid load, and a seven-day independent-host soak containing at least
72 hours of maximum load. The windows may overlap once the configuration is
frozen. Report steady memory slope, component disk growth,
write amplification, CPU/queue saturation and actual framing/recovery traffic.
The soak is not evidence for three-day deletion: observe the real elapsed
retention lifecycle as well as accelerated crash/clock/pruning regressions.

Project-operated object storage must back up permanent public data without
becoming an archive for deleted proof bodies. Upload each finalized block
segment (or at least every six hours) with immutable versioning, publish a
signed daily manifest, and create a weekly full checkpoint snapshot. Restore
into an isolated node by verifying object hashes and signatures, replaying
ordered blocks and PoW, rebuilding indexes and comparing state roots, work and
nullifier/commitment roots before promotion. Run a monthly restore check and a
quarterly replacement-host recovery test. Backups must not be the only copy;
the node set remains the source of permanent public data.

Wallet creation must require an explicit mnemonic backup and a successful
local restore check. A restored wallet scans permanent ciphertexts and public
commitments from genesis or an authenticated wallet birth height, including
segments older than its bootstrap checkpoint, verifies note ownership and asset
metadata, and reconciles balances and pending payment journals exactly once.

On reference hosts with measured 100-Mbps access, initial recovery targets are
return to the durable tip within ten minutes after a clean restart, and catchup
of at most 24 missing blocks within 30 minutes. Measure available residual
bandwidth under concurrent relay before accepting those targets. For lower
bandwidth, derive the catchup allowance from missing bytes divided by measured
spare bandwidth plus verification/replay work; do not promise 30 minutes on a
saturated 30-Mbps connection. Require zero loss of durably accepted records.
Database corruption halts participation and requires verified backup/recovery;
it must not silently rewind accepted history.

## Real-time private monitoring

Provide an authenticated, read-only status feed from each node over outbound
connections to a separate collector. Use distinct telemetry credentials,
bounded queues and expiry; collector failure must not block validation or
mining. Protect any deployed temporary transport with authenticated encryption;
the production connection path still requires the reviewed hybrid handshake.
Use five-second samples and server-pushed panel updates as initial targets;
mark a feed stale after 15 seconds and unavailable after 30 seconds. Sequence
numbers are scoped to an authenticated node process epoch and a fresh
collector-issued session challenge. Enforce increasing sequence numbers within
that session, rotate sessions after either endpoint restarts, and reject old
sessions. Compute receipt age with the collector's monotonic clock; sender
timestamps alone cannot establish freshness. Repeated state with a new sequence
does not itself prove current node progress.

The private panel should show configured opaque node label, role, release
identity, uptime/restart counter, chain height and public roots/work agreement,
explicit state-busy/idle status, finality/sync lag, connection-health classes,
aggregate CPU and charged process memory, memory events, disk headroom,
proof-retention lag, verification latency and aggregate traffic rates.
Busy or unavailable nodes do not establish completed-state equality. Compare
roots only at a common height and confirm propagation lag before declaring
divergence; one slow block does not establish a sustained stall.

Do not emit addresses, nullifiers with times, individual fees/openings,
real/padding classifications, real/dummy counts or padding-pool counts.
Keep low-level diagnostic retention private, bounded and access controlled.
Show durable incident episodes, recovery transitions and acknowledgments.
Display the new network separately from retained-network status.

Bind the panel to loopback/private access by default, authenticate operators,
and enforce session expiry. A remote operator uses authenticated private
access, not a public unauthenticated control endpoint. Monitoring credentials
cannot sign blocks, spend, alter peers or launch recovery. If administrative
controls are later added, use a separate audited authorization boundary.

The native proof components and isolated benchmark evidence exist. The roles,
host profiles, capacity acceptance, telemetry feed and panel integration above
remain planned work. Accept them only after independent-host end-to-end tests,
including observer loss, stale sessions, node restart, peak load and recovery.

## Reopened multi-asset capacity

Measurements of the two-output implementation remain baseline evidence only.
The proposed three-output codec uses 2,027 public body bytes and 2,115
permanent bytes per position. At capped proof sizes and three relay copies,
including one capped settlement per block, the payload is approximately
24.3054 Mbps at 576 positions/300 seconds, before framing, recovery and public
issuance traffic. Updated year-1/3/5 capacity and low-use tables are in
[V1 Storage, Retention and Bootstrap](v1-storage-and-sync.md); reproduce them
with `python3 scripts/v1-storage-budget.py`. The final encoded artifact and
actual-AIR scan must replace these estimates before acceptance.

## Backup checkpoint freshness

A weekly full snapshot alone is insufficient once proofs expire after
three days. Export an authenticated, consistent confirmed-state checkpoint
(full or a complete authenticated delta chain) at least every six hours,
together with the public-data manifest. Weekly full snapshots remain a
compaction/recovery convenience. Before replaying a restored checkpoint's
proof tail, confirm every required proof is still available. If not, obtain a
newer quorum-authenticated checkpoint under the explicit trust policy, or
stop recovery; public records and PoW cannot replace deleted proof validity.
The checkpoint binds the asset registry, fund state, permanent-data manifests
and complete accepted root window. Never synthesize missing state or silently
trust an unauthenticated peer.
