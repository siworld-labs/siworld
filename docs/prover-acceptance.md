# Proof Prover Integration and Acceptance Plan

Status: selected engineering scope with implementation and security gates still
open. Production uses the existing binary D4 relation. The target is D8/W24
with 12-element digests and N=16 `16 -> 2 -> 1`; historical B is methodology
evidence only. This plan does not claim a completed suite or start a network.

## Network boundary

Preserve the current seven-node N=2 network, stores, wallets, payment/fund
journals, images, keys and recovery evidence. Do not migrate its verifiers,
capacity, commitments or notes as part of this work.

The new N=16 suite uses a separate resettable engineering network from a new
genesis, independent directories, network identity, peer keys and wallet/fund
keys. It imports no old tickets, notes or proofs. Use synthetic funds only.
Prevent cross-network peer, worker, wallet and artifact reuse. Retained-network
services and resource reservations remain part of host capacity admission.
An implementation milestone or timing result does not authorize launching an
incomplete suite. Height-activated v1/v2 design and its historical replay,
boundary-reorg and mixed-version matrix are deferred until before mainnet.
Mainnet still requires the independently reviewed launch suite from genesis.

## Gate 1: complete suite and independent security review

Implement the [D8 dependency plan](d8-w24-recursion.md), extract
actual shapes and screen profiles with pinned `p3-security`. Meet the
[security review requirements](proof-security-review.md) for every
layer and composition. Then freeze the full reproducible source/dependency,
artifact and key set for independent human review. Close findings before
production adoption. Quotations and review scheduling may proceed in parallel;
D4/W16 is excluded from external parameter approval.

## Gate 2: isolated production integration

| Component | Required behavior |
| --- | --- |
| Circuit module | Implement reviewed D8 leaf, eight-input and root relations; preserve the experiment as a differential reference and dependency licenses. |
| Trusted artifacts | Bind one immutable suite/relation/capacity/key set to the new network identity from genesis. Deterministically reproduce keys; reject unknown suite, key, format and configuration. Incoming proofs never select trusted keys. |
| Shared validation | Production, inbound validation, replay and audit call the same native state transition and trusted verifier selection. Consensus remains integer-only, deterministic and atomic. |
| State and codecs | Consistently port hashes, notes, nullifiers, anchors, addresses, encryption plaintexts and root layout to reviewed 12-element formats. Do not import or relabel old notes. |
| Candidate lifecycle | Bind jobs, cached subtrees, cancellation and worker handshakes to network, suite, relation, capacity and key identity; reject stale/incompatible results. |
| Privacy | Identical real/padding parameters, artifact shapes and hiding; no public per-block classification, individual fees or user-linked telemetry. |
| Network resources | Keep node and worker limits separate. Admit aggregate hard limits and host/VM reserves before creating any new process; retain the N=2 network unchanged. |

Write consensus tests before implementation. Test correct and wrong suite/key,
all changed public fields, every digest/extension limb, malformed/noncanonical
encodings, native/circuit equivalence, anchor/ciphertext binding, fee carries,
omitted/repeated leaves, bad padding and nullifier/key reuse. Invalid input
must leave state unchanged. A D4 statement comparison does not establish D8
statement compatibility: width changes require explicit reviewed layouts.

Test genesis-to-tip replay, restart, shallow and 99/100-block reorg boundaries,
101-block rejection, job cancellation, disconnect/reconnect, wrong-network
peers/workers and no legacy-proof fallback. Cross-network fixtures and keys
must fail admission. Keep all test data independent of retained stores.

## Gate 3: miner hardware and resource acceptance

### Formal proof-process budget

The acceptance budget is **5 GiB = 5,368,709,120 bytes** for the complete proof
process and its children, including setup, leaf work, recursive workspaces,
native workers, serialization, caches and allocator retention. It is an OS
enforced resource boundary, not a sampled-RSS warning or a worst-case allocation
proof. Use one proof job and at most two native hiding workers unless a new
reviewed measurement justifies a different schedule.

On Linux, place the worker and descendants in one dedicated cgroup with
`memory.max=5368709120` and `memory.swap.max=0`. Record actual limits,
`memory.peak`, sampled charged memory, swap and `memory.events` before and
after every run. Keep all helper descendants inside the boundary. An OOM,
restart, excess, missing peak or missing enforcement evidence fails acceptance;
discard the job and stop progression without an automatic retry loop.

RSS, virtual size and macOS physical footprint are distinct metrics. A sampler
or post-allocation watchdog is not a hard cap. Personal machines on other
operating systems need an equivalent verified process-tree limit, or an
isolated Linux worker with a separately budgeted VM. Do not label an uncapped
macOS/Windows sample as passing the enforced-budget gate.

The [current node memory model](memory-budgets.md) remains separate.
The existing miners have 3-GiB container limits, so a worker with a 5-GiB budget
cannot be placed inside those containers. Plan a separate worker boundary and
retain the node's own resource checks. Do not raise its proof-category ceiling
to disguise aggregate growth.

Size concurrent hard limits, not only observed usage. For example, a hypothetical
node/gateway allocation of 13.75 GiB plus two 5-GiB workers totals 23.75 GiB.
Adding 2 GiB for other applications, 1 GiB of platform reserve and 2 GiB for
serialized maintenance requires 28.75 GiB of capacity; a 20-GiB worker VM
cannot admit this illustrative configuration.
One shared worker still requires admission/serialization and a fresh capacity
review. A different worker host must include its own node/OS/application
reserves. This illustration authorizes no VM or live-container change.

### Personal-machine qualification

There is no single specified miner machine. Before each hardware-class run,
record CPU/model/ISA and allocated workers, physical and available RAM,
OS/kernel, storage, virtualization, power/thermal mode, resource-controller
support, compiler/dependency/image identities and background load policy.
Record proof-worker and node placement, concurrency, actual hard limits and
host/VM reserves. A machine with only 5 GiB total RAM does not qualify merely
because the proof-process budget is 5 GiB.

Validate each supported configuration on actual miner hardware. The existing
M1 Max experiment is a reference, not proof that lower-memory or different-ISA
personal machines pass. Set a minimum supported hardware profile from these
results; slower machines may remain non-mining validators. Do not change
security parameters automatically to accommodate a slower device.

### Timing boundary and service readiness

The target is **at most 180 seconds on qualified target hardware**, defined by
monotonic markers at arrival of the final package input at the proving service
and completion of the canonical root-proof artifact. The arrival marker precedes
queued processing of that input. Include leaf proving and every intervening
admission, witness, candidate, scheduling, recursive proving and serialization
cost. Do not start timing after the leaves are already proved. Controlled
comparison trials make all sixteen package inputs available at the start and
include all sixteen leaf proofs. If a production service proves earlier packages
as they arrive, report that pre-marker work and overlap separately.

Complete input-independent preparation of all leaf, eight-input and root
circuits and trusted keys at service startup, validate their identities, and
keep them resident before declaring the service ready. Input-dependent witness
work and lazy preparation after the arrival marker count toward proof latency;
lazy preparation also fails the declared readiness condition. An external
helper cannot hold prepared state outside the measured memory boundary.

Measure service cold startup through readiness separately. Its duration is
excluded from the 180-second latency budget. This timing exclusion does not
exclude memory: startup preparation, resident state and every proof child stay
inside the same enforced 5-GiB process-tree boundary. Record startup and ready
service memory, interval peaks and the lifetime kernel peak; do not reset or
discard a higher startup peak to manufacture a memory pass.

PoW, publication, propagation, standalone root verification, peer durable
acceptance and recipient receipt have separate timing markers and correctness
checks. They are outside this proof-latency budget. Recursive verification
inside the leaf/aggregation/root proving circuits remains part of proving.
Record payment-submission-to-receipt and PoW waiting independently; the
180-second target is not a guaranteed block interval or a finality deadline.

### Three complete acceptance runs

After gates 1 and 2 close, run three independent trials per qualified hardware
class with identical pinned parameters and fresh OS hiding randomness. Each
trial starts from a prepared, resident, ready service; if it uses a fresh
worker service, record its startup separately before delivering the package
inputs. Use the production wallet/prover/node/transport path on an approved
engineering network with synthetic funds. Preserve retained stores and
journals; real payments and deployment keys are outside this test plan.

For each trial retain the following private evidence:

1. Configuration, artifacts, resource enforcement, startup duration and
   preparation/residency verified before the arrival marker.
2. Final-package arrival, all leaf proofs, both eight-input proofs and root
   completion. Record individual stage wall/CPU times, worker activity, timed
   queueing and any pre-arrival work using the boundary above.
3. Separate PoW, publication, propagation, full peer validation, durable block
   acceptance and recipient wallet scanning/reconciliation observations. Compare
   complete public roots and cumulative work at matched tips, not height alone.
4. Sender reservation/journal and recipient receipt reconciled exactly once;
   distinguish observed inclusion, confirmation and finality. A scan result is
   not final settlement; the 100-block finality window has no 180-second gate.
5. Whole-worker lifetime and interval peaks, charged-memory history, resident
   preparation, actual limits, zero extra swap, OOM/restart counters, node
   budgets, host reserves and explicit completed-state availability. Capture
   teardown/cancellation as well.

Require correctness, the enforced 5-GiB budget and last-package-to-root latency
of at most 180 seconds in all three trials. Report every failure, individual
values, medians and maxima, with cold startup separate. Do not substitute the
fastest run or ignore failed attempts. Restart replay, disconnect/reconnect,
memory-limit and reorg regressions remain required in addition to the three
normal-flow trials. Sustained load and hardware variability need further
evidence before broad deployment.

Historical D4/W16 N=16 measurements include leaf-B and uniform-q92 medians of
29.591 and 64.04 seconds for setup-excluding proof/verification. Both are below
180 seconds numerically; neither qualifies because D4/W16 fails the required
security targets and those records do not establish the new timing markers or
hard memory limit. See the [retained-result interpretation](proof-composition.md#timing-boundary-and-retained-result-interpretation).

## Closure and remaining decisions

Reserve measured timing margin for hardware, propagation and load variation.
N=32 is a pending assessment after the D8 early checkpoint, excluded from the
current work and subject to a separate proposal. No capacity increase or
retained-network migration is part of this plan. Resolve the reviewed D8
artifact/codec binding, actual supported hardware
profiles and isolated network resource admission before launch. Preserve the
existing deployment guard, seven-node N=2 stores and all historical evidence.
