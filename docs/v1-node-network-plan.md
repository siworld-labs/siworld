# Native V1 Node and Network Integration

Status: implementation plan for the independent native-proof engineering
network. The transaction AIR, bounded proof decoder, canonical snapshot pool
and wallet output checks are isolated engineering components. This document
does not activate them on the retained seven-node network.

## Proof parameters and activation

Proof-parameter freeze records the implemented relation, dependency revisions,
trusted verifier, canonical codecs, security reports and successful resource
measurements. It is distinct from independent cryptographic review and from
node, wallet or network activation. Durable wallet receipt integration and the
remaining node work below do not, by themselves, prevent that freeze. They
remain prerequisites for accepting user transactions on the new network.

The selected native profile is KoalaBear D8, standard Poseidon2 W24,
twelve-element digests, `log_blowup=8`, 36 queries, 20 query-grinding bits,
20 opening-batch-grinding bits and zero commitment-grinding bits. Folding is
binary and the last polynomial has logarithmic size zero. The
[engineering freeze bundle](../crates/bench-d8/artifacts/v1-native-freeze.json)
pins the source, public verifier artifacts and actual-instance security
reports. Hosted resource evidence, independent cryptographic review and node
activation are separate gates. A diagnostic row alone does not establish
cryptographic approval.

No V1 node path may use a verification key, suite or proof parameters supplied
by a peer. Resource exhaustion, a local timeout and an unavailable peer are
not cryptographic invalidity and must not become consensus rejection rules.

## Canonical transaction ledger

The proposed three-output relay envelope has a 2,184-byte prefix and one
bounded proof body. All integer framing is little-endian and encodings are
canonical. The current diagnostic implementation has a 1,899-byte prefix;
its source and artifact hashes remain baseline evidence only.

| Field | Bytes |
| --- | ---: |
| Magic and format version | 6 |
| Fixed suite descriptor | 27 |
| Network identity | 32 |
| Snapshot height and block identity | 40 |
| Public transaction body | 2,027 |
| Confidential fee commitment | 48 |
| Proof-body length | 4 |
| **Fixed envelope prefix** | **2,184** |
| Proof-body maximum | 524,288 |
| **Maximum envelope** | **526,472** |

The separate fee sidecar is 78 bytes: four-byte magic, two-byte version,
32-byte transaction identity, eight-byte fee and eight canonical field-element
blinding limbs occupying 32 bytes. These limbs provide approximately 247.91
bits of entropy when sampled uniformly, or approximately 123.95 bits under a
generic quantum search accounting; a 32-byte encoding is not a claim of 256
bits of entropy. It carries no signature, encryption wrapper,
dummy flag or fee-tier flag. The receiver checks the transaction identity and
fee opening against the commitment; the transaction proof establishes fee
validity under its private anchor's schedule. The current block fee schedule
cannot classify an older anchored fee. These
private values must never enter public logs or chain data.

The transaction identity is a domain-separated BLAKE3 digest of the canonical
statement: network, suite, snapshot identity, public body and fee commitment.
It excludes the proof length, proof randomness and sidecar. A new proof for the
same statement therefore preserves the identity. A verification cache also
keys on the proof digest and locally trusted verifier identity; statement
identity alone cannot authenticate a replacement proof.

The proposed maximum envelope plus sidecar is **526,550 bytes** before stream
framing. The proposed permanent record is **2,115 bytes**: 2,027 public bytes,
48 fee-commitment bytes and a 40-byte snapshot selector. Recheck both values
against the actual three-output codec and AIR; they are not measured artifacts.
Version, suite and
network context may be amortized in the authenticated block header. A full
32-byte compact reference is additional transmission data when sent, rather
than an additional independent permanent transaction field. The transaction
identity is reconstructible from the authenticated canonical record.

## Admission and local resource policy

The initial policy below is a design for the new network, not a measurement of
the retained node or a change to its existing 64-MiB mempool ceiling. Bounds
apply to owned bytes, including sidecars and internal bookkeeping. An entry
count supplements a byte limit; it never replaces one. Reserve capacity before
reading or copying a declared body and release reservations on every failure.

| Resource | Initial local policy |
| --- | --- |
| Verified transaction pool | 512 MiB and at most 2,048 entries |
| Unverified ingress queue | 64 MiB and at most 128 entries |
| Per-peer unverified ingress | 2 MiB and at most four entries |
| Per-peer verified contribution | 16 MiB and at most 64 entries |
| Concurrent transaction verification | Two isolated workers, one proof per worker |
| Verifier worker sandbox | Selected initial policy: 128 MiB charged memory, zero swap, 250-ms CPU allowance per job |
| Local deadlines | Ten seconds to receive a reserved transaction body; five seconds of queue residence; two-second verification wall deadline |
| Negative-result cache | 1 MiB, at most 8,192 entries, 300-second local expiry |
| Peer-abuse state | 1 MiB, at most 4,096 opaque peer identities, 600-second local expiry |
| Missing-data block reconstruction | 640 MiB and at most two candidate blocks |
| Padding proof pool | Target at least 64 usable entries; maximum 128 entries and 65 MiB |

The worker memory and CPU values are selected initial operational guards.
Isolated verifier measurements, malformed-input tests and target-host load
tests validate their applicability before activation. Combined setup/prove/
verify cgroup peaks do not establish the verifier's own memory requirement.
A worker killed by its limit produces a retryable local resource result, not
an invalid-proof verdict. Candidate-block validation must reschedule or report
unavailability rather than reject a cryptographically valid block because a
local deadline expired.

At maximum wire size, the 512-MiB transaction budget holds at most 1,020
transactions before bookkeeping; the 64-MiB queue holds at most 127. The
128-entry padding pool needs 67,361,920 wire bytes, about 64.24 MiB; the
65-MiB serialized-payload cap leaves limited payload headroom. Bounded map
metadata is accounted separately in the node budget; it is not covered by
this payload cap.
The 64-entry target is a readiness condition, not permission to exceed a cap.
Padding generation pauses rather than exceeding memory or CPU budgets.

Admission order is:

1. Validate the outer fixed header, declared lengths, network and fixed local
   suite before allocating the full body. Reserve both global and peer bytes.
2. Resolve the selected canonical snapshot from trusted state. Reject expired,
   orphaned or unknown selectors before proof decoding.
3. Decode canonical public data, the bounded proof and fixed sidecar. Check
   the sidecar identity and fee opening against the public commitment before
   scheduling proof work. A matching opening is not proof validity.
4. Verify the proof using the locally prepared shape, trusted root and frozen
   verifier. Bound concurrency separately from the number of queued jobs.
5. Recheck current snapshot membership, confirmed nullifier conflicts and both
   pending nullifier reservations. Atomically insert the verified object and
   both reservations, or release every reservation without changing state.

Use a separate small bounded duplicate cache for in-flight statement/proof
pairs. An entry becomes a negative cryptographic result only after a complete
verification failure. Do not penalize a peer for local resource exhaustion or
ordinary missing data. Cache keys include network, verifier and snapshot
context; expiry or a reorganization invalidates affected positive and negative
entries. Peer diagnostics use bounded opaque identities and error classes,
without addresses, private openings, individual fees or timed nullifiers.

Proof parsing first walks the pinned schema without allocation, then performs
dependency decoding. Its 4-MiB declared-vector budget bounds declared vector
payloads and headers, not total allocations or RSS. Decoder scratch, canonical
re-encoding, allocator overhead and cryptographic verification remain inside
the worker resource guard. Fuzzing must measure those costs rather than infer
them from the wire maximum.

## Block production and validation

The block codec permits groups of 16, with 64 through 576 positions. A
consensus-visible position always contains the same transaction shape.
Producer and validator use the same integer-only atomic transition for the
ordered transaction statements, nullifiers, outputs, issuance and settlement.
The settlement proof is verified independently of all transaction proofs.
Its statement must bind every position exactly once and the single miner
reward output; compact references cannot substitute for this binding.
For a block below 576 positions, the fixed settlement AIR's remaining rows
use canonical zero-fee commitments derived from network, height, declared
block-position count and row index. The verifier reconstructs this tail; it does not add
transactions to the block. The public reward value is a note commitment, with
the amount and fee total private. Each transaction proof authorizes its own
private anchored fee schedule; settlement opens and sums those fees without
imposing a single current block schedule on all positions.

Miners prepare ordinary valid zero-input padding proofs without owning notes.
Maintain the 64-entry target and 128-entry cap above, replenishing under the
same fixed proof parameters and resource controls. Every padding transaction
uses actual ephemeral-recipient encryption and fresh unique nullifiers. Its
proof, ciphertext and fee-commitment encoding is identical to an ordinary
transaction's encoding. Pool entries are private operational state; do not
publish counts or public classification labels.

Snapshot expiry or orphaning evicts affected padding and pending entries and
releases both nullifier reservations atomically. A same-root replacement with
a different block identity still requires a new proof. Inclusion removes the
entry from the usable pool; failed candidates may return it only after all
current snapshot and nullifier checks pass. A shortage of usable padding
delays production or triggers bounded regeneration; it does not permit an
undersized block or invalid placeholder.

At the 300-second target, finality is depth 24 and `MAX_REORG_DEPTH=24` for the
new route. Test depth 23, 24 and 25 explicitly, including the exact finalized
boundary, reward accounting, snapshot-window refill and orphaned-pool eviction.
Deeper divergence requires explicit checkpoint recovery. The retained route's
existing reorganization policy is unchanged.

## Compact relay and capacity

Initially use full 32-byte statement identifiers in inventories. Short IDs
require a separately reviewed collision-recovery scheme. Authenticate the
complete ordered list, retrieve missing public records and proofs under the
same byte/admission limits, and verify all data before applying a block.
Request no more than 16 missing transactions per response; reserve their
declared bytes before accepting the response. Limit reconstruction to the
640-MiB/two-block budget above, including retained downloaded bodies and
bookkeeping. Stream accepted bodies to the bounded proof store rather than
building additional unaccounted copies.

Missing sidecars prevent a local producer from constructing settlement. A
validator does not require a sidecar to check an already constructed block:
the public fee commitments and settlement proof establish its validity.
Sidecar recovery is a private relay operation over the hybrid connection;
it must not publish fee openings to an explorer or public block endpoint.

The proposed multi-asset transaction plus sidecar is 526,550 bytes at the
proof cap; 576 positions and three relay copies plus capped settlement use
24.30537976 Mbps before transport/control costs. The minimum uplink is 30 Mbps;
100 Mbps is recommended. The [complete conditional wire budget](v1-network-budget.md)
adds explicit inventories, requests, AEAD/multiplexing, IPv6/TCP/link framing,
reciprocal ACKs, handshakes, keepalive, bounded issuance, retransmission and
recovery allowances: approximately 29.252 Mbps, leaving 2.49% additional margin
at the floor. Validate and measure each assumption with the actual listener.
Neither a payload fit nor this planning envelope is network acceptance.

Retain `MAX_LEAF_PROOF_LEN=524288`. If no eligible final relation fits the
bound, select a larger blowup first, then report the 544-position fallback if
necessary. Local pool pressure does not change consensus capacity. There is no
automatic increase above 576 positions.

## Proof retention and synchronization

Keep transaction proofs, settlement proofs and received private fee sidecars
until three elapsed days after final confirmation, then delete them from the
online proof store. The nominal depth-24 finality delay is two hours, so a
target-rate node retains 888 blocks in steady state: 24 unresolved blocks plus
864 finalized blocks. Persist finality and retention metadata and extend the
window when clocks, reorganization state or recovery are uncertain. Never use a
fixed block count to shorten the elapsed-time requirement.

Every node permanently retains public data without pruning: block headers and
PoW, output commitments and commitment-tree state, ciphertexts, nullifiers,
fee commitments, per-block settlement declarations without proofs, miner reward
notes, development-fund records and ML-DSA signatures, public asset issuance
records and recent-root snapshots. Proof deletion must not remove these records, accepted state,
snapshot selectors or the trusted verifier manifest. Keep proof and sidecar
stores bounded separately from memory pools and test interrupted deletion,
restart, clock adjustment and reorganization near finality.

V1 has no archive-node role and does not retain proof bodies beyond the three-day
window. A release checkpoint distributed with the node and authenticated PoW is
the default new-node synchronization path. The checkpoint binds the network and
genesis identity, block identity, cumulative work, accepted state commitments,
complete snapshot window, verifier manifest and permanent-data roots. Verify
every later block with the normal transition. Full proof replay from genesis,
using an optional proof archive or asynchronous V2 history compression, is a
future upgrade and is not a V1 launch dependency. Checkpoint bootstrap is an
explicit trust assumption; unauthenticated peer agreement, matching roots or
header work cannot prove deleted transaction proofs. Test wrong-network, stale,
conflicting, incomplete and unavailable checkpoints fail closed.

At 576 positions per 300 seconds, three-day post-finality retention including
the nominal finality delay is 268,672,484,352 bytes for capped transaction
proofs, settlement proofs and sidecars. The proposed 2,115-byte multi-asset
position adds 128,061,388,800 permanent bytes/year. Use [the storage component
model](v1-storage-and-sync.md) for year-1/3/5 and 10k/50k demand estimates.
Measure indexes, full state, amortized records, issuance, WAL/compaction and
recovery space before qualifying the 500-GB floor or 1-TB recommendation.

Project-operated object storage backs up permanent public data but is not an
archive for deleted proofs. Upload finalized block segments at least every six
hours with immutable versioning, publish a signed daily manifest, and create a
weekly full checkpoint snapshot. Restore into an isolated node by verifying
object hashes/signatures, replaying blocks and PoW, rebuilding indexes, and
comparing roots, work and state before promotion. Run monthly restore checks and
quarterly replacement-host recovery tests. Wallet creation requires an explicit
mnemonic backup; a restored wallet rescans all permanent ciphertexts from genesis or
an authenticated wallet birth height, including pre-checkpoint segments, verifies note and asset ownership, and reconciles balances and
payment journals exactly once.

## Transport privacy work

The [network design](v1-network-design.md) selects dual Ed25519/ML-DSA-65
identity authentication for ephemeral X25519 plus ML-KEM-768 and Dandelion++.
Its reviewed combiner/library profile and routing parameters must be frozen
before deployment. Pruned bootstrap uses explicit opt-in two-of-three
checkpoint trust with genesis-pinned authority identities; the release
checkpoint-plus-PoW path is the V1 default. Full proof replay remains a future
independently verifying alternative. Neither mechanism is implemented or
independently approved by selecting this design.

The workspace currently uses libp2p 0.56 with TCP, DNS, Noise, Yamux and
request-response. The live service constructs `noise::Config::new` in its TCP
upgrade; its transaction announcements flood peers. It has no implemented
X25519 + ML-KEM handshake or Dandelion++ source-hiding path. The output
encryption's ML-KEM dependency does not upgrade the connection handshake.

Implement a distinct versioned authenticated libp2p upgrade combining ephemeral
X25519 and ML-KEM shared secrets through a domain-separated reviewed hybrid
KDF. Bind network, offered/selected algorithms, both identities and the complete
handshake transcript into authentication and key confirmation. Specify
decapsulation failure behavior, replay resistance, key erasure and identity
authentication separately. Do not fall back to classical Noise for V1 wallet,
sidecar or node traffic after hybrid negotiation fails. Authentication must
receive its own quantum-security review; hybrid key exchange alone does not
upgrade a classical long-term signature.

Hybrid encryption addresses recorded-content confidentiality. It cannot hide
the network endpoints from a passive observer. The selected Dandelion++
path must separately address origin-to-transaction correlation before launch.
This requires bounded stem/fluff queues, loop/failure handling, randomized
relay selection and reconnect behavior without emitting source addresses or
transaction-time associations in diagnostics.

Use actual TCP listeners in end-to-end tests for successful negotiation,
wrong-network and unsupported-version rejection, downgrade attempts, malformed
KEM input, failed key confirmation, transcript mutation, interrupted handshake,
half-open connections, reconnect and bounded resource cleanup. Synthetic
in-memory messages alone do not cover the deployed transport.

## Implementation milestones

Estimates are engineering days for one engineer familiar with the codebase,
excluding independent review, infrastructure procurement and elapsed soak or
retention windows. Parallel work can shorten elapsed time; security findings
can extend it. N1–N7 sum to 33–56 days; wallet durability and private monitoring
are separate N8/N9 work, for a combined planning range of 42–71 days.

| Milestone | Work | Estimate | Exit condition |
| --- | --- | ---: | --- |
| N1 | Versioned block/public-record codec and common producer/validator transition | 4–7 days | Groups, counts, fee settlement, integer bounds and atomic rejection tests pass |
| N2 | Admission service, isolated verifier workers, quotas and padding proof pool | 4–7 days | Byte accounting, adversarial decode, exhaustion, expiry and reorg tests pass |
| N3 | Compact inventories, bounded missing-data recovery and block reconstruction | 3–5 days | Collision/missing-data/reconnect tests and full-capacity relay measurement pass |
| N4 | Three-day proof retention, permanent public-data backup and explicit-trust checkpoint bootstrap | 4–7 days | Recovery/pruning tests and verified checkpoint-plus-PoW synchronization pass |
| N5 | Reviewed hybrid handshake, dual identities and actual-listener failure tests | 10–17 days | Identity binding/rotation, negotiation, downgrade, key confirmation, erasure and reconnect tests pass |
| N6 | Dandelion++ integration and source-privacy analysis | 5–8 days | Bounded stem/fluff routing, failures and leakage review pass |
| N7 | Independent engineering-network acceptance harness and execution | 3–5 days | Reproducible native acceptance and fault injection; elapsed observation windows complete separately |
| N8 | Durable wallet integration and recovery | 6–10 days | Change keys, receipts, output self-check, reproof and exactly-once backup/recovery tests pass |
| N9 | Private multi-host telemetry and live panel | 3–5 days | Authenticated read-only feeds, five-second samples, stale markers and durable incidents pass loss/restart tests |

N1/N2 may proceed after proof-parameter freeze. N3 depends on their codecs;
N4 can develop against their authenticated records. N5/N6 follow the native
AIR/scan work and can proceed in parallel with node integration. N7 requires
N1–N6, N8/N9 and independent review of the relevant security changes.
Apply the [native acceptance matrix](prover-acceptance.md), including
[host/storage qualification](v1-deployment.md), 72-hour maximum-load hardware
trials, seven-day independent-host observation, real retention lifecycle and
explicit recovery targets. No short standalone proof run closes those gates.
None of these milestones imports or migrates retained seven-node state.

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
