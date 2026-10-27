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

The relay envelope has a fixed 1,899-byte prefix and one bounded proof body.
All integer framing is little-endian and encodings are canonical.

| Field | Bytes |
| --- | ---: |
| Magic and format version | 6 |
| Fixed suite descriptor | 27 |
| Network identity | 32 |
| Snapshot height and block identity | 40 |
| Public transaction body | 1,742 |
| Confidential fee commitment | 48 |
| Proof-body length | 4 |
| **Fixed envelope prefix** | **1,899** |
| Proof-body maximum | 524,288 |
| **Maximum envelope** | **526,187** |

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

The maximum envelope plus sidecar is **526,265 bytes** before stream framing.
The permanent per-position record is **1,830 bytes**: 1,742 public bytes,
48 fee-commitment bytes and a 40-byte snapshot selector. Version, suite and
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

| Positions per 300 seconds | Maximum envelope plus sidecar bytes | Uplink with three copies | Transfer time at 25 Mbps |
| --- | ---: | ---: | ---: |
| 576 | 303,128,640 | 24.25029120 Mbps | 291.00349440 s |
| 544 | 286,288,160 | 22.90305280 Mbps | 274.83663360 s |

At 576 positions this leaves 28,114,080 bytes per interval, about 3.00% of the
25-Mbps budget. Settlement proofs, block headers, inventories, stream framing,
missing-data requests, handshake traffic and any relay copies beyond three
must fit in that remainder. A 576-entry full-ID inventory is 18,432 bytes per
copy before framing. Reserve and measure the actual settlement envelope
separately; its canonical prefix is 159 bytes and its bounded proof body is
at most 524,288 bytes, for a maximum of 524,447 bytes. Three copies add
0.04195576 Mbps, bringing transaction/sidecar plus settlement payload to
**24.29224696 Mbps** and leaving 26,540,739 bytes per interval before inventory,
framing and other traffic. No unmeasured allowance establishes full-network
capacity.

Retain `MAX_LEAF_PROOF_LEN=524288`. If no eligible final relation fits the
bound, select a larger blowup first, then report the 544-position fallback if
necessary. Local pool pressure does not change consensus capacity. There is no
automatic increase above 576 positions.

## Proof retention and synchronization

Keep transaction and settlement proofs for four weeks after depth-24 finality,
then delete their online proof bodies. Keep private fee sidecars for the same
operational retention period where received; they are not part of public
historical verification. Permanent records retain canonical public data,
snapshot selectors and public fee commitments. Deletion must not erase those
records, current accepted state or the trusted verifier manifest.

Four weeks means at least 2,419,200 elapsed seconds after finality. The local
deletion schedule is not a consensus clock. Persist finality/retention metadata
and fail toward longer retention after uncertain clocks or recovery. At the
300-second target this is nominally 8,064 additional blocks, but a faster chain
must not shorten the elapsed retention minimum. Test restart, clock adjustment,
reorganization near finality and incomplete deletion recovery.

Size the online proof store separately from memory pools. At continuous
576-position blocks, maximum-size proofs and the nominal 300-second target,
four weeks plus depth-24 finality span 8,088 blocks. Transaction proof bodies
alone require approximately 2.44 TB; settlement proofs, permanent public data,
sidecars, indexes, recovery reserve and archival growth are additional. Faster
blocks can increase the elapsed-time retention requirement. Disk pressure must
not silently shorten proof retention: stop affected admission/production and
report local unavailability before losing required evidence.

An archive node retains public transaction and settlement proofs beyond online
expiry. Full validation from genesis requires an authentic complete archive,
the corresponding public records and every trusted verifier needed for replay.
Header work and matching state roots alone cannot prove deleted transactions.
Fee openings are unnecessary for verifying either public proof and must not be
made an archive bootstrap requirement.

A pruned new node must instead trust an authenticated checkpoint authority or
an already fully validating node. Its checkpoint authenticates genesis/network,
height/block identity, cumulative work, accepted state commitments and a
complete snapshot window. Verify every later block with the normal transition.
Document who vouches for the checkpoint and the consequence of that trust;
agreement among unauthenticated peers does not remove it. Test wrong-network,
stale, conflicting, incomplete and unavailable checkpoints and archives.

## Transport privacy work

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
the network endpoints from a passive observer. Dandelion++ or a reviewed relay
design must separately address origin-to-transaction correlation before launch.
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
excluding independent review and infrastructure procurement. Parallel work
can shorten elapsed time; unresolved security decisions can extend it.

| Milestone | Work | Estimate | Exit condition |
| --- | --- | ---: | --- |
| N1 | Versioned block/public-record codec and common producer/validator transition | 4–7 days | Groups, counts, fee settlement, integer bounds and atomic rejection tests pass |
| N2 | Admission service, isolated verifier workers, quotas and padding proof pool | 4–7 days | Byte accounting, adversarial decode, exhaustion, expiry and reorg tests pass |
| N3 | Compact inventories, bounded missing-data recovery and block reconstruction | 3–5 days | Collision/missing-data/reconnect tests and full-capacity relay measurement pass |
| N4 | Four-week retention, archival replay and explicit-trust checkpoint bootstrap | 4–7 days | Recovery/pruning tests and verified archive/checkpoint synchronization pass |
| N5 | Reviewed hybrid handshake and actual-listener failure tests | 6–10 days | Negotiation, downgrade, key confirmation, erasure and reconnect tests pass |
| N6 | Dandelion++ or reviewed relay integration and source-privacy analysis | 5–8 days | Bounded origin-hiding relay, failures and leakage review pass |
| N7 | Independent engineering-network acceptance | 3–5 days | New-genesis end-to-end payments, capacity, memory and recovery gates pass |

N1/N2 may proceed after proof-parameter freeze. N3 depends on their codecs;
N4 can develop against their authenticated records. N5/N6 follow the native
AIR/scan work and can proceed in parallel with node integration. N7 requires
all preceding gates and independent review of the relevant security changes.
None of these milestones imports or migrates retained seven-node state.
