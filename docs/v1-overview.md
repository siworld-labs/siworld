# Native V1 System Overview

Status: the selected economic revision reopens native transaction, settlement
and issuance proof parameters. The prior source-bound profiles are baseline
evidence, not qualification of the revised lock and reward relations. Native
node, wallet and network integration remains incomplete. There is no public
native V1 testnet or production network. See the [monetary rules](v1-economics.md).

**Engineering target ≥80-bit quantum security, pending independent review.**
The target applies to the specified estimator terms; it is not a reviewed
full-system security claim.

## Implementation boundaries

| Area | Present implementation | Remaining native V1 work |
| --- | --- | --- |
| Transaction proof | Private asset IDs, two inputs/three outputs, per-asset conservation, SIP-only fees, snapshot/ciphertext binding and source-bound profile | Canonical envelope, bounded node decoder, atomic admission and wallet integration |
| Issuance and settlement | Three-initial-note fixed-supply issuance, declaration-signature checks and fixed-576 SIP-only fee settlement baseline | Mode-dependent one/five reward notes, pool/burn/fund accounting, revised keys and resource screening, atomic integration |
| Existing node | Legacy two-output recursive proofs, storage, peer relay and local RPC | It does not activate native V1 |
| Native network | Codec, transport, retention and acceptance requirements | Complete block validation, compact relay, pruning, checkpoint bootstrap and sustained-load qualification |
| Connection privacy | Hybrid authenticated transport and Dandelion++ designs | Reviewed implementation and actual-listener adversarial tests |

A proof executable or proof-tools image is not a node runtime. The retained
seven-node N=2 legacy engineering testnet keeps its history, verifier and keys.
A native V1 engineering network requires independent genesis, identity,
directories and keys; it imports no retained notes or proofs.

## Transaction flow

The selected design requires the following integrated behavior:

1. The wallet constructs the same two-input/three-output public format for SIP,
   issued assets and padding. Asset IDs are private and bound into notes.
   The relation balances each asset independently and pays fees only in SIP.
2. It generates a native D8/W24 transaction proof and locally checks encrypted
   outputs before broadcast. The AIR binds all ciphertext bytes, but does not
   prove encryption correctness or recipient decryptability.
3. A node resolves a canonical snapshot selector from trusted state, checks
   the bounded encoding and fee-opening sidecar, verifies the proof and
   atomically reserves nullifiers. Timeout/resource failure means unavailable
   verification; it is not evidence of an invalid transaction.
4. A miner selects 64–576 positions in groups of 16, adds valid fixed-shape
   padding and generates one separate native fee-settlement proof. Strict
   ordering by proof-independent BLAKE3 statement IDs and duplicate rejection
   are enforced by the isolated native codec and shared transition; this does
   not establish deployed network acceptance.
5. Compact references avoid retransmitting proofs already held by peers.
   Missing data requires authenticated bounded recovery. Production,
   validation and replay must share one atomic state transition.

The target block interval is 300 seconds; PoW timing is stochastic. Native V1
requires a 24-block local reorganization bound. It accepts the newest 4,096
canonical recent-root-tree snapshots. Expired or orphaned selectors require
transaction eviction and wallet reproof.

## Pre-revision transaction profile and measurements

The following profile predates the economic revision. Unlock-height constraints
and mode-dependent reward settlement require new actual-AIR reports, keys and
three-trial measurements before refreezing. Earlier numbers do not pass that gate.

The [three-relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
freezes fixed shapes and public keys; it does not adopt issuance limits or
qualify other capacities. [Reproduction](native-proof-profiles.md) checks the
actual-AIR reports. The separate source-bound
[transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json) uses KoalaBear D8, standard Poseidon2 W24 and twelve-element digests:
log blowup 7, 41 queries, query/batch grinding 20, commitment grinding zero,
binary folding and final-polynomial log length zero.

Three four-worker EPYC 7763 reference-VM trials took **1.332143, 1.315662 and
1.316440 seconds** for proof generation. Bodies were **583,552–584,848 bytes**.
The maximum charged process-tree memory was **531,668,992 bytes**, including
preparation, generation and verification. These measurements do not bound
wallet end-to-end latency, grinding tails, independent verifier resources or
whole-node capacity.

The transaction cap is **655,360 bytes (640 KiB)**. Separate settlement and
issuance caps are **524,288 bytes (512 KiB)** each. These are admission limits,
not mathematical bounds on every randomized proof. The actual-instance ledger
reports approximately **81.692 quantum-halved Johnson challenge bits**.
Classical conjectured and all selected quantum terms must pass their own
screens; independent cryptographic review remains required.

## Capacity, storage and roles

The limits below remain planning budgets. Reconcile the revised reward-note,
settlement and permanent-record formats before capacity or storage acceptance.

The complete conditional capacity model gives **43 Mbps minimum uplink** and
**100 Mbps recommended** for 576 positions, three relay copies and bounded
network/recovery overhead. At least 15% of the minimum link remains unused.
Integrated wire measurements and issuance limits are still qualification gates.

Every node permanently retains public ledger data: headers/PoW, commitments
and tree state, ciphertexts, nullifiers, fee commitments, proof-free settlement
declarations, reward notes, signed fund records, issuance records and recent
root snapshots. Transaction, settlement and native issuance proofs plus private
fee sidecars expire three elapsed days after final confirmation. V1 has no
archive-node role. Default bootstrap trusts a genesis-pinned two-of-three
checkpoint authority, then verifies subsequent PoW and blocks; it cannot
reconstruct deleted historical proof validity.

Every validator enforces consensus independently. A miner adds production;
bootstrap services and the panel have no consensus authority. Initial
qualification profiles start at **16 GiB RAM for validators** and a separate
**32 GiB for miners**. These are unqualified profiles. The 5-GiB diagnostic
proof scope is not a miner RAM requirement. Both roles use a 500-GB usable SSD
installation floor and 1-TB recommendation; actual lifetime depends on load,
issuance and database costs. One TB does not cover three full-load years under
the current reserve model.

## Privacy and launch gates

Fee commitments hide fee openings on chain. Sidecar recipients learn those
openings, and producers recognize their own padding. Uniform field counts and
lengths are a design requirement, not a guarantee of perfect indistinguishability.
Connection encryption does not hide endpoints; source privacy requires
separate implementation and adversarial analysis.

Complete the native transition, bounded admission, standalone verification,
wallet recovery, transport/source relay, durable public storage, retention,
checkpoint bootstrap and telemetry. Resolve issuance fees/resource limits and
asset-aware minimum outputs. Then complete independent review, maximum-load
hardware qualification and independent-host testnet observation.

See [decisions](00-decisions.md), [implementation milestones](v1-node-network-plan.md),
[testnet acceptance](prover-acceptance.md) and [the documentation index](README.md).
