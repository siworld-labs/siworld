# Protocol Specification

This document describes the retained SI-only implementation. Native V1
requirements are distinguished in the selected-route section below; existing
constants and recursive behavior are not new-network acceptance criteria. Constants are in `crates/core/src/params.rs`; executable rules are in `crates/consensus`. Genesis commits network parameters. Mainnet constructors contain placeholders and do not define an activated network.

## Units and issuance

Amounts are unsigned integer atoms: 1 SI = 100,000,000 atoms. Ratios use integer fixed point. SIP is a reserved denomination, not a separate asset: 1 SI = 10,000 SIP. Current wallet input and output use SI.

| Constant | Value |
|---|---|
| Minimum nonzero note | 10,000 atoms |
| Epoch | 20,160 blocks |
| Initial reward | 678,904,903 atoms |
| Decay Q32 | 4,268,204,354 |
| Tail reward | 30,000,000 atoms |
| Coinbase maturity | 100 blocks |
| Maximum fund payouts | 8 per block |
| Fund lock duration | 157,680,000 protocol seconds |

At epoch e, r[0] = INITIAL_REWARD and r[e+1] = (r[e] * DECAY_Q32) >> 32 with a wide intermediate. The reward is max(r[e], TAIL_REWARD). Each fund account receives floor(reward / 20); the miner receives the exact remainder.

Current fees are reward-linked: standard = floor(reward / 1,000), priority = 4 * standard. An all-dummy slot pays zero. Variable bids and payment-budget fee selection are not implemented. Fixed fullness cannot measure paid demand.

## Notes and slots

A note commits to owner, value, unlock height, rho and rseed. Owner derives from the spend secret; the nullifier derives from that secret and rho. Output rho derives from both input nullifiers under an output-specific tag. Miner rho derives from height; fund-payout rho derives from height and payout index.

Every slot has two inputs and two outputs. Its public encoding has two 32-byte nullifiers and two outputs, each with a 32-byte commitment, 1,344-byte ciphertext and one-byte view tag: 2,818 bytes total. A nonzero input requires tree membership. Dummy inputs skip membership but retain nullifier derivation and uniqueness. Outputs have value zero or at least the minimum deposit.

The relation enforces authorization, membership, conservation including fees, output-seed derivation, ranges and unlock constraints. Consensus independently rejects duplicate and previously spent nullifiers. Ciphertext decryptability is not proven.

## Recent-roots accumulator

The reference commitment tree has depth 40. A depth-12 ring buffer retains 4,096 anchor entries. Position h modulo 4,096 holds the tagged hash of commitment root, anchor height and standard fee. Leaves expose anchor entries; level-one recursion proves membership. A container uses the parent's or grandparent's accumulator root. Individual anchor heights and fees are not published on chain.

## Block validity

1. Exactly N slots appear in strictly ascending order of proof-independent BLAKE3 slot hash.
2. Every on-chain field element has canonical encoding below the modulus.
3. Nullifiers are pairwise distinct and absent from prior state.
4. The root proof verifies under the key for N and the recomputed slot sum, allowed accumulator root, height, miner commitment and share.
5. Issuance and fund shares are exact. The miner note contains its share plus private fees, with unlock height equal to height plus maturity.
6. Miner commitments wait 100 blocks before insertion into the commitment tree.
7. Fund payouts satisfy signature, chain-ID, counter, minimum amount and available-account limits. Public payout plaintext determines its commitment.
8. Timestamp, target, work, body commitments and resulting state roots are valid.
9. The shared producer/validator transition succeeds atomically; failure leaves prior state unchanged.

## Work and fork choice

Sequential BLAKE3 work is seeded by the fixed header and nonce. The final digest, read big-endian, must be below the 256-bit target. Integer ASERT is anchored at genesis with a 14,400-second half-life. Timestamp exceeds the median of the preceding 11 blocks, or the parent while the initial window is incomplete.

The 900-second future-time limit is relay policy, not local-clock-dependent consensus validity. Fork choice follows cumulative work with a local 100-block reorganization bound. Long partitions may require explicit recovery; see [security boundaries](security-model.md).

## Network configuration

The reference constructor uses N = 32, 60-second blocks, 1,000,000 work iterations and Plonky3. It is not an active mainnet. Testnet genesis accepts power-of-two capacities 2 through 128 and calibrates work for its chosen target and miner count. Capacity is fixed; automatic demand adjustment is not implemented.

## Poseidon2 instance

KoalaBear, width 16, eight full rounds, 20 partial rounds, x-cubed S-box, rate eight and capacity eight. Digests have eight field elements, each encoded as canonical little-endian u32. Tests pin constants and native/circuit equivalence.

## Poseidon2 packing and domain tags

Each hashed u64 is four little-endian 16-bit limbs. The first permutation receives the first block followed by tag, block count and six zeros. Later blocks overwrite the rate; additional squeezes zero the rate before permutation. Each tag has a fixed input length.

| Tag | Purpose |
|---|---|
| 1 | Owner |
| 2 | Note |
| 3 | Nullifier |
| 4, 5 | Output rho |
| 6, 7 | Retired and reserved |
| 8 | Set element |
| 9 | Merge-node statement |
| 10 | Anchor |
| 11 | Miner rho |
| 12 | Payout rho |

## Wallet addresses

Format v1 carries a 32-byte owner, a 1,184-byte ML-KEM encapsulation key and a five-byte BLAKE3-derived checksum. Prefixes are `si` and `tsi`; lowercase is canonical, uppercase accepted, mixed case rejected. A testnet address has 1,958 characters and is intended for copying or QR transport. A short recipient directory is not implemented.

## Planned native V1 transaction route

Status: selected design with isolated native three-output transaction AIR,
codec, fixed-supply issuance proof and SI-reward settlement implementations.
The [multi-asset transaction engineering profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
binds the selected parameters, implementation, dependency graph, public verifier
key and qualified measurements. See the
[actual multi-asset evaluation](v1-multi-asset-evaluation.md). Node integration
is planned and the route is not activated. The retained
seven-node N=2 network keeps its current verifier, history, parameters and keys.
The new route uses independent genesis, network identity, directories and keys
and imports no retained notes or proofs. See the
[native transaction proof design](route-a-v1.md) for requirements and open gates.

| Requirement | New-route target |
| --- | --- |
| Transaction proof | Native STARK per fixed two-input/three-output multi-asset transaction; no recursive aggregation in V1 |
| Suite | KoalaBear D8, standard Plonky3 Poseidon2 W24, 12-base-element (48-byte) digests |
| Security screening | Classical conjectured at least 128 bits; every Fiat–Shamir Johnson term, including queries and enforced grinding, at least 80 bits after quantum halving; challenge-domain terms at least 80 bits after halving; BHT commitment collision resistance at least 80 bits |
| Anchor | Depth-12 recent-root membership checked inside the transaction AIR; only the recent-root tree root is public |
| Snapshot acceptance | Newest 4,096 canonical-chain tree snapshots; reject expired/orphaned identities and evict affected pending transactions for wallet reproof |
| Output-encryption boundary | V1 byte binding; sender self-check before broadcast, private per-payment receipt material, recipient AEAD/commitment checks; padding uses real ephemeral-key ML-KEM encryption |
| Fee tiers | Reward-linked standard and four-times-standard priority; Scheme B native confidential settlement ([design](fee-settlement.md), [evaluation](fee-settlement-evaluation.md)); independent review and node integration precede activation |
| Public-data encoding | Implemented isolated three-output codec: 2,027-byte body plus 48-byte fee commitment and 40-byte snapshot selector, or 2,115 permanent bytes |
| Relay envelope | Three-output prefix: 2,184 bytes plus the frozen transaction proof-body cap; private sidecar remains 78 bytes. Node decoder integration remains required |
| Change encryption | ChaCha20-Poly1305 with a 256-bit key and domain-separated BLAKE3 derivation |
| Blocks | Groups of 16; 64–576 positions; 300-second target; 43-Mbps minimum uplink from the complete bounded wire model with at least 15% unused link capacity; 100 Mbps recommended |
| Reorganization bound | New-route local `MAX_REORG_DEPTH = 24`; existing implementation remains at 100 |
| Proof retention | Transaction and settlement proofs plus private fee sidecars are retained for three elapsed days after final confirmation, then deleted; all public data remains permanent, no archive role is selected, and release checkpoint-plus-PoW trust is explicit |
| Proof-body maximum | Transaction admission cap: 655,360 bytes (640 KiB), 12.06% above the selected profile's largest measured proof and rounded to 64 KiB. Settlement and issuance remain capped at 524,288 bytes each; maximum block capacity remains 576 |
| Transaction parameter choice | `log_blowup=7`, 41 queries, query/batch grinding 20, commitment grinding 0, binary folding, final-polynomial log length 0. Selected from blowup 5–8 × grinding 20/24, three trials each: all selected generations at most two seconds on a qualified EPYC 7763 four-vCPU VM, then smallest maximum measured proof |
| Parameter-freeze boundary | Isolated transaction engineering freeze with matching relation, dependencies, public key, codec, security report and qualified resource evidence; node decoder/admission, wallet/network integration, independent review and activation remain separate gates |

Nodes verify proofs on mempool admission. Blocks use compact references and
public transaction data without duplicating proof bodies. The selected snapshot
and byte-binding requirements still need node/wallet integration. Private fee
collection, worker isolation and byte/CPU/in-flight quotas follow the
[node and network plan](v1-node-network-plan.md). The transaction engineering freeze records the relation, codec, verifier,
security and qualified resource evidence without claiming these node properties. The
[fee-settlement design](fee-settlement.md) is not an activated rule; its
[evaluation gate](fee-settlement-evaluation.md), independent review and node
acceptance must pass before activation. The isolated issuance path verifies
ML-DSA-65 and a native proof of exact hidden minted supply, with an external
verified SI fee-payment gate; node application and issuance fee policy remain
open. A keyless public node cannot authenticate an AEAD tag. Isolated native
proof implementations do not establish the pending node/network properties.

Recursive aggregation and historical proof compression are deferred to V2.
The [recursive suite plan](d8-w24-recursion.md) describes paused experimental
work. Its 180-second root-proof target and experimental memory ceiling do not
apply to native V1. The [current acceptance plan](prover-acceptance.md) instead
qualifies native transactions, independent settlement, 24-block reorganization
boundaries and full-network operation. N=32 is outside the V1 scope.
The [V1 transport and checkpoint design](v1-network-design.md) selects
authenticated hybrid identity, Dandelion++ and explicit-trust bootstrap;
implementation and review must pass before the new network launches.
