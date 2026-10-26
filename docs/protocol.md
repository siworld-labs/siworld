# Protocol Specification

This document describes the current SI-only implementation. Constants are in `crates/core/src/params.rs`; executable rules are in `crates/consensus`. Genesis commits network parameters. Mainnet constructors contain placeholders and do not define an activated network.

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

## Planned D8 engineering suite

Status: implementation plan; no verifier or network activation. The selected
target is KoalaBear D8, standard Plonky3 Poseidon2 W24 and 12 base-element
digests, N=16 with two eight-input proofs and one root. Keep the retained N=2
network unchanged. A future engineering deployment uses independent genesis,
directories and keys and imports no legacy notes or proofs. Historical
height-based verifier activation is deferred until before mainnet.

Each layer and the complete recursive composition must meet classical
conjectured security of at least 128 bits, Johnson security of at least 100
bits, challenge-domain security of at least 100 bits after the selected quantum
Fiat–Shamir halving model, and commitment/Merkle collision security of at least
100 bits under BHT. Estimator screening is not a quantum composition theorem.
D4/W16 q42, q92 and leaf B fail these requirements and are methodology controls.

The proof-latency target is 180 seconds on qualified target hardware, from
final-package input arrival before queueing until canonical root completion,
including all leaf and intervening per-candidate work. Input-independent
circuits and keys are prepared at startup and remain resident. Cold-start
duration is reported separately; all startup and resident memory remains within
the selected process-tree boundary, with zero swap. The next D8 experiment
uses a 10-GiB (10,737,418,240-byte) hard ceiling; the production memory budget
remains undecided until actual peaks are measured. The experimental ceiling
is not production acceptance. Propagation, external
verification, PoW and receipt timing are separate metrics. This proof-latency
target does not change the consensus block interval.

Complete opening-batch grinding and freeze the final checkpoint configuration
before timing the first verified eight-input merge. It triggers three
same-machine measurements and an N=16 latency/memory projection. At most
135 seconds with peak memory within the 10-GiB experimental ceiling permits
continued experiments. More than 135 and at most 180 seconds within that ceiling
requires optimization alongside implementation. Above 180 seconds, above 10 GiB,
OOM or an incorrect proof pauses progression. Report stage memory with the
same prominence as stage time, including startup, prepared residency, active workspace, retained proofs
and handoff overlap. Use the EPYC 7763 Ubuntu 24.04 VM profile with two exposed
cores and four vCPUs as the Linux baseline; EPYC 9V45 is a comparison profile.
The x86_64 release baseline is x86-64-v3, with AVX2 required and no scalar
fallback. N=32 is the first separate assessment after a passing D8 checkpoint;
no N=32 evaluation is part of the current scope. See the
[implementation plan](d8-w24-recursion.md) and [acceptance plan](prover-acceptance.md).
