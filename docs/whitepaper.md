# SIWORLD: Shielded Payments with Fixed-Capacity STARK Containers

## Abstract

SIWORLD combines encrypted notes with fixed-capacity blocks and recursive STARK verification. Each block publishes the same number and shape of transaction slots, including zero-value padding. A fixed-width additive accumulator binds recursive proofs to the public slot bytes. Fees accumulate privately inside the proof tree and enter a shielded miner note. The construction targets reduced on-chain activity leakage while retaining public validation of ownership, conservation and state transitions.

This repository implements a research testnet. It does not establish production safety, network-source anonymity, payment-time anonymity or complete post-quantum security.

## State and notes

A note contains an owner digest, an integer amount, an unlock height, a nullifier seed and commitment randomness. A Poseidon2 commitment binds those fields. A spend proves knowledge of the authorization secret and, for a nonzero input, membership in the append-only commitment tree. Its nullifier is derived from the secret and the note seed. Native consensus rejects any nullifier already present in state or repeated within the block.

Each slot has two inputs and two outputs. Zero-value dummy inputs do not require membership, but still produce nullifiers. Nonzero outputs must satisfy the minimum-deposit rule. Missing inputs and outputs are represented by the same fixed public shape, not by shorter encodings.

## Output confidentiality

Each output contains a canonical commitment, a fixed-length ciphertext and a one-byte view tag. ML-KEM-768 establishes a shared secret; BLAKE3 key derivation produces a ChaCha20-Poly1305 key. The commitment is authenticated as associated data. Wallets use view tags as a trial-decryption filter and verify canonical plaintext encodings after decryption.

The proof binds ciphertext bytes to the slot through a digest. It does not prove that the ciphertext decrypts to the committed note. A malformed output can therefore prevent a recipient from recovering a payment. See [cryptography](cryptography.md).

## Recursive containers

For a slot s, the set element is:

```text
E(s) = Poseidon2(TAG_SET; nf_0, nf_1, cm_0, cm_1, d_ct)
```

E has 48 KoalaBear field elements. The ciphertext digest d_ct binds both ciphertexts and both view tags. A leaf proof exposes E, fee limbs, count 1 and an anchor entry. A level-one aggregation verifies each entry's membership in the recent-roots accumulator. Higher levels verify child proofs, add E coordinate-wise, add fees with checked carries, and preserve a common accumulator root.

The root statement contains the sum of E, the accumulator root, height, miner commitment, public miner reward share and slot count. Validators recompute the slot sum from the block, derive the reward share from integer issuance, and verify against the pinned key for the capacity. The miner note commitment binds the private fee total plus the public reward share.

The tree has a fixed depth and trusted child keys. Those constraints bound leaf multiplicity and are security-critical. An additive sum alone does not reject repeated leaves or repeated nullifiers; native checks remain mandatory.

## Consensus

Blocks use sequential BLAKE3 proof of work and integer ASERT difficulty adjustment. Fork choice tracks cumulative work subject to the implementation's local 100-block reorganization bound. Timestamps affect difficulty and median-time-past validation. The future-time limit is a relay policy, not a validity rule based on the verifier's local clock.

The producer and validator call one state transition. Validation covers slot count, strict slot ordering, canonical encodings, proofs, nullifier uniqueness, reward accounting, payouts and state roots. Failure leaves the state unchanged.

The proof is a block witness rather than part of the work commitment. Proving and nonce search can overlap after the native candidate header is fixed; publication waits for both. A failed proof copy does not permanently invalidate a header that could carry a valid proof.

## Observer boundaries

Fixed-capacity blocks remove a direct public count of paid slots. They do not hide that a particular slot appears at a particular height. Peers observe transaction arrival, relayed fees and leaf proofs; miners know their own padding. Recipients observe their own payments. Direct flooding currently exposes additional source and timing information. Low traffic, active probing and off-chain observations can reduce the effective anonymity set.

The [security model](security-model.md) distinguishes these observers and records implementation restrictions. No performance result substitutes for a cryptographic or network privacy analysis.

## Implementation scope

The implementation includes SI-only notes, real note encryption, recursive Plonky3 proofs, peer relay, persistent blocks, authenticated local RPC, encrypted wallet files, durable payment journals and fund-account controls. It retains reward-linked fee tiers and replay-based storage. Anonymous relay, multi-asset notes, payment channels, fast pre-confirmation, a quantum-sound recursive suite and a production release are not implemented by this repository.

Detailed parameters are in [protocol](protocol.md), component boundaries in [architecture](architecture.md), and reproducible measurement commands in [benchmarks](benchmarks.md).
