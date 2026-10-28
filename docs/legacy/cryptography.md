# Cryptographic Construction

> **Superseded by V1 (Route A).** This page documents the legacy recursive implementation. The retained seven-node N=2 engineering testnet uses this classical proof route; it is not a native V1 testnet or post-quantum acceptance result. See the [current V1 overview](../v1-overview.md).

## Primitives

| Use | Construction |
|---|---|
| Notes, nullifiers, anchors and tree nodes | Tagged Poseidon2 over KoalaBear |
| Work, headers and ciphertext digest | BLAKE3 |
| Output key encapsulation | ML-KEM-768, libcrux |
| Output encryption | ChaCha20-Poly1305; commitment as associated data |
| Fund signatures | ML-DSA-65, libcrux |
| Leaf proofs | Plonky3 hiding FRI |
| Aggregation | Plonky3-recursion with pinned keys |
| Keystore | Argon2id and XChaCha20-Poly1305 |

Plonky3 is pinned to 0.9.0-rc.2 and recursion to revision `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. The degree-four proof suite uses log blowup 2, 42 queries and 16 grinding bits. Its nominal query/grinding score of 100 is not a complete classical bound and fails the selected launch requirements. There is no final SNARK wrapper.

## Statement binding

BLAKE3 derive-key context `siworld d_ct v1` hashes both ciphertexts followed by both view tags. The digest packs into 16 little-endian 16-bit limbs. E binds that digest, both nullifiers and both output commitments.

Recursion checks child verification keys and statement digests. Fee limbs are range-checked and added with checked carries. The root derives the miner note from private fees, public share, height, owner and randomness. Validators recompute every public input from block and prior state.

## Additive accumulator assumptions

The root equates the sum of proved E values with the sum from published slots. Multiset binding depends on cryptographic assumptions and bounded leaf multiplicity. Fixed tree depth, trusted child keys, count-one leaves, checked node counts and a capacity-specific root key are security-critical.

Without the multiplicity bound, 49 vectors in 48 dimensions admit a linear dependency. The regression `unbounded_multiplicities_break_the_sum` demonstrates that failure mode. Canonical encoding is also required: arbitrary reduction modulo the field would give multiple byte representations of one element. Decoders reject them. Native checks enforce duplicate-slot and nullifier rejection; addition alone cannot.

`crates/bench-stark/scripts/set_hash_security.py` evaluates generic attacks for its stated model. Estimates are not an independent audit or a security proof for the entire protocol.

## Public verification artifacts

`crates/prover/keys` contains public root verification artifacts for capacities 2 through 128. `crates/prover/tests/data` contains a public proof and statement fixture. These are not secret keys. Key generation is deterministic; proof hiding randomness must remain fresh. Miners compare rebuilt keys with pinned artifacts.

Ciphertext correctness is outside the relation. Note encryption does not establish full-system quantum security, and buffer zeroization does not establish full-memory erasure. See [the security model](security-model.md).

The legacy query/grinding score does not establish composite security. The
selected launch requirements and planned D8 suite are specified in the
[security review scope](../v2/proof-security-review.md); D4/W16 is not a qualifying
post-quantum suite.
