# SIWORLD

[![CI](https://github.com/siworld-labs/siworld/actions/workflows/ci.yml/badge.svg)](https://github.com/siworld-labs/siworld/actions/workflows/ci.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)

A Rust implementation of a shielded payment protocol with fixed-capacity blocks, post-quantum note encryption, and recursive STARK aggregation.

**Research prototype.** The implementation is unaudited and has no production release or mainnet. The current proof configuration targets conjectured classical soundness; it does not establish complete post-quantum security. Use disposable test keys and valueless test assets only.

## Design

- **Uniform block structure.** Each block contains exactly N fixed-shape slots. Each slot has two nullifiers and two encrypted outputs; unused capacity is filled with valid zero-value padding.
- **Recursive verification.** Plonky3 leaf proofs are aggregated through a fixed-depth binary tree. An additive set-hash accumulator binds the root statement to the published slots without exposing individual fees or the fee total on chain.
- **Shared state transition.** Block construction and validation use the same deterministic, integer-only transition. Failed transitions leave state unchanged.
- **Encrypted notes.** ML-KEM-768 and ChaCha20-Poly1305 protect output plaintexts. Poseidon2 commitments and nullifiers support shielded ownership and double-spend rejection.
- **Explicit trust boundaries.** Network observers can see arrival times and fees, and producers recognize their own padding. Fixed-size blocks reduce particular activity signals; they do not guarantee payment-time or source anonymity.

## Implementation

| Component | Responsibility |
|---|---|
| `crates/core` | Canonical types, encodings, parameters and integer issuance |
| `crates/poseidon2` | Tagged hashing, field encoding and domain separation |
| `crates/crypto` | Note commitments, nullifiers, encryption and signatures |
| `crates/state` | Commitment tree, nullifier set, anchor window and reward accounts |
| `crates/circuits` | Native slot relation and proof-system interface |
| `crates/prover` | Plonky3 leaf proofs, recursive aggregation and pinned verification keys |
| `crates/consensus` | Atomic transitions, block production, difficulty and fork choice |
| `crates/storage` | Persistent full-block storage and replay |
| `crates/node` | Peer transport, authenticated local RPC, wallet and recovery controls |
| `crates/bench-stark` | Separate proof-system benchmark workspace; its Plonky3 circuits are also dependencies of the prover |

## Build

Rust is pinned in [rust-toolchain.toml](rust-toolchain.toml). Default node binaries enable Plonky3 and reject mock-proof networks.

```sh
cargo build --release --locked -p siworld-node
python3 scripts/check-node-features.py
```

For a deterministic single-machine demonstration, explicitly enable development capabilities:

```sh
cargo run --locked -p siworld-node --no-default-features \
  --features development --bin siworld-devnet -- demo
```

Development builds use forgeable mock proofs. They are test tools, not deployment artifacts.

## Verification

```sh
python3 scripts/check-repository.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo test --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 -p siworld-bench-common
```

The all-features build is for verification and includes development capabilities. See [test coverage](docs/testing.md) and [contribution requirements](CONTRIBUTING.md).

## Documentation

| Document | Scope |
|---|---|
| [Technical overview](docs/whitepaper.md) | Protocol construction and implementation boundaries |
| [Architecture](docs/architecture.md) | Components, data flow and candidate lifecycle |
| [Protocol](docs/protocol.md) | Notes, block rules, units, rewards and parameters |
| [Cryptography](docs/cryptography.md) | Primitives, statement binding and accumulator assumptions |
| [Security model](docs/security-model.md) | Adversaries, privacy limits and deployment restrictions |
| [Node operations](docs/node-operations.md) | Implemented builds, legacy node setup and wallet access |
| [Native V1 acceptance](docs/prover-acceptance.md) | Proof, resource, privacy and independent-network qualification gates |
| [V1 deployment](docs/v1-deployment.md) | Candidate hardware, storage accounting and private live monitoring |
| [RPC and recovery](docs/rpc.md) | Capabilities, key custody and durable submission |
| [Benchmarks](docs/benchmarks.md) | Reproducible commands and measurement requirements |
| [Testing](docs/testing.md) | Regression coverage and validation commands |
| [Development](docs/development.md) | Engineering invariants and release criteria |

## License

[GPL-3.0-only](LICENSE). Module-level references to the GPL-licensed [midstate](https://github.com/ciphernom/midstate) project are documented in [NOTICE](NOTICE).
