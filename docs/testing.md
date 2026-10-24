# Validation and Regression Coverage

## Required checks

```sh
python3 scripts/check-repository.py
python3 scripts/check-node-features.py
cargo fmt --all --check
cargo fmt --manifest-path crates/bench-stark/Cargo.toml --all --check
cargo check --locked -p siworld-node --bins
cargo test --locked -p siworld-node --bin siworld-node
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo test --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 -p siworld-bench-common
```

All-features tests intentionally enable development helpers. Release artifacts use default features. The feature check excludes deterministic crypto and state test helpers from the default normal/build graph.

## Coverage

| Area | Location |
|---|---|
| Every-input validation, nullifiers and atomic rollback | `crates/consensus/tests/counterexamples.rs` |
| Canonical encodings | `crates/consensus/tests/encoding.rs` |
| Producer/validator agreement | `producer_seed.rs`, `state_delta.rs` in consensus tests |
| Statement binding and miner notes | `container_statement.rs`, `miner_package.rs`, `crates/prover/tests` |
| Integer issuance and fund accounting | `issuance.rs`, `payouts.rs` in consensus tests |
| Difficulty and fork choice | `pow.rs`, `fork_choice.rs`, `main_chain.rs` in consensus tests |
| Native/circuit equivalence | `crates/poseidon2`, `crates/bench-stark/common`, `crates/bench-stark/plonky3` |
| Peers, payments and RPC | `crates/node/tests/network.rs`, `payments.rs`, `rpc.rs` |
| Custody and durable recovery | `keystore.rs`, `backup.rs`, `orders.rs`, `retention.rs` in node tests |
| Fund approvals, budgets and recovery | `fund_security.rs`, `fund_payments.rs`, `fund_backup.rs` in node tests |

## Counterexamples

Preserve regressions for invalid later inputs, repeated nullifiers and authorization reuse where applicable, malformed encodings, incorrect roots/rewards and partial mutation after failure. Write the failing consensus test before implementation.

Proof changes require valid and tampered witnesses, native/circuit consistency, root-input mutations, overflow rejection and key compatibility checks. Regenerating a key does not authorize silently replacing a pinned key.

Tests establish behavior only for their configurations and fixtures. They do not establish cryptographic soundness, anonymity or production readiness. Performance claims need the [benchmark procedure](benchmarks.md).
