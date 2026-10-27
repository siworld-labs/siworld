# Native Multi-Asset Proof Evaluation

Status: isolated executable relations and measurement tools. No node depends on
this crate. The earlier single-asset engineering freeze remains unchanged;
these new relations, domains, preprocessing and verifier keys require a new
review and acceptance process before activation.

The suite is KoalaBear D8, standard Poseidon2 W24, twelve-element digests and
hiding FRI, using pinned Plonky3 dependencies and `p3-security` 0.9.0-rc.2.
The fixed transaction relation has two inputs, three outputs, sixteen u16
asset-ID limbs, per-asset integer conservation and SI-only confidential fees.
A depth-twelve path proves membership in the accepted recent-root tree. The
codec binds all three ciphertexts and the verifier-selected snapshot context.
The native issuance relation proves exact fixed supply and note commitments;
native ML-DSA-65 verification authenticates the declaration. The settlement
relation constrains the miner reward asset to SI inside the AIR.

The issuance-fee payment gate requires an independently verified SI payment;
the benchmark fixture callback is synthetic and does not implement node
admission. Issuance byte/work limits, activation parameters, wallet/node
integration and independent cryptographic review remain outstanding.

## Reproducible validation

From the repository root:

```sh
cargo test --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --lib
cargo clippy --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --all-targets -- -D warnings
cargo build --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --bin native-scan
```

`native-scan screen` emits instance-specific reports for every requested
blowup/grinding combination, plus a separately identified larger-blowup
fallback. Reports contain all error terms, actual symbolic dimensions, the
quantum Johnson ledger and an explicit lack of cryptographic approval.
`FriParams::fast()` is used only by rejection and roundtrip tests; it is never
accepted by the measurement executable's security screen.

A direct measurement takes a proof kind, log blowup, query count, grinding
bits, worker count and a new output file. For example:

```sh
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan transaction 8 36 20 4 result.json
```

This example is a diagnostic profile, not a parameter recommendation. The
executable measures real setup, native generation and verification separately.
It encrypts and locally checks actual transaction outputs; issuance also checks
a real ML-DSA-65 signature. Use a separate one-worker process for single-worker
verification. Process peak memory includes setup, proving and verification;
it is not an independent verifier-only memory measurement. Hosted cgroup
measurements and the full parameter scan are defined by the dedicated workflow.

The 512-KiB proof cap, 576-position block limit, 30-Mbps minimum uplink and
security target are unchanged by a diagnostic result. A profile exceeding any
selected resource target is recorded as rejected rather than weakening that
target. Synthetic keys and fixture data in this crate have no network use.

## Admission integration boundary

Raw issuance `verify` checks only the AIR; admission must use `verify_signed`
and independently consume the bound SI issuance-fee payment. Registry updates,
note insertion and that payment must commit in one durable state transaction;
the isolated registry is an in-memory rejection model. Transaction admission
must require a bound, current canonical snapshot and reconstruct its accepted
root rather than accepting fixture contexts or peer-supplied roots. Settlement
admission must reconstruct the ordered fee commitments, subsidy, height,
network and transaction-list identity from the validated block. These gates
are not supplied by the standalone benchmark entry points.
