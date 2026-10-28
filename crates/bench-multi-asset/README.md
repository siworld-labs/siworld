> Economic rewards and selected-snapshot lock constraints are being revised.
> Existing artifacts describe the prior measured relation. New actual-AIR
> security extraction, hosted measurements and source-bound keys are required.

# Native Multi-Asset Proofs and Engineering Profile

Status: executable native relations and measurement tools, used by the native
engineering node. The [prior profile](artifacts/v1-transaction-profile.json)
records the earlier transaction relation, parameter choice and public verifier
key. Its measurements do not qualify the revised lock-height and economic
reward relations. The earlier two-output `bench-d8` implementation also remains
baseline evidence. Updated source-bound keys, actual-AIR security reports,
performance measurements and independent cryptographic review are required
before activating the revised relations.

The suite is KoalaBear D8, standard Poseidon2 W24, twelve-element digests and
hiding FRI, using pinned Plonky3 dependencies and `p3-security` 0.9.0-rc.2.
The fixed transaction relation has two inputs, three outputs, sixteen u16
asset-ID limbs, per-asset integer conservation and SIP-only confidential fees.
A depth-twelve path proves membership in the accepted recent-root tree. The
codec binds all three ciphertexts and the verifier-selected snapshot context.
The native issuance relation proves exact fixed supply and note commitments;
native ML-DSA-65 verification authenticates the declaration. The settlement
relation constrains the miner reward asset to SIP inside the AIR.

The issuance-fee payment gate requires an independently verified SIP payment;
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
  crates/bench-multi-asset/target/release/native-scan transaction 7 41 20 4 result.json
```

This example uses the prior transaction parameter coordinate; it is not a
qualification of the revised relation. The executable measures real setup, native generation and verification separately.
It encrypts and locally checks actual transaction outputs; issuance also checks
a real ML-DSA-65 signature. Use a separate one-worker process for single-worker
verification. Process peak memory includes setup, proving and verification;
it is not an independent verifier-only memory measurement. Hosted cgroup
measurements and the full parameter scan are defined by the dedicated workflow.

The required transaction scan covers blowup 5–8 and grinding 20/24, with three
four-worker trials per configuration on a qualified EPYC 7763 four-vCPU VM.
All three generation times must be at most two seconds. The selected passing
configuration minimizes the maximum observed proof body. Its admission cap
adds at least 10% to that maximum and rounds up to 64 KiB; it is an engineering
admission policy, not a mathematical proof-size bound. The frozen JSON records
all eight profiles, all 24 measurements, source/dependency identities,
actual-instance security reports, public verifier key and cgroup memory peaks.
The prior relation used `log_blowup=7`, 41 queries and 20-bit query/batch
grinding, with zero commitment grinding, binary folding and final-polynomial
log length zero. Three EPYC 7763 generation times were 1.332143, 1.315662 and
1.316440 seconds; proof bodies were 583,552–584,848 bytes. The maximum combined
process-tree cgroup peak was 531,668,992 bytes, with zero memory-event deltas.
The source-bound artifact records the exact security report; its quantum
Johnson union is approximately 81.692 bits. The cap is 655,360 bytes (640 KiB),
12.06% above the largest measured proof. Five GiB remains a diagnostic process
boundary rather than a miner RAM minimum.

Settlement and issuance caps remain 524,288 bytes each. Block capacity remains
576. Minimum uplink is recalculated from the transaction cap, three relay
copies and complete bounded network overhead with at least 15% unused link
capacity: 43 Mbps minimum; deployment recommendation remains 100 Mbps. Synthetic keys and
fixture data in this crate have no network use.

Regenerate public preprocessing for comparison with the prior profile:

```sh
cargo run --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml \
  --features security-report --bin profile-artifacts -- 7 41 20 verifier.json
python3 scripts/freeze-multi-asset.py \
  --check crates/bench-multi-asset/artifacts/v1-transaction-profile.json \
  --verifier-key verifier.json
```

The parameter arguments must match the artifact's `parameters` fields.
The prior artifact is expected to reject changed AIR/source identities; do not
replace its hashes to conceal the change or describe it as a current freeze.
The Rust tool only prepares public preprocessing and security data;
it does not run a transaction-generation benchmark.

## Admission integration boundary

Raw issuance `verify` checks only the AIR; admission must use `verify_signed`
and independently consume the bound SIP issuance-fee payment. Registry updates,
note insertion and that payment must commit in one durable state transaction;
the isolated registry is an in-memory rejection model. Transaction admission
must require a bound, current canonical snapshot and reconstruct its accepted
root rather than accepting fixture contexts or peer-supplied roots. Settlement
admission must reconstruct the ordered fee commitments, subsidy, height,
network and transaction-list identity from the validated block. These gates
are not supplied by the standalone benchmark entry points.
