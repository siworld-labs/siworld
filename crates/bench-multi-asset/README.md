# Native Multi-Asset Proofs and Engineering Profile

Status: native proof parameters engineering-frozen for relation revision
`native-v1-economics-1`. The [transaction profile](artifacts/v1-transaction-profile.json)
and [three-relation manifest](artifacts/v1-native-proof-profiles.json) bind
snapshot-height input locks, revised economic reward relations, selected
parameters, public keys and actual-AIR reports to hosted measurements. The
native engineering node uses these relations. Release validation, complete
wallet/node/network integration and independent cryptographic review remain
separate gates. The earlier two-output `bench-d8` implementation remains
baseline evidence and does not qualify this relation.

The suite is KoalaBear D8, standard Poseidon2 W24, twelve-element digests and
hiding FRI, using pinned Plonky3 dependencies and `p3-security` 0.9.0-rc.2.
The fixed transaction relation has two inputs, three outputs, sixteen u16
asset-ID limbs, per-asset integer conservation and SIP-only confidential fees.
A depth-twelve path proves membership in the accepted recent-root tree. The
codec binds all three ciphertexts and the verifier-selected snapshot context.
The native issuance relation proves exact fixed supply and note commitments;
native ML-DSA-65 verification authenticates the declaration. The settlement
relation constrains the miner reward asset to SIP and checks the selected
Voyager/Holder reward-note layout inside the AIR. Each nonzero transaction
input must have an unlock height no greater than the trusted snapshot height.

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

This example uses the selected current transaction parameter coordinate.
The executable measures real setup, native generation and verification separately.
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
admission policy, not a mathematical proof-size bound. The schema-two JSON
records all eight grid profiles and 24 grid trials,
three selected one-worker transaction trials and 12 settlement/issuance trials
split across one/four-worker processes: 39 trials in total. It binds source and
dependency identities, actual-instance security reports, public verifier keys
and cgroup memory peaks.

The selected transaction uses `log_blowup=7`, 41 queries and 20-bit query/batch
grinding, with zero commitment grinding, binary folding and final-polynomial
log length zero. Its AIR has 256 base rows, 1,392 main columns, 247 preprocessed
columns, 101 public values and 2,898 degree-at-most-three constraints. Three
EPYC 7763 four-worker generation times were 1.531155438, 1.429902190 and
1.462877730 seconds; the median was 1.462877730 seconds. Those proof bodies
were 581,392–585,808 bytes; the largest selected one-worker proof was 588,832
bytes. Median one-worker verification was 17.006900 ms. The maximum four-worker
combined process-tree cgroup peak was 525,234,176 bytes, with zero memory-event
deltas. The source-bound report records approximately 81.692 quantum Johnson
bits, 185 classical conjectured bits and 123.333 BHT commitment-collision bits.
The cap is 655,360 bytes (640 KiB), over 11% above the largest selected
one/four-worker proof. Five GiB remains a diagnostic process boundary rather
than a miner RAM minimum.

Settlement and issuance caps remain 524,288 bytes each. Block capacity remains
576. Minimum uplink is recalculated from the transaction cap, three relay
copies and complete bounded network overhead with at least 15% unused link
capacity: 43 Mbps minimum; deployment recommendation remains 100 Mbps. Synthetic keys and
fixture data in this crate have no network use.

Regenerate public preprocessing for comparison with the current profile:

```sh
cargo run --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml \
  --features security-report --bin profile-artifacts -- 7 41 20 verifier.json
python3 scripts/freeze-multi-asset.py \
  --check crates/bench-multi-asset/artifacts/v1-transaction-profile.json \
  --verifier-key verifier.json
```

The parameter arguments must match the artifact's `parameters` fields.
Source or AIR changes require a new actual-instance scan, measurements and
review; changing recorded hashes alone does not qualify them. The Rust tool
only prepares public preprocessing and security data; it does not run a
transaction-generation benchmark. Follow the [three-relation reproduction
procedure](../../docs/native-proof-profiles.md) to compare every fixed relation
and rebuild its tool after any profile change.

## Admission integration boundary

Raw issuance `verify` checks only the AIR; admission must use `verify_signed`
and independently consume the bound SIP issuance-fee payment. Registry updates,
note insertion and that payment must commit in one durable state transaction;
the isolated registry is an in-memory rejection model. Transaction admission
must require a bound, current canonical snapshot and reconstruct its accepted
root rather than accepting fixture contexts or peer-supplied roots. Settlement
admission must reconstruct the ordered fee commitments, height, network and
transaction-list identity from the validated block. Its reward plan must come
from the canonical parent state and shared consensus transition, including the
selected mode, subsidy/pool allocations and unlock heights. These gates
are not supplied by the standalone benchmark entry points.
