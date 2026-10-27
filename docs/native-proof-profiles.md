# Native Proof Profile Reproduction

Status: engineering freeze of three isolated native relations and their public
preprocessing identities. This is not cryptographic approval, a production
wallet, native block integration or network activation. The earlier transaction
measurement artifact remains unchanged.

## Fixed relation scope

| Relation | Fixed shape | FRI profile | Proof-body admission requirement |
| --- | --- | --- | ---: |
| Transaction | Two inputs, three outputs; per-asset balance and SI-only fees | Blowup 7, 41 queries | 655,360 bytes |
| Fee settlement | 576 ordered positions; reward asset is SI | Blowup 8, 36 queries | 524,288 bytes |
| Asset issuance | Three initial notes; fixed public supply | Blowup 8, 36 queries | 524,288 bytes |

All use KoalaBear D8, Poseidon2 W24, twelve-element digests, query and opening-
batch grinding of 20 bits, zero commitment grinding, binary folding and final
polynomial log length zero. The issuance shape does not adopt a protocol limit
of three notes: metadata, note-count and per-block issuance policy still require
explicit decisions before integration. Other settlement capacities require their
own preprocessing identities; this manifest freezes the maximum-capacity shape.

The [relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
records deterministic public preprocessing keys, actual-AIR security reports,
parameters and fixed capacities. It binds the unchanged
[transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json),
which already pins native source files, dependency identities and the measured
transaction selection. Each new key uses the offline `SWMP-v1` encoding:
`magic[4]`, little-endian version `u16`, relation kind `u8`, capacity `u32`, six
FRI parameter `u32` values, preprocessing width `u32`, degree bits `u32`,
commitment byte length `u32`, and the canonical dependency-encoded commitment.
Kind identifiers are transaction 1, settlement 2 and issuance 3. Capacity zero
identifies the fixed transaction shape. This encoding is an artifact identity;
it does not register a consensus envelope or permit peer-supplied keys.

The security reports pass the selected instance-specific accounting model.
External review must assess the implementation, hiding, application hashes and
protocol composition. Existing diagnostic measurements are not new full-block,
standalone-verifier or sustained-load qualification.

## Reproduce the public keys

Use the pinned Rust toolchain and Python 3.11 or newer. On Linux x86_64, the
repository release baseline requires AVX2 and operating-system AVX state support.
These commands prepare an isolated manifest with paths to unchanged native
sources; they do not modify the dependency checkout or generate transaction
proofs. Use a new local output directory for each reproduction:

```sh
python3 scripts/check-native-proof-profiles.py \
  --check crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json
python3 scripts/check-native-proof-profiles.py \
  --prepare .local/native-profiles/application
cargo build --release --locked \
  --manifest-path .local/native-profiles/application/Cargo.toml \
  --features security-report --bin native-proof-artifacts
mkdir -p .local/native-profiles/reproduced
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-profiles/application/target/release/native-proof-artifacts \
  transaction .local/native-profiles/reproduced/transaction.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-profiles/application/target/release/native-proof-artifacts \
  settlement .local/native-profiles/reproduced/settlement.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-profiles/application/target/release/native-proof-artifacts \
  issuance .local/native-profiles/reproduced/issuance.json
python3 scripts/check-native-proof-profiles.py \
  --check crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json \
  --reproduced .local/native-profiles/reproduced
```

Do not substitute downloaded or peer-provided keys. `--check` alone validates
the recorded manifest and source binding; `--reproduced` additionally compares
the regenerated keys and complete security reports. The transaction commitment
must also match the existing frozen transaction key. Public preprocessing is
performed serially to avoid unnecessary concurrent memory pressure.

## Generate and verify synthetic proofs

The isolated `native-scan` executable generates a fresh synthetic proof, verifies
it locally, and writes a technical result file. It does not export a reusable
proof package or provide a wallet/peer verification API. To exercise each fixed
profile deliberately, build the existing native crate and use separate new
output files:

```sh
cargo build --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml \
  --features security-report --bin native-scan
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan \
  transaction 7 41 20 4 .local/transaction-roundtrip.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan \
  settlement 8 36 20 4 .local/settlement-roundtrip.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan \
  issuance 8 36 20 4 .local/issuance-roundtrip.json
```

A successful result requires `verified: true`. The issuance diagnostic checks
ML-DSA-65 and the proof, but its SI issuance-fee callback is a synthetic fixture;
it does not consume an actual on-chain fee payment. Production issuance must
use `IssuanceProver::verify_signed` with authenticated network/policy context and
atomic exactly-once SI-payment consumption. Transactions require a verifier-
selected canonical snapshot and reconstructed public statement. Settlement
requires the ordered transaction/fee list, subsidy, height and network context
from the candidate block. The standalone diagnostics supply none of the durable
node state transitions, compact relay or wallet recovery required for launch.

## Ordering and integration boundary

The retained recursive node sorts legacy proof-free slot IDs and rejects any
non-strict adjacent pair, including duplicate IDs. Its old slot encoding is not
the new three-output transaction statement. Native V1 block ordering remains an
M1 integration requirement: compute the specified domain-separated BLAKE3
statement identity, excluding proof randomness, proof length and sidecar; sort
strictly; reject duplicate IDs and unsorted blocks before expensive proof work.
The shared producer/validator transition and node-level atomic rejection tests
must implement this rule. The isolated public codec does not implement a native
block validator, and public-key reproduction does not satisfy that milestone.
