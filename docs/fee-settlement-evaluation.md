# Confidential Fee Settlement Evaluation

The measurements in this document predate the [monetary revision](v1-economics.md).
They are retained reproducible baseline evidence only. Input lock constraints,
mode-dependent reward notes and revised settlement context require fresh AIR
security reports, source-bound keys and performance/memory measurements.
No earlier sampled result qualifies the revised V1 relation.

Status: selected Route A V1 settlement design with an isolated native AIR and
measured proof implementation. It is not an activated consensus rule. Native
block integration, resource qualification and independent review remain gates.
The [source-bound manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
records the pre-revision fixed-576 settlement shape, parameters and
public preprocessing key; it does not qualify revised reward settlement. Smaller-capacity keys require separate identities.
The transaction profile and earlier diagnostic tables remain separate evidence.

## Fixed requirements

Each transaction publishes one fee commitment in its proof statement. The
commitment is a twelve-element KoalaBear digest encoded as twelve canonical
little-endian `u32` values, so it adds **48 public statement bytes per
transaction**. The native three-output body is 2,027 bytes. Adding the fee
commitment and 40-byte snapshot selector gives 2,115 permanent bytes per
position before proof, relay and block-level overhead. The earlier two-output
1,742-byte body is separate diagnostic evidence. The commitment, proof
envelope, and any private-relay sidecar must be counted separately in capacity
and denial-of-service budgets.

The private opening contains the fee and eight independently sampled canonical
KoalaBear blinding elements (32 encoded bytes, about 247.91 bits of entropy).
The fixed sidecar does not carry a tier or padding flag. A verified mempool entry retains
that opening for miner ordering and settlement. The fixed-size sidecar carries the transaction
binding and opening; it has no standalone signature or second encryption
layer. Nodes recompute the public commitment and transaction binding before
forwarding or retaining it. Sidecar transport confidentiality and peer
authentication come from the planned X25519 + ML-KEM connection handshake.
Missing sidecars, mismatched openings, and sidecars bound to another
transaction are discarded before state mutation and recorded in bounded
peer-abuse diagnostics. The opening is never written to a block or exposed as
a public block field.

The settlement relation is a native, non-recursive STARK. For every fixed
position it checks the commitment opening and adds fees with checked integer
carries. The transaction proof enforces the private anchor's fee schedule and
zero-fee padding rule; settlement must not impose the current fee schedule on
an older anchored transaction. It binds the resulting private sum to the
SIP miner reward note. The proof binds the ordered compact references and the
capacity, so an omitted, duplicated, or reordered transaction cannot be
settled by reusing a valid proof.

Transaction, settlement and native issuance proofs and private fee-opening
sidecars are retained for three elapsed days after final confirmation, then
deleted under durable finality/retention metadata. Public fee commitments and
proof-free settlement declarations remain permanent. V1 has no archive-node
role; checkpoint bootstrap has an explicit trust policy.

Zero-valued dummy inputs skip commitment-tree membership checks in the
transaction AIR. They still derive a fresh nullifier and remain subject to
the same uniqueness and fixed-shape checks as real inputs. A real transaction
with a zero fee and a dummy transaction with a nonzero fee are invalid.

## Required measurements

The settlement AIR must be instantiated at capacities 64, 128, 256, 384, 512,
and 576 positions. The 576-position result is the V1 upper-capacity gate.
Each capacity is measured three times on the qualified target host after
one-time circuit setup, key generation, and dependency loading have completed.
The report records the median and all three samples for:

* AIR rows, main columns, preprocessed columns, constraint count and maximum
  degree;
* native proof-generation and verification wall time;
* canonical proof bytes;
* peak charged memory for the prover process and children; and
* single-proof verification wall time and peak charged memory.

The measurement process must run in an independent cgroup and record
`memory.max`, `memory.swap.max`, `memory.peak`, and `memory.events`. No formal
proof-memory ceiling is selected by this evaluation; an initial diagnostic may
run to the qualified machine's available capacity. Any limit used for a sample
must be reported, and a limit breach or a proof-size limit breach must be
visible in the result rather than silently omitted. The report must retain the
exact suite, verifier key hash, compiler profile, worker count, capacity, and
input digest list used by each sample.

The repository validator prints the required private-bundle schema with
`python3 scripts/check-fee-settlement-evaluation.py --schema` and validates a
completed bundle without launching a prover. It requires all six capacities,
exactly three trials per capacity, and SHA-256 references for the AIR, key,
and executable artifacts.

The logical witness work before a concrete AIR is frozen is one fee-opening
hash, four 16-bit fee limbs, one tier flag, one dummy flag, and one checked
sum per position, followed by one miner-note commitment. These counts are
planning quantities only; they are not AIR row or proof-size measurements.

## Two-output diagnostic baseline

This section preserves measurements of the earlier two-output diagnostic
relation. The current three-output SIP-reward relation and its measured profile
are described in the [multi-asset evaluation](v1-multi-asset-evaluation.md).
These baseline samples do not replace source-bound current-profile evidence.

The baseline contains a transaction fee-commitment relation, a native
reference design, and a fixed-capacity settlement AIR/prover in
`crates/bench-d8/src/fee_settlement_air.rs`. The AIR uses one W24 Poseidon2
fee-commitment row per slot, four 16-bit fee limbs with range checks, checked
tier carries, and a checked running sum bound to the miner amount. It is a
research implementation and does not activate Scheme B on the node or
consensus path.

The three-trial harness is `fee-settlement-bench`. Run it inside the qualified
independent cgroup with the patched D8 dependency:

```
cargo run --release --locked --manifest-path crates/bench-d8/Cargo.toml \
  --features parallel --bin fee-settlement-bench -- \
  --output .local/fee-settlement-measurements.json
```

The default profile is the transaction-candidate diagnostic selected by the
80-bit transaction scan (`log_blowup=8`, `queries=36`, query grinding 20,
batch grinding 20, commit grinding 0, maximum log arity 1). It is an
experimental profile and is not cryptographic approval. The legacy recursive
planning profile can be selected only for comparison with
`--legacy-candidate`; `--fast` remains a non-secure smoke-test profile.

It covers capacities 64, 128, 256, 384, 512, and 576, excludes one-time setup
from timings, and records native generation, verification, proof bytes, and
cgroup/VmHWM observations. The resulting private bundle must pass
`scripts/check-fee-settlement-evaluation.py`; no generated bundle belongs in
the public repository. Existing transaction proof timings cannot be used as a
settlement measurement because they do not prove the private sum or bind the
miner reward note.

### Diagnostic transaction-candidate run

The following three-trial run used the default transaction-candidate profile on
the local macOS diagnostic host. Values are medians; proof bytes and timings
are native measurements after one-time setup. The host did not expose a
delegated Linux cgroup, so charged-memory values are unavailable and this run
does not satisfy the qualified-host acceptance gate. The process used ten
Rayon workers; a separate four-worker comparison is retained as private
diagnostic evidence and neither run is a qualified-host result.

| Capacity | AIR rows | Main / preprocessed columns | Constraints | Generation (ms) | Verification (ms) | Proof bytes | Charged-memory evidence |
|---:|---:|---:|---:|---:|---:|---:|:---|
| 64  | 128  | 329 / 67  | 1,107 | 321 | 7  | 267,425 | unavailable |
| 128 | 128  | 329 / 131 | 1,875 | 249 | 8  | 276,647 | unavailable |
| 256 | 256  | 329 / 259 | 3,411 | 631 | 9  | 326,931 | unavailable |
| 384 | 512  | 329 / 387 | 4,947 | 1,009 | 11 | 380,191 | unavailable |
| 512 | 512  | 329 / 515 | 6,483 | 927 | 12 | 411,903 | unavailable |
| 576 | 1,024| 329 / 579 | 7,251 | 2,142 | 22 | 456,315 | unavailable |

The individual samples were retained in the private measurement bundle. The
576-position proof was 448,059--459,627 bytes across the three trials and
is below the separate 524,288-byte settlement-proof maximum. Settlement
proofs have their own capacity budget; their size does not select or replace
the transaction proof limit. The benchmark now resolves the process's cgroup v2
membership from `/proc/self/cgroup` before reading `memory.max`,
`memory.swap.max`, `memory.peak`, and `memory.events`; a fallback to `VmHWM`
is labeled as non-cgroup diagnostic evidence.

The reference model and native AIR tests exercise the four required rejection
cases: a commitment sum different from the miner reward fee component, a
forged opening that does not recompute the published commitment, a padding
position with a nonzero fee, and a real position with a zero fee. Until
qualified-host memory measurements and the remaining review gates are
available, Scheme B remains a V1 evaluation candidate and must not be
described as production-ready or activated on the retained network.

No qualified EPYC 7763 Ubuntu 24.04 cgroup result is included in this
two-output baseline table. Current-profile measurements are recorded separately
in the [multi-asset evaluation](v1-multi-asset-evaluation.md). The macOS series above cannot supply Linux kernel charged-memory
evidence. The hosted native cgroup workflow provides a separate three-trial
process-tree diagnostic series on Ubuntu 24.04, with kernel `memory.peak`,
`memory.events`, exact limit readback and actual CPU identity retained in its
sanitized artifact. A fresh hosted allocation does not establish the EPYC 7763
reference baseline or isolated verifier-memory bounds. See
[the measurement procedure](linux-proof-measurement.md#hosted-native-diagnostics).
