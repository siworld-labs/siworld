# Confidential Fee Settlement Evaluation

Status: evaluation gate. Scheme B is the selected Route A V1 candidate for
measurement. It is not an activated consensus rule and it is not included in
the V1 production scope until the native settlement relation, measurements,
and review gates below pass.

## Fixed requirements

Each transaction publishes one fee commitment in its proof statement. The
commitment is a twelve-element KoalaBear digest encoded as twelve canonical
little-endian `u32` values, so it adds **48 public statement bytes per
transaction**. The existing 1,742-byte transaction body is unchanged; when
the commitment is retained in the per-transaction statement this is 1,790
bytes before proof, relay, and settlement overhead. The commitment, proof
envelope, and any private-relay sidecar must be counted separately in capacity
and denial-of-service budgets.

The private opening contains the fee, tier/dummy flags, and a 256-bit
blinding value. A verified mempool entry retains that opening for miner
ordering and settlement. The fixed-size sidecar carries the transaction
binding and opening; it has no standalone signature or second encryption
layer. Nodes recompute the public commitment and transaction binding before
forwarding or retaining it. Sidecar transport confidentiality and peer
authentication come from the planned X25519 + ML-KEM connection handshake.
Missing sidecars, mismatched openings, and sidecars bound to another
transaction are discarded before state mutation and recorded in bounded
peer-abuse diagnostics. The opening is never written to a block or exposed as
a public block field.

The block relation is a native, non-recursive STARK. For every fixed position
it checks the commitment opening, accepts only zero for a padding position and
the anchor's standard or priority amount for a real position, and adds the
fees with checked integer carries. It binds the resulting private sum to the
miner reward note. The proof binds the ordered compact references and the
capacity, so an omitted, duplicated, or reordered transaction cannot be
settled by reusing a valid proof.

Settlement proofs and their private fee-opening sidecars are retained for four
weeks after final confirmation, then deleted from the online store. The public
fee commitments remain permanently with the confirmed transaction; fee
openings are never part of the permanent record. Archive and checkpoint
operators may retain proofs longer when they need independent replay evidence.

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

## Current result

The repository contains the transaction fee-commitment relation, a native
reference design, and an evaluation fixed-capacity settlement AIR/prover in
`crates/bench-d8/src/fee_settlement_air.rs`. The AIR uses one W24 Poseidon2
fee-commitment row per slot, four 16-bit fee limbs with range checks, checked
tier carries, and a checked running sum bound to the miner amount. It is a
research implementation and does not activate Scheme B on the node or
consensus path.

The three-trial harness is `fee-settlement-bench`. Run it inside the qualified
independent cgroup with the patched D8 dependency:

```
cargo run --release --features parallel --bin fee-settlement-bench -- \
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
therefore exceeds the 431,029-byte transaction-proof screening threshold; the
settlement proof has a separate capacity budget and is not substituted for the
transaction proof limit. The benchmark now resolves the process's cgroup v2
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
evaluation. The available diagnostic host is macOS and reports no delegated
cgroup, so it cannot supply the required three `memory.peak` and
`memory.events` samples for either the transaction proof or the 576-position
settlement proof. Existing D4 measurements and generic CI runners are not
substitutes for that baseline.
