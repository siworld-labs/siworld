# Commitment Collision Security Accounting

Status: selected screening model. These calculations specify report units and
ideal generic attack costs. They are not a security proof for Poseidon2, a
quantum Fiat–Shamir theorem, or approval of a production proof configuration.

## Digest size and classical report input

The transaction suite uses KoalaBear `p = 2130706433`, extension degree 8,
Poseidon2 width 24, rate 12 and a 12-base-field-element digest. The sponge
capacity is 12 base-field elements. The ideal digest-space exponent is

```text
n = 12 * log2(p) = 371.8642162493911 bits
classical generic collision exponent = n / 2 = 185.9321081246956 bits
ideal generic BHT collision exponent = n / 3 = 123.9547387497970 bits
```

The digest is encoded in 48 bytes, but its elements have fewer than 32 bits of
entropy each. Treating the encoding as 384 independent bits overstates this
calculation. Digest width and capacity are both inputs to the ideal model;
neither alone establishes the security of the instantiated construction.

The caller conservatively sets `InstanceShape::collision_resistance = 185`.
In pinned `p3-security = 0.9.0-rc.2`, this field is a **classical collision
exponent**, not a digest length. `src/stark.rs::regime_report` copies the value
unchanged into the `commitment-collision` term in the conjectured and Johnson
reports. The package does not derive this input from Poseidon2 parameters and
does not perform a quantum collision conversion.

## Selected quantum collision model

For an ideal hash with `n` output/capacity entropy bits, classical birthday
collision search has cost approximately `2^(n/2)`. Generic quantum BHT
collision search has query cost approximately `2^(n/3)`, under its quantum
oracle and lookup/memory assumptions. Consequently, converting a classical
collision exponent `c = n/2` to this model uses `2*c/3`:

| Report quantity | Calculation | Bits |
| --- | --- | ---: |
| Raw pinned `p3-security` commitment term | caller's classical floor | 185 |
| Selected BHT commitment ledger | `2 * 185 / 3` | 123.3333333333333 |
| Uniform halving diagnostic | `185 / 2` | 92.5 |

The 92.5-bit value applies a generic square-root speedup to an exponent that
already includes the classical birthday square root. In terms of digest
entropy, it is `n/4`, not the BHT `n/3` exponent. It may be retained as a
separately labeled stricter diagnostic. It must not be labeled BHT or used to
claim that W24/digest12 inherently fails a 100-bit BHT screen.

The reproducible report retains the raw 185-bit term and separately reports
123.3333333333333 bits as the selected ideal BHT ledger. It does not replace
the raw term, halve it again, or present the ledger as an upstream
`p3-security` quantum guarantee. The conversion is implemented by
`crates/bench-d8/src/bin/v1_transaction_scan.rs` and independently checked by
`scripts/scan-v1-transaction.py`. The boundary test in
`scripts/tests/test_v1_transaction_scan.py` verifies that a 120-bit classical
collision floor meets exactly an 80-bit BHT screen and that a smaller floor
fails that screen, without changing the raw classical units.

## Scope and limiting terms

The Fiat–Shamir challenge ledger is separate. Every Johnson challenge term,
including the applicable query and enforced grinding contribution, is halved
under the selected quantum screening rule. Folding multiplicity is charged
after halving. The current transaction target requires at least 80 bits for
each applicable term, each challenge-domain term and the combined challenge
ledger; classical conjectured security must remain at least 128 bits.

The ciphertext-byte binding additionally uses BLAKE3-256 outside the AIR.
Its nominal classical collision exponent is 128 and its ideal BHT exponent
is `256/3 = 85.3333333333333` bits. This application binding is excluded from
the raw PCS report. A 123.3-bit PCS commitment ledger therefore must not be
reported as the collision strength of the complete transaction relation.
The nominal minimum of these two hash ledgers is 85.3 bits; it is not an
independently established compositional lower bound.

The current diagnostic transaction profile has an approximately 81.9-bit
quantum-halved Johnson challenge union, below both nominal hash ledgers.
Actual AIR dimensions, transcript order, all enforced grinding sites,
multi-target losses, capacity/permutation analysis, application bindings,
zero knowledge and full protocol composition require review against frozen
sources and artifacts. A report passing this screen does not complete those
reviews or resource acceptance.

## Primary implementation references

- `p3-security 0.9.0-rc.2`, `src/shape.rs::InstanceShape`: defines the units of
  `collision_resistance`.
- `p3-security 0.9.0-rc.2`, `src/stark.rs::regime_report`: emits the raw
  `commitment-collision` term.
- `crates/bench-d8/src/common.rs`: width, rate, digest and application
  permutation geometry.
- `crates/bench-stark/patches/recursion-d8-w24.patch`: D8 W24 random-codeword
  suite registration with width 24, rate 12 and digest 12.
- `crates/bench-d8/src/bin/v1_transaction_scan.rs::security` and
  `scripts/scan-v1-transaction.py::summarize_security`: classical reports,
  separate selected BHT conversion and application-binding scope.
