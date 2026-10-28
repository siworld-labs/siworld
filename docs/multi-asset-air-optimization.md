# Multi-Asset Transaction AIR Layout Optimization

Status: the engineering-frozen `native-v1-economics-1` relation includes the
snapshot-range and exact asset-comparison reductions described below. Its
source-bound [profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
records actual-AIR reports and hosted measurements. A separate unreferenced
layout prototype remains research; its structural counts are not measured
production proof savings. Further relation changes require new keys, security
reports and measurements.

## Adopted relation

The two-input/three-output relation has **256 base rows, 1,392 main columns,
247 preprocessed columns and 101 public values**. Symbolic extraction gives
2,898 constraints, maximum degree three and eight quotient chunks. The hiding
construction increases the committed domain: the 256-row base relation is not
the 512-row committed trace.

| Main column group | Columns | Use |
| --- | ---: | --- |
| Slot Poseidon2 lane | 239 | One W24 permutation per row |
| Slot direction, range value and range bits | 18 | One direction, one u16 value and 16 bits |
| Slot row-constant registers | 778 | Notes, exact asset matches, balances, slot public values and accumulator data |
| Private accumulator statement | 101 | Set elements, fee commitment, count, anchor entry and snapshot-height binding |
| Recent-root Poseidon2 lane | 239 | Twelve path permutations in a separate lane |
| Recent-root direction and anchor-height bits | 17 | Direction and 16 row-constant low height bits |
| Total | 1,392 | |

The preprocessed trace has the previous 243 columns plus four trusted selectors
for snapshot-height limb checks. The original 168 range-check rows are
unchanged. The two Poseidon2 lanes remain separate; the recent-root path has
not been relocated into the slot lane.

### Canonical snapshot-height range cells

The snapshot height is represented by four canonical u16 limbs. The adopted
layout reuses the slot AIR's existing range-value and 16-bit decomposition
cells at rows 168–171, selected by four appended preprocessed columns. This
avoids dedicated snapshot bit columns while retaining private-to-public
snapshot binding and both nonzero inputs' full u64 unlock-height inequalities.
These range cells do not alias the separate recent-root Poseidon2 lane.

### Exact asset self-comparisons

Each of the two input asset IDs has a self-comparison whose equality flag must
be one. Its 16 inverse-certificate coefficients cannot affect that equality,
so the adopted layout omits those 32 unused main columns. The remaining 13
comparisons retain their exact checks over all 16 canonical u16 limbs of the
32-byte asset ID. No compressed asset identifier or probabilistic equality
test is introduced. Equality-flag mutation tests still cover all 15 flags,
including the two self-comparisons.

## Measured qualification

The current relation was screened with pinned `p3-security` 0.9.0-rc.2 across
log blowup 5–8 and grinding 20/24. The selected coordinate is log blowup seven,
41 queries, 20-bit query/batch grinding, zero commitment grinding, binary
folding and final-polynomial log length zero. Three four-worker EPYC 7763 VM
generation times were 1.531155438, 1.429902190 and 1.462877730 seconds. The
four-worker maximum process-tree peak was 525,234,176 bytes. The largest
selected one/four-worker serialized proof body was 588,832 bytes, below the
655,360-byte admission cap. See the [measurement scope](v1-multi-asset-evaluation.md)
and [reproduction procedure](native-proof-profiles.md).

These results qualify the recorded source instance under the selected
engineering model. They do not isolate each optimization's causal performance
effect, bound every randomized proof, establish independent verifier memory or
complete cryptographic review and whole-node acceptance.

## Separate structural prototype

The unreferenced [layout prototype](../crates/bench-multi-asset/src/experiments/transaction_layout.rs)
constructs coordinate mappings and relocates synthetic cells. It is absent
from the crate module graph and scanner. Its historical reference was a
pre-lock relation with 1,420 main columns, 243 preprocessed columns and 97
private statement registers. The prototype's 1,104-main-column target is a
structural count, not the current revised AIR. Its proposed changes are not
all adopted:

1. Reuse the slot Poseidon2 lane for the recent-root path at rows 168–179,
   removing the second 239-column lane. Preserve every slot sponge and
   note-membership permutation, bind the path's first node to the private
   anchor entry and its last output to the public recent-root root.
2. Reuse direction/range cells while constraining canonical integer path-index
   transitions, removing the separate direction and low-height bit columns.
   The revised snapshot checks now occupy range rows 168–171; a new combined
   schedule must explicitly resolve cell use and selector interaction.
3. Remove unused legacy fee-carry columns after confirming that per-asset and
   fee-tier carries remain live at their separate locations.
4. Alias symmetric exact asset comparisons only with a canonical certificate;
   an inverse certificate cannot simply be reused with its sign unchanged.
   The implemented self-comparison reduction above is narrower than this
   proposal.

The historical target saves 316 main columns (22.25%) relative to its own
1,420-column reference. At four serialized bytes per base-field element, that
is 1,264 bytes from a queried main row. It also removes D8 out-of-domain
claims at 32 bytes per extension element and opening point. These arithmetic
counts exclude authentication paths, FRI openings, quotient/random matrices,
hiding salt, length prefixes and query-count or degree changes. They establish
neither total proof size nor generation or memory savings.

A direct evaluator might later avoid copying already-public set/fee/count
values into private statement registers. That requires replacing the generic
embedded-leaf statement adapter while preserving private anchor and trusted
snapshot bindings. It is not implemented by the prototype.

## Requirements for further changes

- Preserve every fixed hash domain, exact asset limb check, per-asset integer
  balance, final zero carry, SIP-only fee and nullifier-uniqueness constraint.
- Reject wrong path entries, roots, directions, siblings, height limbs,
  shift quotients and transitions across active/padding boundaries. Retain
  both inputs' before/at-unlock tests, full-u64 boundaries and snapshot-binding
  mutation tests.
- Differentially compare public statements and witness validity for duplicate
  input assets, SIP inputs, zero outputs and single-limb asset differences.
  Recalculate all derived offsets and selectors; keys change with the AIR.
- Extract the actual symbolic instance and repeat the pinned security report.
  Quantum-halved Johnson and challenge-domain terms must remain at least
  80 bits, BHT commitment-collision terms at least 80 bits and classical
  conjectured terms at least 128 bits under the selected model.
- Repeat three-trial generation, verification and process-tree memory
  measurements on the qualified four-vCPU profile. Adopt a smaller envelope
  or lower bandwidth requirement only after measured qualification and review.
