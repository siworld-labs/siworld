# Multi-asset transaction AIR layout optimization

The [monetary revision](v1-economics.md) reopens affected proof qualification.
Earlier source-bound reports, keys and numeric profiles are baseline evidence
only; revised lock/reward relations require new actual-AIR screening and
resource measurements. Separate optimization work does not waive this gate.

Status: isolated structural prototype. The production parameter scan and its
source remain independent. No smaller proof, lower peak memory or faster
proving time is established by this prototype. It does not implement an AIR,
produce a proof or change network acceptance.

## Reference instance

The native two-input/three-output relation currently has 256 base rows,
1,420 main columns and 243 preprocessed columns. The hiding construction
increases the committed domain as specified by its fixed FRI configuration;
256 is the padded base-relation height, not the committed domain size.

| Main column group | Columns | Use |
| --- | ---: | --- |
| Slot Poseidon2 lane | 239 | One W24 permutation per row |
| Slot direction, range value and range bits | 18 | One direction, one u16 value and 16 bits |
| Slot row-constant registers | 810 | Notes, exact asset matches, balances, public-slot values and accumulator data |
| Private accumulator statement | 97 | 72 set elements, 12 fee-commitment elements, count and 12 anchor-entry elements |
| Recent-root Poseidon2 lane | 239 | Twelve useful path permutations; remaining rows have no path binding |
| Recent-root direction and anchor-height bits | 17 | Direction and 16 row-constant low height bits |
| Total | 1,420 | |

The 810 slot registers comprise 146 input-note columns, 204 output-note
columns, 23 fee columns, 12 nullifier-inequality columns, 255 asset-match
columns, 27 asset-carry columns, three output-asset admission inverses,
84 slot-public-value registers and 56 accumulator registers.

The 243 preprocessed columns comprise 7 fixed slot role fields, 38 absorb
selectors, 18 output selectors, 168 range selectors and 12 recent-root
selectors. The slot has 132 useful hash rows. Range checks occupy rows 0
through 167. The trace has enough unused rows to schedule the 12 recent-root
permutations at rows 168 through 179 without increasing base height.

## First implementation candidate

The unreferenced [layout prototype](../crates/bench-multi-asset/src/experiments/transaction_layout.rs)
constructs a coordinate mapping and relocates synthetic trace cells. It is
absent from the crate module graph and scanner. Its structural tests cover
path relocation, non-overlap, retained-column uniqueness, exact identifier
comparison aliases and every possible low anchor-height limb.

1. Reuse the slot Poseidon2 lane for the recent-root path at rows 168–179.
   Preserve every slot sponge and note-membership permutation and bind the
   new path's first node to the private anchor entry. Bind its last output to
   the public recent-root root. Remove the second 239-column lane.
2. Reuse the slot direction and range-check cells on these rows. Set the range
   value to the low anchor-height limb at path level zero. At later path rows,
   constrain `previous_index = 2 * current_index + previous_direction` and
   constrain direction to range bit zero. Existing u16 decomposition prevents
   a field-valued quotient from replacing an integer quotient. This removes
   the separate direction and 16 height-bit columns.
3. Delete the nine unused legacy fee-carry columns. Current per-asset carries
   and fee-tier carries have separate live locations; they remain unchanged.
4. Keep one exact asset-comparison cell for each unordered pair. The two
   input self-comparisons are constants equal to one. Reuse the input-0 versus
   input-1 equality flag for its reverse comparison; do not reinterpret the
   signed inverse certificate as the reverse certificate. Retain one
   canonical exact-comparison constraint/certificate. Fifteen cells of 17
   columns reduce to twelve cells, saving 51 columns. All sixteen canonical
   u16 limbs continue to participate; no compressed identifier is introduced.

The resulting structural target is **1,104 main columns**, a reduction of
316 columns (22.25%), with the same 256-row base height and, initially, the
same 243 preprocessed columns. This is a layout count, not a measured AIR
instance. The new AIR must independently confirm maximum degree, quotient
chunks, hiding height and exact security terms.

The prototype retains all 97 private statement registers. A later direct
native evaluator could read the 85 already-public set/fee/count values
without copying them into main registers, leaving only the private 12-element
anchor entry. That would target a further 85-column reduction. It requires
removing the generic embedded-leaf statement adapter and has not been
implemented by this prototype.

## Opening-size accounting

For the pinned non-human-readable base-field serialization, one field
element is four bytes. The reference main plus preprocessed row contains
1,663 elements (6,652 bytes); the first candidate contains 1,347 elements
(5,388 bytes). Holding the PCS query shape fixed, removing 316 main columns
removes **1,264 bytes from a queried main row**. It also removes D8
out-of-domain claims: 316 columns at 32 bytes per extension value, for each
opened point. Two main opening points would remove 20,224 claim bytes.

These terms do not include Merkle authentication paths, FRI round openings,
quotient/random matrices, hiding salt, length prefixes or possible changes
in the selected query count. They therefore are not an upper bound or a
measured total proof saving. Changes to constraint degree or hiding geometry
could offset the saving. Compare actual serialized proofs after the full
candidate AIR passes the same security screen.

## Soundness and validation requirements

- Use one Poseidon2 constraint evaluation on the shared lane. Activate the
  correct sponge/Merkle transition selectors on the relocated path rows and
  preserve the reference fixed hash domains and statement.
- Reject a wrong initial anchor entry, root, direction, path sibling,
  low-height limb, shift quotient, or transition across a path/padding boundary.
  Exercise both a valid path and a path whose membership would succeed under
  a different anchor position.
- Run the existing per-field mutation and counterexample tests unchanged.
  In particular, retain per-asset integer conservation, final zero carries,
  SIP-only fees, unique nullifiers and canonical asset limbs.
- Differentially check reference and candidate public statements and native
  witness validity, including duplicate input assets, SIP inputs, zero-valued
  outputs and all single-limb asset differences. Proof/verifier artifacts
  change and require their own identifiers and hashes.
- Extract the actual symbolic instance and repeat the pinned `p3-security`
  report. No candidate may reduce the quantum-halved Johnson or challenge
  domain target below 80 bits or classical conjectured target below 128 bits.
- Measure all stages and process-tree peak memory on the same four-vCPU
  baseline, with three repeats and the same runtime settings. Parameter
  freeze does not wait for this optimization. Adopt a later smaller envelope
  or lower bandwidth requirement only after measured validation.
