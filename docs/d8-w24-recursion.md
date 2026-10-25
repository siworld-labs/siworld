# D8 W24 Recursive Suite Implementation Plan

Status: dependency assessment and proposed implementation sequence. The target
is KoalaBear D8, standard Plonky3 Poseidon2 W24 and 12-base-element digests.
The N=16 proof-latency target is 180 seconds under the unchanged 5-GiB
process-tree hard limit. This proving target does not change the consensus
block interval.
No working recursive suite or security approval is claimed. The baseline is
Plonky3 `0.9.0-rc.2` and recursion revision
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`.

## Verified gaps

Native D8 arithmetic and circuit execution work in prerequisite probes. The
suite registry has no D8/12-element entry. Existing W24 sponge mode works, but
binary Merkle geometry is rejected. Native Merkle sibling conversion falls
back to 12 lifted scalars, each with seven zero extension coefficients; the
matching recursive circuit and transcript must be implemented. The existing
D8/W32 prototype is reference material only, not the selected suite.

## Scalar geometry

A W24 permutation occupies three D8 state lanes. Its 12-element rate and
12-element capacity split through the middle lane. Binary compression must
bind all 24 base-field inputs and return exactly the designated 12 output
scalars. A one-lane digest would drop four elements; a two-lane digest would
silently change the format. Neither is permitted.

Add an explicit scalar-digest geometry and compression role instead of
bypassing existing checks. The permutation may produce all three D8 output
lanes; extract the first 12 scalar coefficients. Any internal repacking uses
separately constrained canonical zero padding. Do not constrain unused actual
permutation outputs to zero. Keep the external digest at 12 scalars throughout
MMCS proofs, caps, artifacts, serialization and transcripts. Native lifted
siblings and circuit coefficients must match exactly.

## Work packages and estimates

Estimates are engineering days for one developer familiar with the dependency,
including tests and review fixes within each package. They are planning ranges,
not completion promises; security findings can change them. Audit availability
is separate. The sequential subtotal is 17–31 engineering days, conditional on
the early performance checkpoint permitting further work.

| Package | Estimate | Deliverable and blocking tests |
| --- | ---: | --- |
| Scalar W24 geometry | 3–5 days | Typed geometry, coefficient extraction/recomposition, standard permutation tables, native/circuit binary compression; mutations of all 24 inputs, 12 digest limbs and eight extension coefficients, wrong padding and malformed geometry |
| Recursive suite and FRI | 3–5 days | D8 AIR/table/recomposition dispatch, registry/config codec, transcript observation/squeezing, cap/MMCS targets and canonical artifacts; native/circuit transcript equivalence, wrong suite/key/cap and noncanonical proof rejection |
| Opening-batch grinding | 2–4 days | Native nonce generation and recursive verification with identical transcript order; configuration/shape/key binding, serialization, positive-difficulty and zero-difficulty rejection tests; required before checkpoint |
| SI relation port | 4–7 days | Consistent leaf/anchor/note/nullifier/hash/codecs, eight-input and root circuits, reviewed additive-set/output layouts; run the early performance checkpoint after the first verified eight-input merge with opening-batch grinding and the final checkpoint configuration, before completing the root; independent native oracle, all public-field mutations and complete N=16 proof verification |
| Security screening and measurements | 2–4 days | Actual shape extraction, pinned conjectured and Johnson reports, composition/quantum screening, only passing profiles receive three full N=16 acceptance runs under 5 GiB |
| Production integration and freeze | 3–6 days | Shared transition/verification interfaces, worker/network binding, resource admission, isolated engineering-network fixtures, reproducible complete sources/artifacts/keys for audit |

Plan the first eight-input checkpoint for engineering day 13, with an estimated
window of days 10–18 from the start of implementation. This comprises 3–5 days
for scalar geometry, 3–5 for the recursive suite, 2–4 for opening-batch grinding,
and the first 2–4 days of the SI port for the leaf and eight-input relation.
The remaining 2–3 SI-port days cover the root and full rejection coverage.
Opening-batch grinding is on the critical path; it is not deferred until after
timing. Run the checkpoint immediately when the first merge verifies under the
final checkpoint configuration, even if earlier than day 10; do not wait for
the planned date. These are engineering-effort estimates, not calendar deadlines.
Dependency failures, CI findings and the checkpoint stop conditions can delay
or suspend progression.

Write failing tests for new validation behavior before implementing it. Keep
work in an isolated dependency experiment; do not modify frozen measurements
or the live N=2 deployment. Reuse W32 field-generic patterns only after reviewing
their applicability. Do not inherit W32 constants or digest assumptions.

## Application and transcript review

Inventory every W16/8-element hash use: proof commitments, challenge duplex,
leaf statement, additive set hash, anchor/note trees, miner/fund notes,
nullifiers, addresses, ciphertext plaintext codecs and block/state bindings.
A wider digest does not automatically port these interfaces. Preserve domain
separation and canonical encodings in native and circuit code.

The old 48-element set accumulator and 70-element root layout are D4 prototype
facts. Keeping six digest-width squeezes would suggest 72 set elements and a
102-element root, but this is a layout hypothesis requiring set-hash analysis,
not an adopted constant. Record the reviewed choice before implementation;
never silently truncate to preserve the old layout.

The two-worker hiding kernel must retain independent fresh randomness and the
same masking guarantees as serial execution. Pin every source delta in the
final review identity. Validate cancellation, errors and buffer lifetimes.

## Opening-batch grinding prerequisite

The pinned native `p3-fri` already implements this site: its PCS transcript
absorbs claimed evaluations in commitment, matrix and opening-point order,
generates the batch PoW witness, and only then samples the extension-field
batching challenge `alpha`. The native proof carries `batch_pow_witness`, and
native verification checks it before redrawing `alpha`. This is opening-batch
grinding, separate from per-fold commitment grinding and final query grinding;
work at one site cannot be credited at another.

The pinned recursive implementation deliberately supports only zero batch
PoW bits. `NativeFriParams` rejects nonzero difficulty, its PCS transcript seed
binds zero, target allocation and shape capture omit the batch witness, and
challenge extraction samples `alpha` without a batch PoW check. These are
identified implementation gaps, not evidence that the site is impossible.
Existing recursive commit/query PoW checks provide a pattern to reuse, subject
to D8/W24 transcript and scalar-geometry validation.

Complete the following before the first eight-input checkpoint:

1. Reuse native `PcsProverTranscript::batch_phase` for nonce generation at the
   configured difficulty. Preserve the native witness type, canonical encoding
   and failure behavior; do not add an unbound or off-transcript nonce search.
2. Carry the batch difficulty through checked native and recursive parameters,
   suite/config codecs, PCS domain-separator shape, prepared-shape identity and
   verifying-key/artifact identity. Validate field/word limits as for the other
   PoW sites. Allocate and constrain the witness in full and prepared recursive
   paths, including private-input and serialization layouts.
3. Match the exact pinned native transcript: bind the PCS seed and claimed
   evaluations, replay the batch witness check, sample `alpha`, then enter the
   separately seeded FRI low-degree transcript. Preserve existing commitment
   and query grinding positions. Compare native and circuit transcript states
   and challenges; never rely only on successful end-to-end proof verification.
4. Write rejection tests before implementation for changed validation behavior.
   Test missing, altered, insufficient-work and noncanonical witnesses; wrong
   difficulty, suite, seed, key and prepared shape; reordered or changed claims;
   a witness selected to fail after claim mutation; and a skipped or moved
   grinding step. A PoW nonce is not a one-time identifier: do not assert that
   every reused nonce necessarily fails the difficulty on a different transcript.
   Preserve canonical zero-witness behavior at zero difficulty without absorbing
   an extra transcript element. Exercise native, recursive and prepared/reused
   verifier paths with identical accepted and rejected fixtures.
5. Re-extract each affected circuit's table heights, main/preprocessed columns,
   constraint degree, quotient chunks, lookup dimensions and batched-opening
   count. Regenerate pinned `p3-security` reports from the actual configuration,
   retaining per-layer and 19-proof composition losses. Record the native search
   cost and recursive verification cost separately in phase measurements.

Freeze the checkpoint source/dependency revisions, W24 permutation and digest
layout, per-layer FRI/folding and all three grinding difficulties, transcript
codec, two-worker hiding patch, eight-input circuit artifact and verifying key
before the three measured trials. Freeze the binary and its build configuration
as well. The intended recursive candidates currently require 16 batch PoW bits;
that credit remains conditional until generation and every verification path
are implemented and tested. Reduced or zero-difficulty smoke configurations do
not establish the performance checkpoint. A later change to any frozen item
requires a new three-trial checkpoint before relying on its projection.

If implementation is shown to be infeasible, record the concrete failed
requirement and stop checkpoint progression. Re-screen aggregate and root
parameters with batch difficulty fixed to zero using the pinned `p3-security`
version and all unchanged security targets; query or commitment grinding cannot
replace missing batch credit by relabeling it. Broaden the search or reduce the
actual batched relation only with an explicit design. For every replacement
candidate report old/new table heights, column counts, degree, quotient chunks,
lookup dimensions and batched-opening count, then rebuild and measure that
configuration. The current planning-envelope zero-batch search does not meet
the quantum target; it does not prove that every alternative is impossible.
No passing replacement means pause and report rather than weaken the target.

## Early performance checkpoint

Immediately after the first D8/W24 eight-input merge produces a proof that
verifies with the opening-batch grinding prerequisite completed and checkpoint
configuration frozen, run this checkpoint before continuing root implementation
or production integration. Do not measure a configuration that still omits a
planned grinding site. Do not wait for completion of the full recursive suite.
This is an engineering feasibility measurement; it does not replace security
screening or the later complete N=16 acceptance trials.

Run three trials on the same qualified target machine, using one proof job
and two native workers per proof. Complete input-independent circuit/key
preparation before timing and keep it resident in the worker boundary. Record
cold startup separately. Fix the suite, intended eight-input relation,
parameters, input proofs and verifying key across all three trials; retain
fresh hiding randomness for each proof. Record hardware, compiler,
source/dependency revisions, configuration and artifact identities. Preliminary
parameters remain unapproved; reduced smoke parameters cannot establish this
checkpoint. Real and padding leaves must use identical parameters.

For each trial record eight-input proving wall time, separate startup and
standalone verification times, and complete process-tree charged-memory peaks,
including resident preparation. Start isolated merge timing with eight leaf
proofs available; include their generation in the N=16 projection. Verify every
resulting proof. Keep all three observations and report median proving time
and median memory peak, together with observed maxima. Enforce the 5-GiB
process-tree limit with zero extra swap, including during startup. An OOM,
incorrect proof or observed cap violation blocks progression and must not be
discarded as an outlier.

### N=16 latency and memory projection

Project the N=16 `16 -> 2 -> 1` schedule with one proof job and two native
workers, so the two eight-input merges execute serially. Apply the
[last-package-to-root timing boundary](prover-acceptance.md#timing-boundary-and-service-readiness),
including all sixteen leaf proofs in controlled trials:

```text
T_N16_est = T_leaf16 + 2 * median(T_merge8) + T_root_est + T_timed_overhead_est
```

Use D8 leaf timings under the same schedule and configuration. Timed overhead
includes only per-candidate admission, witness, queueing, handoff and output
work between final-package arrival and root completion. Exclude input-independent
startup preparation from latency, retain its memory, and record cold time
separately. PoW, propagation and standalone root verification have separate
timings. Do not double count stage costs or reuse D4 timings. Until a root
measurement exists, one additional median eight-input merge may serve as an
explicitly labeled provisional root-time proxy; it is not a measured root
time or a proven upper bound. Document the assumed root shape.

Project the simultaneous charged-memory peak, not a sum of independent stage
peaks or three times the isolated merge peak. One explicit accounting model is:

```text
M_ready_peak_est = M_resident_all + max(
    W_leaf16 + R_leaf,
    W_merge8 + R_merge,
    W_root_est + R_root,
    W_transition_est + R_transition)
M_N16_est = max(M_startup_peak_est, M_ready_peak_est)
```

`M_resident_all` includes every prepared leaf, aggregation and root circuit/key
and fixed service allocation. `W` is additional active workspace, and `R` is
other concurrently retained proofs, buffers and allocator/cache retention not
already charged to the resident baseline or workspace. Include sixteen leaf
proofs, retention of the first merge while the second runs, both children
while the root runs, and allocation overlap at handoffs. Measure the baseline
and incremental workspace consistently; an isolated peak already containing
the baseline must not have it added a second time. Use the three-trial medians
for the projection and retain observed maxima and uncertainty separately. A
maximum over the cap cannot be hidden by a passing median.

Estimate not-yet-built root residency and workspace from its explicit shape
and memory model; eight-input timing alone does not establish root memory.
`M_startup_peak_est` includes preparation of every circuit that must be resident
in the final service. List every measured and estimated term. Missing cost
or residency terms leave the projection incomplete and cannot establish a
passing checkpoint. Revise latency and memory with actual root measurements
when available; this estimate is not a worst-case memory proof.

### Continuation thresholds

Apply the decision to projected total N=16 proof latency and peak memory, not
to the isolated merge. For an actionable near-cap warning, use **4.5 GiB**, or
90% of the hard budget. The warning takes precedence over ordinary continuation;
the hard limit remains 5 GiB.

| Projected N=16 latency and peak memory | Required action |
| --- | --- |
| At most 90 seconds and below 4.5 GiB | Continue implementation. |
| More than 90 and at most 180 seconds with memory at most 5 GiB, or any latency at most 180 seconds with memory from 4.5 through 5 GiB | Continue and investigate leaf parameters and circuit optimizations in parallel, retaining all security requirements. |
| More than 180 seconds or more than 5 GiB | Pause progression and report the three observations, medians, maxima, projections and assumptions. Resume only after a decision on the target, hardware, optimization or N. |

An observed OOM or incorrect proof also blocks progression. The checkpoint
does not authorize a hardware or capacity change. N remains 16; N=32 is a
pending assessment after this checkpoint and is outside the current work.
Early timing headroom does not establish acceptance or justify weaker security.

## Acceptance sequence

First obtain a working D8 hiding leaf and recursive verifier with complete
limb/transcript rejection coverage and opening-batch grinding support. Freeze
the final checkpoint configuration, run the early performance checkpoint at the
first verified eight-input merge, and follow its continuation decision.
Then complete actual leaf, eight-input and root shapes, and screen leaf
profiles under all requirements in the
[review scope](proof-security-review.md), including 16/2/1
composition losses. A missing theorem or term cannot be treated as a pass.

Only profiles passing the security screen receive three N=16 acceptance trials
with one proof job and two native workers on qualified target hardware. Each
trial begins from a ready service with prepared circuits resident. Record
last-package-to-root latency, every proving phase, separate cold startup and
post-proof timings, whole-worker charged-memory peaks, actual enforced 5-GiB
limit, zero extra swap and OOM events. Select parameters from complete security
and performance evidence; do not lower security to reach 180 seconds. The
existing D4 leaf-B and uniform-q92 timing medians are below 180 seconds but do
not qualify: D4/W16 fails the required security targets and those records lack
the new timing and hard-limit evidence.

Freeze a complete reproducible review bundle after correctness and screening.
External review covers the final suite, parameters, composition and hiding
kernel. Production-path trials on qualified miner hardware follow finding
closure. A separate resettable N=16 network uses independent genesis, keys and
directories; the retained seven-node N=2 network remains unchanged. Leave N=32
assessment after the early checkpoint for a separate scope, and defer historical
height-activation design until before mainnet.

## Preliminary parameter work

The [planning parameter screen](d8-parameter-screen.md) uses explicit estimated
shape envelopes. Three profiles per layer meet its conservative arithmetic
requirements conditionally. Recursive profiles require an additional 16-bit
opening-batch grinding site, absent from the pinned recursive suite although
already supported natively. Implement and test the prerequisite above before
crediting it or running the checkpoint. These are experimental candidates, not
activation parameters. Actual-shape extraction and independent composition
review remain mandatory.

## Implemented scalar scaffold

The opt-in benchmark feature `d8-geometry` implements typed 12-scalar digests,
24-scalar/three-D8-lane packing, standard native W24 binary compression and
ALU constraints for canonical internal repacking. Scalar witnesses satisfy
`x^p=x` before recomposition; recomposition alone would permit arbitrary D8
coefficients masquerading as base elements. The two-lane digest representation
is internal only and constrains its final four padding coefficients. Extraction
from actual permutation outputs takes exactly the first 12 scalars and does
not force the unused output coefficients to zero.

Mutation tests cover every scalar, every extension coefficient, malformed
geometry and noncanonical internal padding. This is a correctness scaffold,
not an optimized hash AIR, registered suite, transcript, MMCS verifier or
recursive proof. It changes no node dependency or live network configuration.
Next work connects the scalar compression role to dependency tables and
native/recursive transcript verification, retaining all 12 external elements.
