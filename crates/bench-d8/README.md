# D8 W24 Recursive Proof Checkpoint

Status: isolated experimental implementation. No node or network activates
this suite. The benchmark uses KoalaBear D8, standard Plonky3 Poseidon2 W24
and twelve scalar digest elements. The application relation has sixteen
leaves, two eight-input proofs and one root. The application encoding and
verification keys are experimental.

Build with `python3 scripts/build-d8-checkpoint.py --output .local/d8-build` from the repository root.
The adapter checks out the pinned recursion revision, applies the explicit
dependency patch to a fresh private copy and uses the locked registry graph.
Direct compilation against the unpatched upstream suite is unsupported.
The production dependency graph and retained network remain unchanged.

The initial implementation lifts the scalar W24 permutation AIR into D8. It
constrains all scalar coefficients and uses a separate challenger table so
MMCS operations cannot alter transcript capacity. It does not claim a packed
D8 permutation optimization. Ciphertext digests retain all sixteen scalar
limbs, padded to two rate-twelve blocks with constrained zero tails. Ciphertext limbs are range-checked to sixteen bits. Numeric
blocks have eight limbs and four constrained zero elements.

Opening-batch grinding is checked after claimed openings and before the
batching challenge in native, ordinary recursive, hiding and prepared paths.
The zero-difficulty descriptor encoding is preserved, but the recursive input
layout now includes a canonical-zero nonce slot, so old prepared keys are
not reused. This isolated experiment does not change existing network keys.

The checkpoint prepares and retains the leaf, merge and root layers once,
exports their artifacts and actual-shape security reports, and waits for a
validated controller grant. It then proves three full synthetic N=16 schedules
with fresh hiding randomness. Timing starts at final input arrival before
leaf generation and ends at root proof completion. Cold preparation is timed
separately; its memory remains inside the process-tree 5-GiB/no-swap limit.

A fixed `p3-security` report screens each actual layer and the nineteen-proof
composition before warm measurement. The selected halving/BHT ledger is an
experimental screening model, not a QROM theorem or cryptographic approval.
Raw artifacts, fixtures and measurements remain outside source publication.

At most 135 seconds and at most 5 GiB permits continuation. More than 135 and
at most 180 seconds under the cap requires optimization. More than 180 seconds,
a cap violation, OOM or an incorrect proof pauses progression. Per-stage charged
peak samples are lower bounds; kernel lifetime `memory.peak` governs the hard
limit and includes startup and every resident layer. Serialized retained-proof
sizes are reported separately from allocator memory. N=32 is out of scope.
