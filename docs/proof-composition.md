# Commitment and Proof Composition Tree Separation

Status: isolated circuit prototype and design evaluation. No new root key,
consensus format or parameter suite is activated. The node retains the binary
tree specified in [Protocol Decisions](protocol.md).

## Distinct trees and scheduling

The depth-40 note commitment tree commits accepted output notes and supplies
wallet membership paths. The depth-12 recent-roots tree commits anchor entries.
Neither tree is the recursive proof composition tree. Their roots and paths
remain checked even if private proof composition changes.

For 16 slot proofs the current composition is `16 -> 8 -> 4 -> 2 -> 1`:
15 binary recursive proofs, four dependent layers. Running two nodes at a time
changes execution overlap, not fan-in, proof count or the pinned relation.
Dividing the same tree into two eight-slot worker jobs still requires seven
binary proofs per worker plus the root. That partition alone cannot remove a
layer or establish a latency improvement.

## The 16 -> 2 -> 1 candidate

A genuine two-layer candidate requires two **eight-input** aggregation
circuits, each checking eight slot proofs, followed by one two-input root.
There are three recursive proof artifacts, but still 16 leaf-verifier checks
and two recursive child-verifier checks. Larger circuits can enlarge padded
trace domains, commitments, openings and peak memory; three artifacts do not
mean three current binary-proof costs. For N=32 the analogous split would
require two sixteen-input circuits, or an additional stage. N=16 measurements
must not be relabeled as N=32 evidence.

Let `T8` be one eight-input proof including all anchor checks, `Tr` the new
root proof, `L` the leaf production/validation cost, and `O` integration
overhead. With two workers, the optimistic critical path is
`L + max(T8_left, T8_right) + Tr + O`. With one worker it is
`L + T8_left + T8_right + Tr + O`. A 60-second target therefore requires
`max(T8_left, T8_right) < 60 - L - Tr - O`. The isolated measurements below cover
this candidate at the current classical prototype parameters. Summing binary
layer costs is not a measurement of the eight-input relation.

## Isolated prototype

The opt-in `experimental-fanin` feature in `siworld-bench-plonky3` implements
`agg::fanin::EightLeafAggregation`. One circuit verifies exactly eight leaf
proofs, checks all eight anchor paths against a common root, adds the set
accumulators and range-checked fee limbs with overflow rejection, and commits
the resulting internal statement. Two such proofs feed a binary root built
against their distinct verifier. This produces an actual `16 -> 2 -> 1`
recursive topology without changing the note commitment tree or anchor tree.
The node never enables this feature; its default feature check rejects it.

The isolated regression constructs both eight-input proofs and the root,
checks the root against the native statement fold, mutates every root field,
and rejects missing leaves, spliced statements, changed anchor paths and a
binary child under the eight-input verifier. Repeating a leaf changes the
proved multiset; native slot and nullifier uniqueness checks remain necessary,
as they are for the binary relation. The regression uses explicitly insecure
smoke parameters and establishes neither performance nor cryptographic
acceptance. Run it independently with:

```sh
cargo test --manifest-path crates/bench-stark/Cargo.toml --release --locked \
  -p siworld-bench-plonky3 --features experimental-fanin --lib agg::fanin::tests
```

## Required statement and verifier checks

An experiment must preserve the canonical slot-byte binding, additive set
accumulator, all fee limb ranges/carries, exact slot multiplicity and count,
anchor membership and common anchor root, and miner-note/reward derivation.
Every child must use a pinned verifier key. Native duplicate-slot/nullifier
rejection and fixed-capacity padding remain mandatory. The final public
statement may retain its layout; that does not preserve the circuit or root
verifier key. New relations need distinct artifact/key identities and an
explicit versioned history-verification migration before activation.

Required rejection cases include one omitted or repeated leaf, a wrong child
key, spliced anchors, a changed ciphertext binding, fee overflow, missing
padding and each mutated root field. Compare independent native folds against
the proved statements. Statement compatibility requires rejection tests and
independent native folds, rather than configuration assertions.

## Measurement and decision gates

1. Retain a cold binary control at the pinned parameters, with one and two
   concurrent proofs. Record aggregation time separately from setup and root
   verification; record whole-process peak RSS and its scope.
2. Extend the isolated eight-input prototype's rejection coverage and review
   its constraints, retaining unmodified current keys and validators.
3. Measure both worker proof times, root proof time, artifact size, padded
   table dimensions and memory. Report one-worker and two-worker bounds using
   the same CPU allocation and fresh hiding randomness.
4. Adopt only after the full statement checks, independent review, resource
   budget and versioned migration pass. A faster classical experiment does
   not establish the quantum-suite, full-node or sustained block target.

## Parameters, CPU profile and measured N=16 behavior

The current protocol prototype uses D4/W16, log blowup 2, 42 queries and 16
pre-query grinding bits. These are also the parameters of the earlier N=32
binary concurrency measurements. A 92-query D4/W16 run changes the query budget
only; it is not the complete proposed quantum suite. No finalized quantum
parameter set or new consensus key is selected by this experiment.

The isolated `composition-bench` executable proves 16 synthetic slots and
verifies the resulting root. Each measurement starts a fresh process and uses
fresh hiding randomness. Compilation is excluded. Cold time includes circuit
setup. Proof time includes leaves, recursive proofs and their verification,
but excludes setup. Both global Rayon configurations use two workers. These
are worker settings, not an OS CPU quota.

A binary-tree serial profile measured 95.87 seconds of proof and verification,
99.72 seconds cold, 1.44 GiB peak RSS and 2.11 GiB peak physical footprint. The
recursive STARK phases accounted for approximately 94.54 seconds and used
0.97 effective cores; one thread usually accumulated CPU in each 100 ms sample.
The witness phases were much smaller. The pinned recursion library isolates
hiding native proofs in a one-worker Rayon pool, regardless of the global pool.

`scripts/build-composition-intra.py` creates an ignored copy of the pinned
upstream revision and benchmark workspace. Its only proving execution change
allows an explicitly selected one- or two-worker native pool, defaulting to
one. It retains registry versions/checksums and leaves node dependencies and
verifier code unchanged. Relation and rejection regressions pass with two
workers. This does not independently establish cryptographic safety of
parallel hiding and is not enabled by the node.

With one proof at a time and two native workers, the binary profile measured
50.71 seconds of proof/verification, 54.19 seconds cold, 1.84 GiB peak RSS and
2.15 GiB peak physical footprint. Its recursive STARK phases used 1.88–1.93
effective cores, with two CPU-active threads typical in sampled intervals.
Thread counts are sampled CPU deltas, not proof that all phase instructions
execute concurrently. Phase boundaries can be attributed within one sample
interval.

Measurement environment: Apple M1 Max, 10 logical CPUs, 32 GiB RAM, macOS
26.6.2, `aarch64-apple-darwin`, Rust 1.99.1, release thin LTO and 16 codegen
units. The recursion dependency is pinned to
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. Measured binary SHA-256 identities
are `ff170e9143c294439759df7072c0387b85f9c2f46757a6f58fe8f09d5c444188`
for the original kernel and
`b38f94c65bb0f630f63666271262464e8bdacc667a70025d0121465ff42022c4`
for the isolated two-worker kernel. Background service load was not controlled.

Three cold N=16 measurements per safe eight-input configuration produced:

| Schedule | Proof/verification seconds | Median seconds | Cold median seconds | Maximum RSS | Maximum physical footprint |
| --- | --- | ---: | ---: | ---: | ---: |
| One proof, one native worker | 48.42, 45.49, 45.66 | 45.66 | 48.79 | 2.89 GiB | 3.00 GiB |
| One proof, two native workers (isolated dependency) | 24.39, 24.65, 24.23 | 24.39 | 27.53 | 2.95 GiB | 2.97 GiB |
| Two proofs, one native worker each | No completed sample | — | — | Unavailable | At least 4.08 GiB sampled before termination |

The dual-proof configuration exceeded the separate 4 GiB experiment budget and
was terminated. Further dual-proof runs were skipped after the budget violation. RSS
alone would understate memory under compression. The 100 ms watchdog checks
both RSS and kernel lifetime physical footprint; it can overshoot and is not a
kernel allocation cap. The node's 3 GiB acceptance ceiling is separate.

Both safe N=16 series are below 60 seconds in this synthetic scope. This does
not satisfy the N=32, complete quantum suite, proof-of-work, network/load or
sustained block acceptance requirements. Three samples do not establish tail
latency. The historical 106-second reference lacks its command and artifact,
so it is contextual only. The measured CPU profile favors isolated intra-proof
parallelism over a second full proof workspace within this budget; production
retains its existing serial native kernel until review and migration gates pass.

Build and measure without a node or network listener:

```sh
cargo build --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 --features experimental-fanin,phase-profile \
  --bin composition-bench
python3 scripts/measure-composition.py \
  --binary crates/bench-stark/target/release/composition-bench \
  --jobs 1 --repetitions 3 --output .local/composition-serial.json
python3 scripts/build-composition-intra.py
python3 scripts/measure-composition.py \
  --binary .local/composition-intra/benchmark/target/release/composition-bench \
  --hiding-workers 2 --jobs 1 --repetitions 3 \
  --output .local/composition-intra.json
```

The collector requires macOS. Linux resource acceptance needs separate cgroup
charged-memory evidence and enforcement. Raw observations remain private.
