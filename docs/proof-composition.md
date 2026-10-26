# Commitment and Proof Composition Tree Separation

Status: isolated circuit prototype and design evaluation. No new root key,
consensus format or parameter suite is activated. The node retains the binary
tree specified in [Protocol Decisions](protocol.md). D4 q42/q92/B results
below are historical method evidence. B is no longer a parameter candidate:
D4/W16 does not meet the selected post-quantum requirements. The selected
D8/W24/12-element target requires new security reports and measurements.

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

## The 16 -> 2 -> 1 topology

A genuine two-layer candidate requires two **eight-input** aggregation
circuits, each checking eight slot proofs, followed by one two-input root.
There are three recursive proof artifacts, but still 16 leaf-verifier checks
and two recursive child-verifier checks. Larger circuits can enlarge padded
trace domains, commitments, openings and peak memory; three artifacts do not
mean three current binary-proof costs. For N=32 the analogous split would
require two sixteen-input circuits, or an additional stage. N=16 measurements
must not be relabeled as N=32 evidence.

Let `T8` be one eight-input proof including all anchor checks, `Tr` the new
root proof, `L` the leaf proving work in the timed interval, and `O` the other
per-candidate work between last-package arrival and root-proof completion.
The selected schedule has one proof job and two native workers inside each
proof; the two eight-input proofs execute serially. Its projected latency is
`L + T8_left + T8_right + Tr + O <= 180 seconds`. A hypothetical two-proof-job
schedule instead has the optimistic path
`L + max(T8_left, T8_right) + Tr + O`, but is not the selected configuration.
Summing binary-layer costs is not a measurement of the eight-input relation.

## Timing boundary and retained-result interpretation

On qualified target hardware, measure from arrival of the last package input
at the proving service until the canonical root proof is complete. Include
leaf proving and all intervening admission, witness, scheduling and handoff
work. Controlled comparisons start all sixteen leaf proofs after all package
inputs are available. Record any production leaf work before the arrival marker
separately; never move the marker forward until leaf proofs are already ready.
See the [timing definition](prover-acceptance.md#timing-boundary-and-service-readiness).

Prepare all input-independent leaf, aggregation and root circuits and trusted
keys at service startup and keep them resident. Cold-start duration is recorded
separately and excluded from the 180-second latency budget. Preparation,
resident circuits, caches, proof buffers and native workers all remain inside
the current experimental process-tree ceiling, including during startup. The
next D8 experiment uses 10 GiB (10,737,418,240 bytes), with zero swap. This is
not a production acceptance budget; select that budget from actual peak
measurements. Input-dependent
work cannot be relabeled as startup preparation. PoW, propagation, standalone
root verification and wallet receipt are reported separately from proof latency.

Several retained D4/W16 N=16 results are numerically below 180 seconds:

| Configuration | Median proof/verification time | Median cold process time |
| --- | ---: | ---: |
| q42, one proof and one native worker | 45.66 s | 48.79 s |
| q42, one proof and two native workers | 24.39 s | 27.53 s |
| Leaf B, q92 aggregation/root, two native workers | 29.591 s | 33.564 s |
| q92 at every layer, two native workers | 64.04 s | 70.48 s |

These setup-excluding proof/verification figures include all sixteen leaves
and root verification, so they are useful timing-method references but not
exact measurements of the new arrival-to-root interval. The synthetic inputs
have no production last-package arrival marker. D4/W16 does not meet the
required security targets, so **none of these results constitutes acceptance**.
The records also do not establish an enforced production memory budget; uniform
q92 reached 5.82 GiB physical footprint during uncapped characterization. Changing
the time target does not qualify a rejected suite or change a memory observation.
D8/W24 requires new security screening and target-hardware measurements.

After opening-batch grinding is implemented and the checkpoint configuration
is frozen, at the first verified D8 eight-input merge apply the
[early checkpoint](d8-w24-recursion.md#early-performance-checkpoint)
to projected N=16 latency and peak memory: at most 135 seconds within the
10-GiB experimental ceiling permits continued experiments; more than 135 and
at most 180 seconds under that ceiling requires parallel optimization; more
than 180 seconds, more than 10 GiB or OOM pauses progression. The ceiling is
not production acceptance. Select the production memory budget after measured
peaks are available. Report per-stage memory components and peaks alongside times.
N=32 is the first separately scoped assessment after that checkpoint passes
and is not measured in the current work.

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
explicit trusted-verifier selection. The selected D8 engineering deployment
uses a separate new network; retained-history activation design is deferred.

Required rejection cases include one omitted or repeated leaf, a wrong child
key, spliced anchors, a changed ciphertext binding, fee overflow, missing
padding and each mutated root field. Compare independent native folds against
the proved statements. Statement compatibility requires rejection tests and
independent native folds, rather than configuration assertions.

## Root statement and verifier compatibility

The binary and eight-input topologies export the same 70-element root layout:
48 set-accumulator elements, eight anchor-root elements, height, eight miner-note
commitment elements, four reward-share limbs and fixed capacity. For the same
leaves, anchor root and miner-note witness, the statements are fieldwise equal.
The accumulator is an elementwise sum of leaf set hashes. Internal node digests
hash the full accumulated statement; they do not construct a binary Merkle root
over package proofs. The depth-12 anchor Merkle tree and depth-40 note commitment
tree are separate and retain their existing definitions.

The differential regression proves the same 16 leaves under both topologies,
compares every root field, verifies each proof under its own verifier, and
rejects both cross-verifier combinations. It also checks that the serialized
root verifier artifacts differ. A second regression repeats this with a distinct
leaf blowup and rejects a leaf proved under a different configuration. These
are relation tests with insecure smoke parameters, not a security approval.

Statement equality therefore preserves the public data interface, but does not
make the proof acceptable under the existing pinned root key. The eight-input
relation embeds a different child verifier. Production validates against trusted
root artifacts selected by capacity; adopting the new relation requires a
trusted-verifier change. The selected engineering scope uses a new N=16
network from genesis, preserving the old N=2 network without migration. It cannot be deployed as only a prover scheduling
change under unchanged validators.

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
   budget and isolated-network integration pass. A faster classical experiment does
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

Three cold N=16 measurements per completed eight-input configuration produced:

| Schedule | Proof/verification seconds | Median seconds | Cold median seconds | Maximum RSS | Maximum physical footprint |
| --- | --- | ---: | ---: | ---: | ---: |
| One proof, one native worker | 48.42, 45.49, 45.66 | 45.66 | 48.79 | 2.89 GiB | 3.00 GiB |
| One proof, two native workers (isolated dependency) | 24.39, 24.65, 24.23 | 24.39 | 27.53 | 2.95 GiB | 2.97 GiB |
| Two proofs, one native worker each | No completed sample | — | — | Unavailable | At least 4.08 GiB sampled before termination |

The dual-proof configuration exceeded the separate 4 GiB experiment budget and
was terminated. It was not repeated to manufacture three unsafe samples. RSS
alone would understate memory under compression. The 100 ms watchdog checks
both RSS and kernel lifetime physical footprint; it can overshoot and is not a
kernel allocation cap. The node's 3 GiB acceptance ceiling is separate.

Both completed N=16 series are below 180 seconds in this synthetic scope. This
does not satisfy the selected suite's security, enforced memory or hardware
acceptance requirements. Three samples do not establish tail
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

## Repeated q92 query-only measurements

The same preserved two-native-worker executable was run with 92 queries at
all layers, keeping D4/W16, log blowup 2, grinding 16, N=16, eight-input batches,
one proof at a time and two global Rayon workers. Each run used fresh hiding
randomness. The 4 GiB experimental threshold was disabled for characterization;
RSS and physical footprint collection remained enabled at 100 ms intervals.
No build or other local proof measurement ran concurrently. Background services
were retained and their load was not controlled.

| Run | Proof and verification | Cold process time | Peak RSS | Peak physical footprint |
| --- | ---: | ---: | ---: | ---: |
| 1 | 65.80 s | 73.34 s | 4.50 GiB | 5.74 GiB |
| 2 | 57.17 s | 64.36 s | 4.72 GiB | 5.53 GiB |
| 3 | 64.04 s | 70.48 s | 4.73 GiB | 5.82 GiB |

All three roots verified. Median proof/verification time was 64.04 seconds and
median cold time was 70.48 seconds. The two eight-input proofs together consumed
43.53–52.07 seconds, while the root proof consumed 13.11–13.39 seconds. Leaf
production for all 16 slots consumed 0.46–0.53 seconds. Maximum process RSS was
5,077,172,224 bytes and maximum physical footprint was 6,250,648,592 bytes.
No resource sampling errors occurred. All three setup-excluding proof/verification
times are below the current 180-second proof-latency target numerically, but
they do not establish the new timing markers, hard memory limit or required
security. They remain non-qualifying historical controls.

The nominal query/grinding arithmetic is `2 * 92 + 16 = 200`. This is the
repository's simplified query-budget comparison, not a proven composite
soundness bound. The pinned Plonky3 source also provides conjectured and proven
instance-level security accounting, including AIR/trace shape, batched openings
and commitment limits. Neither the simplified score nor halving it establishes
quantum security of the unchanged D4/W16 suite.

## Leaf-only experimental profiles

The isolated composition executable accepts fixed historical leaf profiles;
recursive aggregation and root proofs remain at `(log_blowup=2, queries=92,
grinding=16)`. No profile is an approved consensus parameter set.

| Profile | Leaf log blowup | Queries | Grinding | Nominal query/grinding score |
| --- | ---: | ---: | ---: | --- |
| B | 4 | 46 | 16 | `4 * 46 + 16 = 200` |
| A | 3 | 62 | 16 | `3 * 62 + 16 = 202` |
| C | 5 | 37 | 16 | `5 * 37 + 16 = 201` |

All slot types share one configured leaf prover. D4, W16, the leaf AIR and the
hiding PCS remain unchanged. The declared maximum AIR constraint degree is 3;
all candidate blowup factors exceed this conservative quotient-domain
requirement. The hiding minimum is 128 rows for B/C and 256 for A. Reducing
padding follows the changed query budget; hiding itself is not disabled.

For the historical measurement method, export its leaf pin in a separate operation. It
contains the exact suite, FRI parameters, AIR height, preprocessing width/degree
and preprocessing commitment. Every measurement must supply that fixed pin;
any parameter or key difference is rejected before generating a leaf proof.
The first aggregation circuit embeds the selected leaf configuration and
constrains its trusted preprocessing commitment. It never chooses a key from
an incoming proof. The regression rejects both a changed external pin and a
valid leaf proof generated with a different configuration.

These score equalities are experimental hypotheses. They do not establish
identical proven or conjectured composite security under different trace and
opening shapes. D4/W16 is excluded from external parameter approval. Review instead targets
the final D8 suite and screened profiles before production adoption.

### Measured profile B

Three fresh processes used the fixed B leaf pin, with one proof at a time and
two native hiding workers. All roots verified; every process matched the same
leaf pin, and no memory threshold was applied during characterization.

| Run | All leaves | First eight-input proof | Second eight-input proof | Root proof | Proof and verification | Cold process | Peak RSS | Peak physical footprint |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.659 s | 12.274 s | 9.939 s | 8.995 s | 31.946 s | 36.327 s | 3.03 GiB | 3.26 GiB |
| 2 | 0.595 s | 10.131 s | 9.753 s | 8.862 s | 29.421 s | 33.302 s | 3.37 GiB | 3.61 GiB |
| 3 | 0.653 s | 9.767 s | 9.730 s | 9.364 s | 29.591 s | 33.564 s | 2.95 GiB | 3.27 GiB |

Median proof/verification time was 29.591 seconds and median cold time was
33.564 seconds. Maximum RSS was 3,622,060,032 bytes and maximum physical
footprint was 3,879,488,728 bytes. The measured executable SHA-256 was
`25298ac2d2dccef0fdb616e96e84e4bb3beaeefe3ec9bc42841a3f2fa87e3967`;
the fixed leaf pin SHA-256 was
`4d3a4182399674295bc7f7e41d97bf89f3d82d3bfaffe8fdea6df9debe793941`.
Both proof time and cold time were below 180 seconds in all three runs. No
fallback to A or C was triggered. Leaf generation increased modestly relative
to uniform q92, while recursive proving and memory decreased. Lowering the
leaf verifier's query count changes both the eight-input circuit and the root
circuit that verifies it, despite retaining q92 output-proof parameters.

The [production-path acceptance plan](prover-acceptance.md)
leaves the production proof-process budget undecided until actual D8 peak
measurements are available. Uniform q92's observed physical footprint exceeded
5 GiB; this historical value is unchanged. Those uncapped D4 observations do
not establish compliance with any subsequently selected hard limit. The next
D8 experiment has a 10-GiB ceiling, which is not a production budget. Three
processes do not establish tail latency or a worst-case memory bound, and the
existing node/container limits are separate.

On a fresh experiment checkout, build the isolated two-worker dependency as
above, then export the B pin and collect three uncapped macOS processes:

```sh
composition_binary=.local/composition-intra/benchmark/target/release/composition-bench
"$composition_binary" --topology fanin8 --jobs 1 --queries 92 \
  --leaf-profile b --export-leaf-pin .local/leaf-b-pin.json
for repetition in 1 2 3; do
  RAYON_NUM_THREADS=2 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
    /usr/bin/time -l "$composition_binary" \
    --topology fanin8 --jobs 1 --queries 92 \
    --leaf-profile b --leaf-pin .local/leaf-b-pin.json \
    > ".local/leaf-b-${repetition}.jsonl" \
    2> ".local/leaf-b-${repetition}.stderr"
done
```

The executable exports per-batch timings, root time, proof/verification time,
cold time and the exact leaf configuration/key identity. The macOS time output
records process RSS and physical-footprint peaks. The retained experiment also
sampled libproc every 100 ms with no memory cutoff. The default bounded
measurement script retains its existing 4 GiB default; no production budget is
changed by these commands.

### Integration gate

D4/W16 does not meet the selected post-quantum target. B is retained only as
measurement-method evidence and is not a parameter candidate for external
review or production integration. Its apparent timing margin is not D8
headroom. The [D8/W24/12-element implementation](d8-w24-recursion.md)
needs new instance-specific security screening and three bounded measurements
before the [independent review](proof-security-review.md) and
[production-path gates](prover-acceptance.md).
Preserve the current N=2 network. Use a separate resettable N=16 engineering
network with independent genesis, keys and directories and no old-note/proof
imports. Height-activated historical-verifier design is deferred until before
mainnet. N=32 is the first separately scoped assessment after a passing D8
early checkpoint and is excluded from the current work. No existing key or validator is replaced by
this experiment.
