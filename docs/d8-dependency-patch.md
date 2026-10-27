# D8 Dependency Patch and Review Boundary

Status: experimental source implementation with fixed project-fork revisions.
The native application directly pins the source revision and registry lock graph;
the earlier local-path adapter is retired. The upstream proposal is
[Plonky3-recursion #479](https://github.com/Plonky3/Plonky3-recursion/pull/479). No retained node
or production proof parameter is changed by this work.

## Source lineage

The source delta is in **Plonky3-recursion**, based on
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. Base Plonky3 registry packages,
including `p3-security`, remain pinned to `0.9.0-rc.2`. Base Plonky3 already
provides KoalaBear D8, standard Poseidon2 W24 constants and native opening-batch
grinding; this patch does not modify those registry packages or Cargo caches.

Two complete revisions separate upstream-neutral APIs from compatibility:

| Source branch | Fixed revision | Scope |
| --- | --- | --- |
| `codex/d8-w24-native-suite` | `cb50fe9bb2dcd76fc7de1b71d0cd3f099eb235db` | Experimental suite, batch work, typed bounded hiding workers |
| `codex/d8-w24-native-suite-downstream` | `d3d15b2b5d1325fb38ebc8979c1cae04b761e71f` | Same APIs plus bounded downstream environment compatibility; no-std serial behavior preserved |

The source is distributed at [the project fork](https://github.com/siworld-labs/Plonky3-recursion).
The source patch, base revision and complete dependency lock graph remain pinned
together in `crates/bench-d8/dependency-lineage.toml`. Cargo uses the full
downstream revision rather than a mutable branch name. The build checks its
exact source tree and the separate upstream-base-to-downstream audit patch.
Operation does not depend on upstream acceptance.
Unmodified upstream code keeps its existing license notices; every modified
surface is included in the [audit registry](../.github/audit-registry.json).

## API coverage

| Surface absent from the stock dependency | Added implementation and required coverage |
| --- | --- |
| D8 random-codeword factory | `ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig` and factory with native parameter geometry |
| W24 scalar permutation/challenger | `Poseidon2Config::KOALA_BEAR_D1_W24`, dedicated challenger table and constrained eight-coefficient scalar lift |
| Suite identity | Experimental `SuiteIdV1` value `0xF824`, twelve-element digest codec and artifact/backend dispatch |
| Opening-batch work | `FriConfigV1::with_batch_pow_bits`, native/full/prepared transcript order, runtime witnesses, descriptor serialization and nonce rejection |
| FRI verifier parameters | `FriVerifierParams::try_with_mmcs_and_batch` and checked compatibility constructors; zero-work encoding remains stable |
| Hiding execution policy | Typed one/two-worker opt-in, serial default, unsupported-policy rejection and independent RNG/kernel review |

The native transaction and settlement proofs use `p3-uni-stark`; their proving
path does not invoke the recursive batch-prover worker pool. Four Rayon workers
in the native diagnostic must not be confused with recursive two-worker hiding
isolation. The compatibility environment hook is excluded from the upstream
proposal. Existing suites are not silently replaced.

## Test and audit scope

Focused worker-policy tests cover valid and invalid choices, exact pool size,
non-hiding caller-pool preservation and rejection of two workers without
parallel support. The dependency also contains fixtures for native/circuit
transcript equivalence, interleaved MMCS/challenger work, both binary-compression
directions, suite/descriptor identity, all scalar coefficients, positive batch
work and changed nonce/opening rejection through full and prepared paths.
Test presence is distinct from observing all upstream checks on a new revision.
The final implementation passed 14 descriptor tests, seven batch-work API
tests (one overlaps the descriptor group), a full-width scalar witness-bus
rejection test, and upstream-neutral worker policy tests with parallel support
(three) and without it (two). These are focused correctness checks. The new
W24 registry entries append after all existing wire tags. Zero-work native
proof/descriptor decoding remains compatible, but rebuilt recursive circuits,
verification keys and prepared artifacts may change identity and require
regeneration and pinning.

No recursive performance benchmark is required to evaluate the native V1 route.

External review must include the modified dependency sources, native AIRs,
application byte bindings, all Fiat–Shamir work sites, descriptor/key binding,
scalar coefficient constraints, RNG derivation and opt-in hiding parallelism.
The raw and selected-model [security ledgers](bht-security-accounting.md) are
inputs to review, not an independent soundness theorem.

## Remaining engineering estimate

| Work package | Engineering days | Completion evidence |
| --- | ---: | --- |
| Fixed source distribution, direct Cargo pins and adapter retirement | Implemented; release validation pending | Immutable remote revision and unchanged registry graph; observe clean remote build |
| Native/full/prepared adversarial and feature-matrix regression | 2–3 | Observed positive/negative tests, legacy suite/zero-work compatibility |
| Frozen audit snapshot and native application integration | 1–2 | Source, lock, codec, descriptor, key, report and executable identities |
| Upstream review follow-up | 1–3, parallel | PR #479 submitted; review responses and required upstream checks pending; merge is not a release dependency |

These are effort estimates for remaining verification and distribution work,
not a production-readiness claim. Cryptographic review duration is separate.

## Production freeze dependencies

A passing resource diagnostic does not complete node integration of the selected
4,096-canonical-snapshot policy, checked wallet outputs or bounded untrusted-proof
admission. The isolated implementations are described in the native specification.
The current scanner deliberately emits `actual_production_air=false` and
`production_selection_allowed=false`; these flags may change only after the
corresponding [relation and codec gates](route-a-v1.md) are implemented and tested.

The 524,288-byte wire maximum is selected independently of that freeze.
Mempool byte/CPU/in-flight limits need deterministic decoding bounds, the final
sidecar/envelope ledger, single-core verifier memory and malformed-input work
measurements. Generation memory from a combined setup/prove/verify process
cannot be mislabeled as an isolated verifier-memory bound. These gaps prevent
freezing measurement-derived production admission constants today.
