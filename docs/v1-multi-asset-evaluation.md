# Native Multi-Asset Proof Measurements

Status: reproducible isolated diagnostics, not a new parameter freeze or network
acceptance. The D8/W24/12-element relations run natively without recursion.
The complete requested grid did not meet both the 512-KiB body limit and the
two-second four-worker generation target on the local comparison host.

## Actual relation shapes

Dimensions are extracted from the complete AIR with fixed `p3-security`
0.9.0-rc.2. Hiding padding depends on the query count.

| Relation/profile | Base rows | Main columns | Preprocessing columns | Public values | Constraints | Degree |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Transaction, b9/q31/g24 | 256 | 1,420 | 243 | 97 | 2,940 | 3 |
| Settlement, 576 slots, b8/q36/g20 | 1,024 | 516 | 587 | 6,964 | 7,720 | 3 |
| Issuance, three notes, b8/q36/g20 | 128 | 438 | 10 | 72 | 573 | 3 |

The transaction body encodes exactly 2,027 bytes; fee commitment and snapshot
selector bring permanent per-position bytes to 2,115. Envelope framing and
node admission remain integration work. Issuance authenticates actual ML-DSA-65
signatures and checks real encrypted note fixtures. Its benchmark SI-payment
callback is synthetic; it is not an implementation of fee-payment admission.

## Requested transaction grid

Host: Apple M1 Max, ten physical/logical CPU cores, 32 GiB RAM. Release build,
four Rayon workers, two internal hiding workers, fixed Cargo lockfile and
dependency revision. Each row is one real encrypted three-output transaction
proof and native verification, using the minimum query count passing the
actual-instance screen. These rows are screening measurements, not three-trial
medians or Linux reference-hardware acceptance. Grinding randomness affects
generation time and hiding/Merkle randomness affects encoded length.

| log blowup | Query/batch grinding | Queries | Proof bytes | Four-worker generation (s) | Process peak RSS (MiB) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 16 | 73 | 808,974 | 0.1189 | 73.31 |
| 4 | 20 | 71 | 784,466 | 0.4431 | 74.52 |
| 4 | 24 | 69 | 772,870 | 2.8344 | 72.38 |
| 5 | 16 | 58 | 703,525 | 0.2272 | 137.75 |
| 5 | 20 | 57 | 686,639 | 0.7137 | 137.62 |
| 5 | 24 | 55 | 670,243 | 1.6500 | 138.64 |
| 6 | 16 | 49 | 645,536 | 1.2454 | 261.34 |
| 6 | 20 | 47 | 628,372 | 1.3589 | 258.45 |
| 6 | 24 | 46 | 613,742 | 5.0850 | 259.08 |
| 7 | 16 | 42 | 603,847 | 0.7786 | 507.23 |
| 7 | 20 | 41 | 587,056 | 0.8884 | 508.75 |
| 7 | 24 | 39 | 561,828 | 1.5405 | 509.58 |
| 8 | 16 | 37 | 568,569 | 1.5886 | 996.53 |
| 8 | 20 | 36 | 559,075 | 1.7121 | 996.33 |
| 8 | 24 | 35 | 547,325 | 6.2398 | 996.06 |
| 9 | 16 | 33 | 549,506 | 4.0248 | 1982.45 |
| 9 | 20 | 32 | 529,644 | 3.4182 | 1982.47 |
| 9 | 24 | 31 | 521,206 | 6.2272 | 1982.20 |

Rows 4--8 are the requested grid. Log blowup 9 is the separately measured
larger-blowup fallback after all requested-grid bodies exceeded 524,288 bytes.
Commitment grinding is zero, folding is binary and final polynomial log length
is zero throughout. The b9/q31/g24 profile fits the cap in the observed trials
but exceeds the two-second generation target. It is a rejected diagnostic
profile, not an approved or selected production parameter.

## Three-trial diagnostics

Each generation entry is the median of three fresh four-worker processes.
Verification is the median timed native verification in three separate
one-worker processes. Those processes first build preprocessing and generate
their own proof; their memory is not an independent verifier-only bound.
Setup is timed separately and excluded from the generation value. RSS is the
largest process-lifetime maximum across all six trials, including setup,
generation and verification; it is not cgroup charged memory.

| Relation/profile | Proof bytes, observed range | Four-worker generation median (s) | One-worker verification median (ms) | Maximum process RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Transaction b9/q31/g24 | 512,805--521,206 | 4.7473 | 14.2035 | 1982.48 |
| 576-slot settlement b8/q36/g20 | 488,571--498,939 | 3.3959 | 15.0113 | 2839.78 |
| Three-note issuance b8/q36/g20 | 272,289--283,761 | 0.6434 | 8.2287 | 203.95 |

The transaction cap margin in these samples is not a maximum encoded-size
proof. All output lengths remain subject to admission limits; a later freeze
must qualify size variation and enforce the cap without weakening security.
No cap, block capacity, hardware requirement or retained network is changed.

## Instance security ledger

The selected external ledger halves all Johnson Fiat--Shamir challenge error
exponents, including query/grinding terms, and unions the resulting errors.
The following values are diagnostics under that model, not independent
cryptographic approval of the relation/PCS/application-hash composition.

| Term (bits) | Transaction b9/q31/g24 | Settlement b8/q36/g20 | Issuance b8/q36/g20 |
| --- | ---: | ---: | ---: |
| Classical conjectured union | 185.000 | 185.000 | 185.000 |
| Classical Johnson union | 163.413 | 163.974 | 163.798 |
| Quantum Johnson challenge union | 81.706 | 81.984 | 81.899 |
| AIR composition, before halving | 222.976 | 220.119 | 226.832 |
| DEEP/ALI, before halving | 222.327 | 218.863 | 224.824 |
| FRI query including grinding, before halving | 163.413 | 163.974 | 163.798 |
| FRI folding, raw before halving/union | 194.574 | 188.685 | 200.562 |
| Batch combination, before halving | 206.807 | 197.477 | 210.519 |
| Commitment collision, classical report | 185.000 | 185.000 | 185.000 |
| Commitment collision, selected BHT ledger | 123.333 | 123.333 | 123.333 |

FRI query error is the weakest challenge term. Challenge-domain folding
also accounts for the union over folding rounds before the 80-bit screen.
External BLAKE3-256 byte/asset-ID binding has nominal classical collision
exponent 128 and BHT exponent 256/3; it is explicitly separate from the raw
p3-security report. The full JSON reports include all raw terms, actual shapes,
source/dependency/binary identities and lack of approval or activation.

## Hosted EPYC 7763 diagnostics

[Hosted run 40458954984](https://github.com/siworld-labs/siworld/actions/runs/40458954984)
passed for source commit
`d546783c760d3c0910d838df82d43f8b2a5b691e`. Its sanitized JSON artifact records
the full requested grid, fallback profiles, three-trial statistics, security
terms and source/dependency/binary identities.

The runner reported Ubuntu 24.04, AMD EPYC 7763, two exposed physical cores
and four vCPUs under Microsoft virtualization. AVX2 was available; AVX-512
was absent. Exclusive physical-host access was not established. The release
used the fixed x86-64-v3 baseline, four Rayon workers and two internal hiding
workers; instruction inspection found AVX2 packed-multiply instructions.

All 36 fresh process-tree trials produced valid proofs and exited zero under
`memory.max=5368709120`, `memory.swap.max=0`. Every `memory.events` delta,
including `max`, `oom` and `oom_kill`, was zero. `cpu.max` reported
`max 100000`, so these scopes imposed no CPU quota.

The following timing medians use three four-worker generation runs and three
separate one-worker verification runs. Proof ranges and maximum charged
memory cover all six repeats of each relation. Setup is excluded from the
generation timer. The memory scope includes fresh setup, generation,
verification, descendants and the recorder; it is not verifier-only memory.

| Relation/profile | Observed proof bytes | Four-worker generation median (s) | One-worker verification median (ms) | Maximum cgroup peak (bytes) |
| --- | ---: | ---: | ---: | ---: |
| Transaction b9/q31/g24 | 512,469--523,702 | 6.3081 | 14.8915 | 2,083,336,192 |
| 576-slot settlement b8/q36/g20 | 485,115--498,747 | 4.6014 | 16.0873 | 2,976,501,760 |
| Three-note issuance b8/q36/g20 | 272,673--282,609 | 0.7320 | 8.4428 | 210,628,608 |

Per-trial four-worker values retain the variability hidden by the medians:

| Relation | Three generation times (s) | Three cgroup peaks (bytes) |
| --- | --- | --- |
| Transaction b9/q31/g24 | 8.7617 / 5.1430 / 6.3081 | 2,083,336,192 / 2,083,299,328 / 2,082,828,288 |
| 576-slot settlement b8/q36/g20 | 4.6856 / 4.6014 / 4.5881 | 2,976,501,760 / 2,976,468,992 / 2,976,477,184 |
| Three-note issuance b8/q36/g20 | 0.7320 / 0.9624 / 0.5511 | 210,370,560 / 210,407,424 / 210,628,608 |

No transaction profile met both the proof cap and two-second generation
criterion. Every requested blowup-4--8 profile was oversized; the separately
measured blowup-9 fallback fits the cap in these samples but its median is
6.3081 seconds. Its largest observed body leaves only 586 bytes below the
524,288-byte cap, which is not a deterministic encoded-size guarantee.
Grinding and shared-runner variability require explicit treatment in any
future qualification. The instance security terms match the ledger above.
These measurements do not freeze parameters, establish independent verifier
resource bounds or activate a network. Five GiB remains a diagnostic scope
boundary rather than an adopted miner hardware requirement.

## Hosted reproduction and remaining gates

The dedicated `multi-asset-native.yml` workflow reruns the actual grid on
Ubuntu 24.04 with the repository x86-64-v3 baseline and startup CPU guard.
It records the actual CPU rather than assuming an EPYC 7763 allocation.
Every process tree has a fresh `MemoryMax=5G`, `MemorySwapMax=0` scope; the
artifact retains `memory.peak`, `memory.events`, CPU controls and stage timing.
Five GiB remains a diagnostic boundary, not a formal miner requirement.

If no profile passes both targets, the workflow still repeats the best
diagnostic profile three times and records rejection. A successful workflow
means its tests and collection completed; it does not mean parameter acceptance.
Independent verifier-only memory/CPU limits, full block validation, final
envelope/issuance limits and sustained integrated-node qualification remain
open. Supply auditing, backup jobs, wallet recovery and actual elapsed
three-day deletion acceptance follow the AIR work.
