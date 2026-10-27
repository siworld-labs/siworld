# Native Multi-Asset Proof Profile and Measurements

Status: engineering-frozen native transaction profile with reproducible
instance-specific security and performance evidence. This is not independent
cryptographic approval, network activation or whole-node acceptance. The
D8/W24/12-element relations run natively without recursion.

## Selected transaction profile

The [engineering profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
selects `log_blowup=7`, 41 queries, 20-bit query grinding, 20-bit batch
grinding, zero commitment grinding, binary folding and final polynomial log
length zero. All three four-worker generation trials on the qualified EPYC
7763 reference profile complete within two seconds. Among the profiles that
meet that rule, this profile has the smallest maximum observed proof body.

| Selected-profile measurement | Value |
| --- | ---: |
| Generation trials, seconds | 1.332143 / 1.315662 / 1.316440 |
| Generation median, seconds | 1.316440 |
| Observed proof body, bytes | 583,552--584,848 |
| Body admission cap, bytes | 655,360 (640 KiB) |
| Cap above maximum observed body | 12.0565% |
| Maximum process-tree charged memory, bytes | 531,668,992 |
| Verification median in a four-worker process, milliseconds | 16.9034 |
| Classical conjectured union, bits | 185.0000 |
| Classical Johnson union, bits | 163.3846 |
| Quantum-halved Johnson challenge union, bits | 81.6922 |
| Selected W24 commitment BHT ledger, bits | 123.3333 |

The cap is at least 10% above the largest observed body and is rounded up to
64 KiB. It is an admission limit, not a mathematical maximum-size theorem for
all randomized valid proofs. The new multi-asset wallet/envelope/decoder and
node admission must enforce it before activation. The unchanged two-output
`bench-d8` baseline retains its own 512-KiB decoder and proof profile.

Three successful trials do not establish a worst-case proving-time bound:
hash grinding has probabilistic runtime, and shared-host load varies. No
security setting, 576-position block limit or capacity is reduced to meet the
performance criterion. Circuit-width and query-opening optimization follows a
[separate structural plan](multi-asset-air-optimization.md); replacement
parameters or lower bandwidth requirements need new evidence and an explicit
profile revision.

## Reference execution and measurement scope

[Hosted run 40465519899, attempt 2](https://github.com/siworld-labs/siworld/actions/runs/40465519899/attempts/2)
measured source commit `46b793e24ed42495d6c0c4c051e5a06fb4d56b13`.
The runner reported Ubuntu 24.04, AMD EPYC 7763, two exposed physical cores
and four vCPUs under Microsoft virtualization. Four CPUs were available in the
worker affinity mask. AVX2 was present and AVX-512 was absent. This establishes
the exposed reference hardware profile, not identity with a previous ephemeral
VM or exclusive access to the physical host.

The release uses the repository x86-64-v3 baseline, four Rayon workers and two
internal hiding workers, fixed dependencies and the startup CPU guard. All 24
fresh process-tree trials exited successfully under
`memory.max=5368709120`, `memory.swap.max=0`. Every `memory.events` delta,
including `max`, `oom`, `oom_kill` and `oom_group_kill`, was zero. Visible scope
and parent `cpu.max` values were `max 100000`; no finite visible quota reduced
the four-worker process.

Generation times measure the actual native proof generation after one-time
preprocessing. Preparation is separately timed and must occur at service
startup and remain resident in the integrated wallet/prover. The reported
charged-memory peak covers the whole fresh setup/prove/verify process tree,
including descendants and the recorder. It is not a standalone verifier-memory
bound or a miner hardware requirement. The 5-GiB scope is a diagnostic boundary.
Verification in this scan uses the same four-worker process; single-worker
verification and malformed-proof resource limits for this selected profile
remain separate qualification work.

## Complete eight-profile scan

Every row uses the minimum query count passing the actual-instance security
screen for the indicated blowup and grinding. Query and batch grinding have
the same value; commitment grinding is zero, folding is binary and final
polynomial log length is zero. Each row contains three fresh four-worker
processes; proof ranges and peak charged memory cover those three processes.
The selection requires every generation trial to be at or below two seconds,
then minimizes the maximum observed proof body. Median-only qualification is
not used.

| log blowup | Queries | Query/batch grinding | Three generation times (s) | Observed proof bytes | Maximum cgroup peak (bytes) | Quantum Johnson union (bits) | All three <=2 s |
| ---: | ---: | ---: | --- | ---: | ---: | ---: | --- |
| 5 | 57 | 20 | 0.347746 / 0.431773 / 0.315287 | 685,631--693,071 | 143,482,880 | 81.1698 | Yes |
| 5 | 55 | 24 | 4.687113 / 9.904237 / 5.536282 | 674,707--676,387 | 143,736,832 | 80.6726 | No |
| 6 | 47 | 20 | 0.753690 / 0.842322 / 0.717343 | 616,467--624,964 | 272,478,208 | 80.4338 | Yes |
| 6 | 46 | 24 | 2.049190 / 3.087182 / 5.130963 | 615,278--619,838 | 273,338,368 | 80.9352 | No |
| 7 | 41 | 20 | 1.332143 / 1.315662 / 1.316440 | 583,552--584,848 | 531,668,992 | 81.6922 | Yes |
| 7 | 39 | 24 | 4.084397 / 2.223029 / 1.694906 | 562,020--574,500 | 531,169,280 | 80.1951 | No |
| 8 | 36 | 20 | 2.238902 / 2.298781 / 2.315131 | 551,539--556,963 | 1,049,620,480 | 81.9492 | No |
| 8 | 35 | 24 | 11.778875 / 4.021280 / 4.217235 | 536,477--550,973 | 1,050,329,088 | 81.9506 | No |

All eight profiles satisfy the selected 80-bit quantum screen. The four
24-bit-grinding profiles and the blowup-8/20-bit profile fail the three-trial
generation criterion. Blowups 5, 6 and 7 with 20-bit grinding qualify; blowup 7
has the smallest observed proof body among them. The old 524,288-byte
transaction limit is not a selection constraint for this engineering profile.
Settlement and issuance retain independent 524,288-byte body caps.

## Actual relation shapes and permanent encoding

Dimensions are extracted from the complete AIR with pinned `p3-security`
0.9.0-rc.2. Hiding padding depends on the query count.

| Relation/profile | Base rows | Main columns | Preprocessing columns | Public values | Constraints | Degree |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Selected transaction, b7/q41/g20 | 256 | 1,420 | 243 | 97 | 2,940 | 3 |
| Settlement, 576 positions, b8/q36/g20 | 1,024 | 516 | 587 | 6,964 | 7,720 | 3 |
| Issuance, three notes, b8/q36/g20 | 128 | 438 | 10 | 72 | 573 | 3 |

The selected transaction instance has eight quotient chunks, 3,486 batched
functions and committed trace log length 9. The challenge-field floor is
247 bits and the selected classical commitment-collision floor is 185 bits.
The body codec encodes 2,027 public bytes; its 48-byte fee commitment and
40-byte snapshot selector bring permanent bytes per position to 2,115.
Envelope, sidecar, block and issuance records are additional components.

## Complete selected-profile security ledger

The following are the selected profile's raw error exponents in bits. Error
probabilities are combined before reporting union exponents. The quantum
ledger halves every Johnson Fiat--Shamir challenge exponent, including
query/grinding and batch-combination terms, and accounts for the folding-round
union. The [profile artifact](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
retains every actual shape and raw term for all eight measured profiles,
source/dependency identities and the public preprocessing commitment.

| Report/model | Error term | Bits |
| --- | --- | ---: |
| Classical conjectured | `air-composition` | 235.478400 |
| Classical conjectured | `deep-ali` | 234.829762 |
| Classical conjectured | `ldt-query-phase` | 305.011966 |
| Classical conjectured | `ldt-commit-phase` | 230.999978 |
| Classical conjectured | `batch-combination` | 239.233057 |
| Classical conjectured | `commitment-collision` | 185.000000 |
| Classical Johnson | `air-composition` | 223.975585 |
| Classical Johnson | `deep-ali` | 223.326947 |
| Classical Johnson | `low-degree-test` | 163.384584 |
| Classical Johnson | `batch-combination` | 206.806754 |
| Classical Johnson | `commitment-collision` | 185.000000 |
| Johnson FRI | `fri-folding` | 198.573697 |
| Johnson FRI | `fri-query` | 163.384584 |
| Challenge-domain ledger | `ood-deep-ali-domain` | 223.326947 |
| Challenge-domain ledger | `fri-folding-domain` | 191.929841 |

The FRI query term is the weakest challenge term. The `fri-folding-domain`
entry includes the folding-round adjustment before quantum halving; it must
not be counted as a second independent folding error. The classical
conjectured union is 184.99999999999997 bits, classical Johnson union
163.38458391106965 bits and quantum Johnson challenge union
81.69221886630498 bits. The selected Johnson list-decoding parameter is
`m=256`; proof multiplicity is one. The selected W24 commitment-collision
ledger converts its 185-bit classical collision term to
`185 * 2 / 3 = 123.33333333333333` BHT bits.

External BLAKE3-256 ciphertext/asset-ID binding is separately modeled at 128
classical collision bits and `256 / 3 = 85.33333333333333` nominal BHT bits.
It is not the W24 digest calculation and is not included in raw
`p3-security` output. The overall relation, application binding, hiding kernel
and Fiat--Shamir accounting still require independent security review.

## Independent settlement and issuance evidence

The settlement and three-note issuance diagnostics use `log_blowup=8`,
36 queries, 20-bit query/batch grinding, zero commitment grinding and binary
folding. Their parameters and 512-KiB caps are independent of the selected
transaction profile. Issuance verifies real ML-DSA-65 signatures and encrypted
note fixtures, but its benchmark SI-payment callback is synthetic; real
fee consumption and registry/note insertion need one durable atomic node
transition.

[Hosted diagnostics 40458954984](https://github.com/siworld-labs/siworld/actions/runs/40458954984)
used source `d546783c760d3c0910d838df82d43f8b2a5b691e` on an exposed EPYC
7763 two-core/four-vCPU reference profile. The table uses three four-worker
generation processes and three separate one-worker verification processes.
Proof ranges and maximum charged memory cover all six processes; those
one-worker processes also prepare and generate a proof, so their memory does
not establish an independent verifier bound.

| Relation/profile | Observed proof bytes | Four-worker generation median (s) | One-worker verification median (ms) | Maximum cgroup peak (bytes) |
| --- | ---: | ---: | ---: | ---: |
| 576-position settlement b8/q36/g20 | 485,115--498,747 | 4.6014 | 16.0873 | 2,976,501,760 |
| Three-note issuance b8/q36/g20 | 272,673--282,609 | 0.7320 | 8.4428 | 210,628,608 |

| Security ledger (bits) | Settlement | Three-note issuance |
| --- | ---: | ---: |
| Classical conjectured union | 185.000 | 185.000 |
| Classical Johnson union | 163.974 | 163.798 |
| Quantum Johnson challenge union | 81.984 | 81.899 |
| Selected W24 commitment BHT ledger | 123.333 | 123.333 |

## Network, retention and remaining gates

At the selected 655,360-byte transaction cap and 576 positions, the conditional
full-network ledger is **36.50164 Mbps** with three broadcasts and the bounded
transport, control, recovery and issuance allowances in the
[wire budget](v1-network-budget.md). A **43-Mbps minimum uplink** leaves at
least 15% of link capacity unused in that model; deployment recommends
**100 Mbps**. Qualification must still measure actual wire counters and
queue growth. Unbounded issuance or bulk recovery is outside this finite
allowance and needs explicit byte/work/rate limits.

The [storage ledger](v1-storage-and-sync.md) uses three elapsed days of proof,
settlement, issuance-proof and sidecar retention after depth-24 finality,
plus permanent public data. Database/WAL/compaction and issuance limits still
require integrated measurements. No proof is pruned early to meet a device
capacity target.

The engineering profile binds measured implementation/dependencies and a
reproducible public preprocessing key. It does not activate a consensus suite
or change the retained seven-node network. Canonical multi-asset envelopes,
allocation-bounded decoding, standalone verification CPU/memory limits,
concurrency/in-flight budgets, full-block validation, issuance fee/resource
policy and node/wallet atomicity remain integration gates. Supply auditing,
backup jobs, wallet restoration and actual elapsed three-day deletion
acceptance follow that integration; isolated proof/CI success does not
establish them.
