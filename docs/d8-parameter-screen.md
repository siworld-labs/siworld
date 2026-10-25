# D8 Parameter Planning Screen

Status: experimental candidates conditional on estimated shapes and proposed
transcript work. These are not approved parameters, actual D8 circuit reports
or an implemented recursive suite. Re-extract every shape and enforced grinding
site after implementation. Do not deploy from this table.

The calculator pins `p3-security = 0.9.0-rc.2`. Run:

```sh
cargo run --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 --features security-report --bin d8-security-screen
```

## Model and shape assumptions

The suite uses KoalaBear D8, standard Poseidon2 W24 and digest12. Round down
field size to 247 bits, ideal classical collision resistance to 185 and BHT
resistance to 123. These ideal ceilings still require permutation/capacity
review. Halve every non-hash term, including the total grinding contribution,
for a conservative selected-model screen. Use BHT for commitment collisions.
This is not a QROM theorem. DEEP-ALI is the estimator's combined OOD/DEEP term.

For Johnson, evaluate one consistent list parameter m across ALI, DEEP, FRI
and batching. Split FRI folding and query errors and sum them, instead of
treating the estimator's weakest-round minimum as an exact error sum. Sum all
terms by log-sum-exp; reserve another log2(19)=4.247928 bits at **every layer**
for 16 leaves, two merges and one root. Thus any selection below passes this
19-proof envelope, conditional on every shape/site assumption. No independence
is assumed. All algebraic/query terms are quantum-halved, a stricter screen
than halving only the named challenge rounds.

The search covers log blowup 2/3/4, 96–256 queries in increments of four, binary
and quaternary maximum folding, and Johnson m=3–32. Grinding is 16 bits before
queries, zero before FRI commits, OOD and lookups. Recursive alternatives below
also require 16 bits immediately before opening batching. That additional site
is **not implemented** by the pinned recursive suite; its nonce, transcript
order and recursive verification need design and tests. No security credit is
permitted until all validators check it. This is an experimental dependency
proposal, not a consensus decision.

Estimated conservative envelopes use the D4 table inventory as an anchor and
allow larger widths/heights for D8, wider digests and more verifier queries.
They are planning assumptions, not measured maxima or proven cost bounds. Each
recursive table is conservatively charged at the maximum committed height,
with summed constraints/chunks/lookups/openings. Table-row and width changes
outside this envelope invalidate the selection. The root uses the same envelope
as a planning allowance, not a claim that root and merge costs are equal.

| Layer | Maximum base rows per table | Hiding-extended rows | Main widths | Preprocessed widths | Constraints | Max degree | Quotient chunks | Batched openings | Lookup factors/row; max width |
| --- | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | --- |
| leaf | 1024 | 2048 | [1024] | [256] | 8192 | 7 | 16 | 4096 | 0; 0 |
| eight_input | 1048576 | 2097152 | [8, 32, 160, 336, 8, 16] | [12, 16, 128, 64, 20, 18] | 65536 | 7 | 128 | 8192 | 128; 32 |
| root | 1048576 | 2097152 | [8, 32, 160, 336, 8, 16] | [12, 16, 128, 64, 20, 18] | 65536 | 7 | 128 | 8192 | 128; 32 |

These are separate main/preprocessing widths, not combined physical column
counts; extension auxiliary columns and quotient commitments are charged via
the envelope's opening/chunk counts. Leaf base rows allow hiding padding for
the larger query counts. LDE domain log size must not exceed KoalaBear's
24-bit two-adicity; the calculator rejects larger combinations. A log-21
recursive commitment therefore excludes log blowup 4. Maximum folding arity
means factor 2 or 4, with final polynomial log length zero and a potentially
smaller terminal fold; it is not a new Merkle branching format.

## Candidate summaries

All values are bits. Classical columns sum every term for one proof, before
the reserved 19-proof loss. The quantum column includes that loss. Each passes
classical conjectured ≥128, Johnson ≥100, quantum-halved non-hash ≥100 and BHT
≥100 **only under the declared envelope and proposed sites**. The narrow
margins are not permission to round up, omit terms or tolerate larger shapes.

| Layer/profile | log blowup | Queries | Query/batch grinding | Maximum fold | Johnson m | Conjectured union | Johnson union | Quantum after 19-proof union | BHT after 19-proof union |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| leaf/1 | 2 | 216 | 16/0 | 2 | 8 | 185.0000 | 185.0000 | 100.0488 | 118.7521 |
| leaf/2 | 2 | 216 | 16/0 | 4 | 8 | 185.0000 | 185.0000 | 100.0360 | 118.7521 |
| leaf/3 | 3 | 148 | 16/0 | 2 | 4 | 185.0000 | 185.0000 | 100.3036 | 118.7521 |
| eight_input/1 | 2 | 216 | 16/16 | 2 | 8 | 185.0000 | 185.0000 | 100.0385 | 118.7521 |
| eight_input/2 | 2 | 224 | 16/16 | 4 | 6 | 185.0000 | 185.0000 | 100.1284 | 118.7521 |
| eight_input/3 | 3 | 148 | 16/16 | 2 | 4 | 185.0000 | 185.0000 | 100.2159 | 118.7521 |
| root/1 | 2 | 216 | 16/16 | 2 | 8 | 185.0000 | 185.0000 | 100.0385 | 118.7521 |
| root/2 | 2 | 224 | 16/16 | 4 | 6 | 185.0000 | 185.0000 | 100.1284 | 118.7521 |
| root/3 | 3 | 148 | 16/16 | 2 | 4 | 185.0000 | 185.0000 | 100.2159 | 118.7521 |

## Per-term ledger

Each cell is `classical / selected quantum` bits. Errors are bounded by
`2^(-bits)` under the corresponding estimator/model assumptions. An omitted
lookup term means the leaf has no lookup argument. The weakest classical term
and the weakest transformed term are distinguished below.

### leaf profile 1

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 234.0000 / 117.0000 | 229.9125 / 114.9563 |
| deep-ali | 231.9125 / 115.9562 | 227.8250 / 113.9125 |
| ldt-query-phase | 443.6866 / 221.8433 | — |
| ldt-commit-phase | 233.9998 / 116.9999 | — |
| batch-combination | 222.0004 / 111.0002 | 209.3222 / 104.6611 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 221.3219 / 110.6609 |
| fri-query | — | 213.1080 / 106.5540 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `batch-combination`.

### leaf profile 2

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 234.0000 / 117.0000 | 229.9125 / 114.9563 |
| deep-ali | 231.9125 / 115.9562 | 227.8250 / 113.9125 |
| ldt-query-phase | 443.6866 / 221.8433 | — |
| ldt-commit-phase | 232.4149 / 116.2074 | — |
| batch-combination | 222.0004 / 111.0002 | 209.3222 / 104.6611 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 219.7369 / 109.8685 |
| fri-query | — | 213.1080 / 106.5540 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `batch-combination`.

### leaf profile 3

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 234.0000 / 117.0000 | 230.3301 / 115.1650 |
| deep-ali | 231.9125 / 115.9562 | 228.2426 / 114.1213 |
| ldt-query-phase | 456.1936 / 228.0968 | — |
| ldt-commit-phase | 232.9999 / 116.5000 | — |
| batch-combination | 221.0004 / 110.5002 | 210.0748 / 105.0374 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 222.0745 / 111.0372 |
| fri-query | — | 212.8511 / 106.4255 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `batch-combination`.

### eight_input profile 1

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.9125 / 113.4563 |
| deep-ali | 218.9888 / 109.4944 | 214.9013 / 107.4507 |
| ldt-query-phase | 443.6866 / 221.8433 | — |
| ldt-commit-phase | 224.0000 / 112.0000 | — |
| batch-combination | 227.0002 / 113.5001 | 214.3227 / 107.1614 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 211.3226 / 105.6613 |
| fri-query | — | 213.1080 / 106.5540 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-folding`.

### eight_input profile 2

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 227.2996 / 113.6498 |
| deep-ali | 218.9888 / 109.4944 | 215.2883 / 107.6442 |
| ldt-query-phase | 459.5268 / 229.7634 | — |
| ldt-commit-phase | 222.4150 / 111.2075 | — |
| batch-combination | 227.0002 / 113.5001 | 215.4838 / 107.7419 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 210.8987 / 105.4493 |
| fri-query | — | 214.1331 / 107.0666 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-folding`.

### eight_input profile 3

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 227.3301 / 113.6650 |
| deep-ali | 218.9888 / 109.4944 | 215.3188 / 107.6594 |
| ldt-query-phase | 456.1936 / 228.0968 | — |
| ldt-commit-phase | 223.0000 / 111.5000 | — |
| batch-combination | 226.0002 / 113.0001 | 215.0754 / 107.5377 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 212.0752 / 106.0376 |
| fri-query | — | 212.8511 / 106.4255 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-folding`.

### root profile 1

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.9125 / 113.4563 |
| deep-ali | 218.9888 / 109.4944 | 214.9013 / 107.4507 |
| ldt-query-phase | 443.6866 / 221.8433 | — |
| ldt-commit-phase | 224.0000 / 112.0000 | — |
| batch-combination | 227.0002 / 113.5001 | 214.3227 / 107.1614 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 211.3226 / 105.6613 |
| fri-query | — | 213.1080 / 106.5540 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-folding`.

### root profile 2

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 227.2996 / 113.6498 |
| deep-ali | 218.9888 / 109.4944 | 215.2883 / 107.6442 |
| ldt-query-phase | 459.5268 / 229.7634 | — |
| ldt-commit-phase | 222.4150 / 111.2075 | — |
| batch-combination | 227.0002 / 113.5001 | 215.4838 / 107.7419 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 210.8987 / 105.4493 |
| fri-query | — | 214.1331 / 107.0666 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-folding`.

### root profile 3

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 227.3301 / 113.6650 |
| deep-ali | 218.9888 / 109.4944 | 215.3188 / 107.6594 |
| ldt-query-phase | 456.1936 / 228.0968 | — |
| ldt-commit-phase | 223.0000 / 111.5000 | — |
| batch-combination | 226.0002 / 113.0001 | 215.0754 / 107.5377 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 212.0752 / 106.0376 |
| fri-query | — | 212.8511 / 106.4255 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-folding`.

## Blocking comparison and next extraction

Without the proposed batch-grinding site, the strongest recursive comparison
found in this search reaches only 96.7668 quantum bits after the complete
envelope loss. It fails the selected target; increasing queries does not
remove that batching bottleneck. Leaf profiles need no new batching grind in
this screen. The recursive candidates require a reviewed, verified extra site
or a different justified argument/shape. No existing q92 inheritance is valid.

After D8 correctness, record actual tables, constraints, degrees, quotient
chunks, hiding extensions, preprocessing keys, opening powers, lookup shapes,
FRI schedules and every checked grinding site. Repeat the full screen and
composition analysis. Only then measure passing profiles under the hard limit.
A single commitment-collision term is the estimator's ideal cap, not a complete
count of adaptive hash oracle calls; multi-target hash/transcript and recursion
composition losses remain independent review requirements.
