# Native V1 Monetary Rules

Status: selected native monetary rules with implemented integer accounting,
revised proof relations and engineering-frozen proof parameters. The accounting
reference is `crates/core/src/v1_economics.rs`. Fresh actual-AIR reports and EPYC
measurements qualify the revised isolated profiles; required CI, public-key
reproduction, durable wallet/network integration and independent review remain
separate gates. The legacy issuance module and retained seven-node network
keep their existing rules.

## Units and emission

One SIP is 100,000,000 atoms. All consensus amounts, percentages, heights and
rounding use checked integers. There is no secondary denomination conversion.
The native target interval is 300 seconds. For positive block height `h`:

```text
epoch(h) = floor((h - 1) / 4032)
r[0] = 3,394,524,515 atoms
r[e + 1] = max(100,000,000, floor(r[e] * 4,268,204,354 / 2^32))
subsidy(h) = r[epoch(h)]
```

The initial reward is exactly 33.94524515 SIP; 33.945 SIP is an abbreviated
description, not a replacement constant. Blocks 1 through 4,032 have the initial
reward. The first decay applies to block 4,033. The tail is exactly 1 SIP per
five-minute block, equivalent to 20,000,000 atoms per 60 seconds. No finite
supply cap is implied by a permanent positive tail. Actual calendar timing
varies with PoW production.

## Subsidy allocation and rounding

Let `S` be this block's subsidy, `P` the pool balance before this block, and
`M` the miner's base allocation. Compute these values in order:

```text
T = floor(S / 10)
F[i] = floor(T * basis_points[i] / 10000)
F[team] += T - sum(i) F[i]
C = floor(3 * S / 100)
M = S - T - C
P1 = P + C
```

The development-fund registry contains 1–32 wallets. Every share is a positive
integer number of basis points, and shares must sum to exactly 10,000. The
ordered ML-DSA-65 public keys, shares and explicit development-team wallet
index are fixed in canonical genesis parameters. Duplicate or zero public
keys, an invalid team index, a count/key mismatch or invalid share sum are
rejected. The team wallet receives the distribution residue after all
per-wallet floors. No V1 mechanism replaces keys, recipients or shares.

The actual launch recipients, wallet count and shares remain unconfigured.
New-network production fails closed until a complete configuration exists.
Synthetic test registries do not select a launch allocation. The native
configuration and ledger have new versioned encodings; old engineering stores
are rejected without migration. Retained legacy chain parameters and their
`DevFundKeys` structure remain separate compatibility interfaces.

The Holder pool receives 3%; the miner receives the residual, nominally 87%.
Fees are private transfers, not subsidy: their full sum goes to the producing
miner and never enters this percentage split.

Every block publicly names exactly one mode. The producer must require an
explicit `reward_mode = voyager` or `reward_mode = holder` on initialization;
there is no default. Changing the setting affects only subsequently created
templates. An in-flight template retains the mode bound at its creation.

| Mode | Immediate subsidy note | Locked subsidy notes | Burn | Additional pool credit |
| --- | --- | --- | --- | --- |
| Voyager | `M - floor(5*M/100) - floor(20*M/100)` | None | `floor(5*M/100)` | `floor(20*M/100)` |
| Holder | `M - 4*floor(M/10) + floor(P1/4032)` | Four notes of `floor(M/10)` each | Zero | Zero |

For Voyager, the post-block pool is `P1 + floor(20*M/100)` and no claim occurs.
For Holder, first include this block's 3% pool credit, then pay
`floor(P1/4032)` and retain the remainder. Empty pools and sub-4,032-atom
balances require no special rounding exception. The pool has no private key.

Settlement adds the entire private transaction-fee sum to note zero. Voyager
has one reward note; Holder has note zero plus four locked notes. Note zero,
including a Holder pool claim and fees, becomes spendable at `h + 24`. This is
the normal reward maturity, not a second Holder lock. The four Holder subsidy
notes unlock at `h + 52,560`, `h + 105,120`, `h + 157,680` and `h + 210,240`.
Their indices bind distinct reward randomness/nullifiers. Each reward asset
must be the all-zero SIP asset ID. A different count, amount, index, asset or
unlock height must fail validation.

## Locked-note spending

Every note commitment and encrypted note plaintext bind the u64 unlock height.
Ordinary unrestricted notes use zero. For each nonzero input the transaction
AIR requires `unlock_height <= snapshot_height`, where the height comes from the
trusted canonical snapshot referenced by that proof. Membership, ownership,
asset balance, fee and nullifier checks remain mandatory under their existing
rules. A note cannot be unlocked early by changing its ciphertext, witness,
snapshot selector or public field. An old snapshot can delay spendability; the
current wall clock or current tip cannot make that snapshot newer.

Wallet recovery must reconstruct all note fields, including unlock heights,
from authenticated ciphertexts and reconcile spent status against permanent
nullifiers. The wallet shows available and locked balances by asset, lists
scheduled batches and the next unlock, and labels date estimates as estimates
from block intervals. After maturity, wallet preparation delays use of every
nonzero-unlock note by a private six-hour to three-day interval, including when
inputs are selected explicitly. Scheduling and small-note consolidation remain
local policy; they cannot bypass a consensus lock or change proof validity. See
the [wallet protection design](v1-wallet-protection.md).

## Development-fund vesting and spending

For every configured fund wallet and each of its credits `F` created in block `h`:

```text
direct = floor(F / 2)
vested = F - direct
days(H, h) = min(1461, floor(max(H - h, 0) / 288))
unlocked(H, h) = (direct if H >= h + 24 else 0)
                 + floor(vested * days(H, h) / 1461)
```

Thus each credit has its own 1,461-day height-based schedule. A protocol day is
288 blocks. Day zero releases no vested amount; the last day releases every
remaining atom. This replaces the old five-year native design. Each configured
wallet has independent entitlement, unlocked/spent counters and expenditure
records under its immutable share. There is no aggregate unlocked-minus-spent
budget. Blocks accrue balances without creating an output for every wallet.
Only an authenticated claim creates a payout note. The native limit is eight
signed claims per block, independent of the 32-wallet registry limit. Each
claim advances that wallet's counter and consumes only its own allowance.
Multiple claims in the same block use the updated candidate balance, so neither
splitting claims nor alternating wallets can bypass an allowance.

A block first advances its candidate economic state to height `H`, including
maturity and vesting, then checks expenditures. Each positive payout requires
the account's ML-DSA-65 signature, the next account counter and
`amount <= unlocked_total - spent_total`. Verify network, account, recipient,
amount and counter before atomically consuming the authorization and creating
the payout note. Arithmetic failure, replay or excess spending rejects the
whole transition. No unsigned accounting helper grants spending authority.
The testnet asset-issuance fee is a separate transfer to its configured
50-SIP development-fund destination; it is not newly issued subsidy.

## Supply invariant and reorganization

Maintain cumulative gross subsidy issuance `I`, cumulative subsidy credited to
miner reward notes `R`, pool balance `P`, cumulative burn `B`, and every
configured fund wallet's cumulative subsidy entitlement `F[i]`:

```text
I = R + P + B + sum(i) F[i]
```

`R` is a lifetime subsidy-credit counter, not the current unspent note set.
Pool claims move value from `P` into `R`. Fund payouts transfer an existing
entitlement into a note and do not increase `I` or get counted again in `R`.
Fees, payments and asset issuance cannot create SIP subsidy. Issued assets
have separate declared-supply accounting.

The public scheduled locked-subsidy measure includes immature reward notes
and remaining prescribed Holder batches. It cannot reveal the total locked
amount in arbitrary private transaction notes. The scheduled circulating
measure subtracts burn, pool, scheduled reward locks and unreleased fund
entitlements from gross issuance; it is not a claim about lost keys, private
holdings or immediately available market supply.

Production, validation, replay, reorganization and public audit use one shared
integer transition. Pool, burn, reward schedules, fund entitlements/unlocks,
spending counters, notes and roots roll back atomically with the replaced
branch. An unchanged cumulative-work/depth-24 reorganization policy does not
permit retaining economic state from an orphaned block.

## Deterministic projections

These are exact emission-schedule sums, independent of reward-mode choices.
A projection year is 365 protocol days or 105,120 blocks; no wall-clock launch
date is assumed. They are not observed long-running network results.

| Protocol year | Cumulative gross issuance (SIP) |
| ---: | ---: |
| 1 | 3,303,016.40337408 |
| 4 | 10,519,407.34229376 |
| 10 | 17,659,667.69721792 |
| 20 | 21,120,931.62237312 |
| 40 | 23,248,826.23548096 |

The tail begins at epoch 564, block 2,274,049: about 21.6329 protocol years
from genesis. Gross issuance immediately before that block is
21,318,074.23548096 SIP. The constant tail creates 105,120 SIP per protocol year,
about 0.493103% of the gross amount at tail entry; that ratio then decreases as
gross issuance grows. Burn, pool holdings and mode-dependent lock schedules
change the distribution, not the gross schedule.

## Executed accounting simulation

The remote release-mode deterministic test advanced 2,102,400 consecutive production
heights with mixed Voyager and Holder modes. It checked supply conservation at
every height, cross-checked gross issuance against the epoch projection, and
checked the remaining reward-lock schedule. The
[numeric evidence](../crates/core/artifacts/v1-economics-simulation.json)
records the source identity and exact reproduction command.

| State after 20 protocol years | Atoms |
| --- | ---: |
| Cumulative gross subsidy | 2,112,093,162,237,312 |
| Cumulative miner subsidy credits | 1,854,911,800,239,910 |
| Holder pool balance | 125,271,865,958 |
| Cumulative burn | 45,846,774,833,460 |
| Scheduled locked subsidy | 3,396,010,239,013 |
| Cumulative fund entitlements | 211,209,315,297,984 |
| Unlocked fund entitlements | 209,476,713,447,456 |
| Spent fund entitlements | 93,912,546,485,906 |

The test uses 24 synthetic wallets: 23 shares of 400 basis points and a
team wallet with 800 basis points at index 23. Every height checks supply
conservation; the final entitlement and unlocked components of every wallet
also match an independent per-deposit oracle. Randomized mode choices and
wallet claims exercise separate balances and counters. The evidence lists
every wallet; it selects no launch recipient or share.

Scheduled locked subsidy is a subset of miner credits; unlocked and spent
fund amounts are subsets of fund entitlements. These subsets must not be
added again in the supply sum. This is an executed accounting simulation,
not a long-running network or proof-resource qualification.

## Engineering timing and acceptance

A distinct resettable engineering genesis may compress Holder unlock offsets,
for example to 60/120/180/240 blocks, and the fund vesting duration. The
canonical network parameters must bind that choice. Reward maturity remains
24 blocks, issuance epochs remain 4,032 blocks and production constants do not
change. Reject an undeclared timing substitution or cross-network artifact.

Before external review, complete test-first exact-allocation, pool-order and
rounding tests; before/at-unlock AIR rejection tests; mode/reward mutation
checks; per-wallet fund maturity/linear release/overdraft and signature/counter tests;
exact basis-point sums, explicit team residue and isolation between wallet spending budgets;
atomic reorganization tests; tail-threshold tests; and a deterministic
20-year mixed-mode block simulation with supply conservation at every height.
Publish actual results and source-bound reports after execution. No result is
implied by listing this acceptance scope.

The [revised actual-AIR scan](v1-multi-asset-evaluation.md) uses pinned
`p3-security=0.9.0-rc.2` and 39 fresh EPYC 7763 process-tree scopes. Selected
transaction b7/q41/g20 generates in 1.531155438 / 1.429902190 / 1.462877730
seconds with four workers. Quantum-halved Johnson challenge union is
81.692218869 bits, classical conjectured union is 185 bits and selected W24
BHT collision ledger is 123.333333333 bits. The 655,360-byte body cap is
11.2983% above the largest selected body, 588,832 bytes across both worker
groups. The maximum charged process-tree peak is 525,234,176 bytes; one-worker
verification median is 17.006900 ms. This is not independent verifier-memory
or whole-node acceptance.

Fixed-576 revised settlement generates in 5.523829281 seconds median with four
workers, maximum body 520,203 bytes and charged peak 3,161,432,064 bytes.
Three-note issuance generates in 0.639979907 seconds median, maximum
four-worker body 280,401 bytes and charged peak 211,423,232 bytes. Both retain
independent 524,288-byte caps and pass their own 80-bit quantum screens.
The current source-bound reports replace earlier baseline qualification;
required CI and deterministic public-key reproduction remain release checks.

Keep 576 positions, two-second transaction trials, at least 80 quantum-halved
Johnson/challenge bits, classical conjectured security at least 128 bits and
selected BHT collision resistance at least 80 bits. Any parameter/layout
revision requires fresh screening and equivalent measurements. Unchanged proof
caps preserve the complete conditional 43-Mbps uplink and rolling-storage
budgets; do not lower them solely from smaller sampled bodies. Independent
review includes snapshot-height locks, mode-dependent settlement, Holder
pool/burn, fund vesting/spending, recursion-free composition and hiding.
Launch recipients and shares remain unconfigured; the native registry supports
up to 32 wallets and fails closed without a complete genesis allocation.
