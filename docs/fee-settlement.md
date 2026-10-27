# Confidential Fee Settlement for Route A V1

Status: selected V1 design direction; research and measurement gate open. This
document specifies Scheme B, a confidential settlement mechanism for the
native, non-recursive transaction route. The direction is selected for V1, but
it is not an activated consensus rule and no implementation parameter has
been approved. The retained seven-node network is unchanged.

## Goals and boundaries

Route A broadcasts one native proof with each fixed-shape transaction. Nodes
verify the proof before mempool admission, and a block carries compact
references to those transactions. A transaction always has two inputs and two
outputs. Real and padding transactions use the same public byte length and the
same proof envelope shape. A real transaction commits either the standard or
priority fee; a padding transaction commits zero. The commitment, rather than
the fee amount, is the only fee value exposed on chain, so the two cases remain
indistinguishable from public data.

The settlement mechanism must meet four requirements:

1. The proof must establish the selected fee rule without publishing the tier
   or amount for an individual transaction. The public statement contains only
   a randomized fee commitment.
2. A block must credit the miner with the exact issuance reward plus the fees
   of its included transactions, including zero-fee padding, exactly once.
3. A node must reject omission, duplication, overflow, replay, and forged
   settlement data before changing state.
4. No public field may classify a slot as real or padding, or make an
   individual fee identifiable through a deterministic value.

This design uses a separate native block-level settlement proof. It does not
recurse over transaction proofs and does not replace transaction proof
verification. The proof is the selected V1 direction for making the private
sum publicly checkable, but its circuit size, proof size, generation cost,
memory cost, and security must be measured before it is included in the V1
production scope.

## Private fee binding in a transaction proof

Let `b` be the base fee committed by the accepted anchor snapshot. For a
transaction with tier bit `t` and dummy bit `d`, the private fee is:

```text
f = 0                         if d = 1
f = b * (1 + 3 * t)            if d = 0 and t is 0 or 1
```

The transaction AIR receives `f`, `d`, `t`, and a fresh 256-bit blinding value
`r` as private witness data. It computes a fixed-width field digest:

```text
F = Poseidon2_fee_v1(
      suite_id || network_id || transaction_binding || anchor_snapshot || f || r)
```

`transaction_binding` is the digest of the canonical 1,742-byte public
transaction data and the fixed proof context. `anchor_snapshot` identifies
the accepted canonical recent-root snapshot and its fee schedule. Accept only
the newest 4,096 canonical snapshots; remove orphaned or expired snapshots and
evict affected pending transactions for wallet reproof. This window is separate
from the depth-12 anchor tree and may accept correspondingly older fee schedules.
Historical replay uses the window at the block being validated. The domain tag,
field-limb order, padding, and transcript framing are fixed before an AIR
freeze. The chosen D8/W24/12-element suite is used for this relation; a
separate hash circuit must not be introduced implicitly.

The proof statement publishes only `F` in a fixed-size statement slot and omits
the fee limbs, tier bit, dummy bit, and `r`. With the D8/W24/12-element suite,
the canonical commitment occupies 48 bytes (twelve little-endian 32-bit
elements). This is an incremental proof-statement/relay-envelope field; it is
not part of the 1,742-byte permanent transaction encoding. The 48-byte `F` field
must nevertheless remain in the retained on-chain transaction statement after
the proof body is pruned; absent an explicitly amortized block-context format,
the public record is therefore 1,790 bytes before relay and settlement
overhead. The AIR proves all of the following:

- the two inputs and two outputs satisfy the transaction relation;
- every positive-amount input proves ownership and commitment-tree membership;
  a zero-amount dummy input uses the canonical dummy witness and skips that
  membership check;
- nullifiers are derived for every input, including zero-amount dummy inputs;
  transaction-level uniqueness is checked in the relation, while mempool and
  consensus admission check conflicts against the candidate and prior state;
- `d` and `t` are boolean and the formula above holds with checked carries;
- `F` is the Poseidon2 digest of the private values and the canonical public
  transaction binding;
- the accepted anchor snapshot supplies `b` and the recent-root membership.

The same relation is used for real and padding transactions. A padding witness
uses zero-amount dummy inputs, zero-valued outputs and `f = 0`; it does not
carry a special public marker. Its nullifiers remain protocol values and must
be unique just like real transaction nullifiers. A wallet samples `r`
independently for every transaction,
including any transaction that happens to use the same tier. Reusing `r` is a
wallet error and must be rejected by the wallet; the protocol does not use the
value of `F` as a fee identifier.

`F` is bound to the transaction and network context, so a proof or fee witness
cannot be moved to a different public transaction, network, suite, or anchor
snapshot. The 1,742-byte public transaction encoding remains unchanged. `F`
belongs to the fixed proof statement/envelope and must be included in the
proof-size, relay, and denial-of-service ledger; it is not silently added to
the public transaction bytes.

### Supplying a settlement witness to the miner

A transaction proof deliberately does not reveal `f` or `r`. A miner therefore
cannot create the block settlement proof from the public proof alone. This is a
real protocol dependency, not an implementation detail. Scheme B places a
fixed-size fee-opening sidecar alongside the transaction in the mempool. The
sidecar contains `(transaction_binding, f, r, dummy, priority)` and uses the
same canonical encoding for real and padding transactions. It is available to
the block producer for ordering and settlement; the opening is never written
to the block or public chain.

Sidecars do not carry an additional signature or application-level encryption
layer. Any node that receives one recomputes the fee commitment `F_i` and
checks the transaction binding before forwarding or using it for settlement.
Missing sidecars, an opening that does not match `F_i`, and a sidecar bound to
another transaction are rejected before mempool or consensus state changes,
and the bounded relay-abuse diagnostic records the peer. Confidentiality and
peer authentication for sidecar transport come from the planned X25519 +
ML-KEM connection handshake; the sidecar protocol does not introduce a second
key schedule. The handshake and reconnect design remains a separate network
gate.

If a valid sidecar is unavailable, block production aborts rather than
guessing an opening or weakening the settlement proof. Until the sidecar
codec, handshake coverage, and rejection tests are reviewed, Scheme B remains
an evaluation direction and is not an activated V1 consensus rule.

## Block settlement statement

For a block with `M` fixed positions, the miner constructs a private witness
for every position, including generated padding. The settlement proof binds the
following public values:

- block header and network/suite identity;
- the ordered compact-reference digest for each of the `M` positions;
- the corresponding transaction binding and fee commitment `F_i` for each
  position;
- the miner output commitment and its fixed-format ciphertext;
- the issuance reward recomputed from the block height.

The proof keeps the `f_i`, tier bits, dummy bits, blindings, and total private.
It proves:

```text
F_i = Poseidon2_fee_v1(context_i || f_i || r_i)       for every i
f_i is exactly 0, b_i, or 4*b_i                      for every i
T   = sum(i = 0..M-1) f_i                            (checked integer sum)
miner_amount = issuance_reward(height) + T            (checked integer sum)
miner_commitment = NoteCommit(miner_amount, miner_blind)
```

`T` is not a public block field. The miner note commitment and ciphertext are
the only settlement result. The proof binds them to the exact included
transaction list and to the height-derived reward. The public block therefore
does not expose a fee total, a paid-slot count, or a per-transaction fee.
The phrase "sum of commitments" means that the proof opens each `F_i` to its
private fee witness and proves the integer sum of those openings; the digest
values themselves are not arithmetically added.

The settlement proof is padded to the selected fixed capacity and has a fixed
shape for that capacity. A 16-position group is the smallest unit; an empty
position is represented by an ordinary fixed-format padding transaction and an
ordinary fee witness with `f = 0`. The proof must not contain a variable-length
list whose length reveals the number of real transactions.

This proof is intentionally described as a block-level relation rather than a
recursive aggregation of the transaction proofs. It may reuse their public
statements, but it must not accept a transaction merely because the settlement
proof claims its fee. Each transaction proof is still verified independently
and the settlement proof must bind to the resulting statement digest.

### Required settlement evaluation

Before Scheme B is admitted to the V1 scope, implement a fixed-capacity
settlement circuit and measure capacities 64, 128, 256, 384, 512, and 576.
The report must include the row and column shape, constraint count and degree,
proof and envelope bytes, verifier time, peak charged memory, and generation
time on the qualified machine. The 576-position case is the acceptance gate:
run it three times with the same fixed configuration and report the median and
each stage's peak memory. Include witness decoding, fee ordering, settlement
proving, and payout construction in the generation measurement; one-time
circuit preparation may be excluded only when it is performed at service
startup and remains resident. A result that exceeds the V1 time or memory
budget pauses the route and does not silently lower the privacy or proof
requirements.

The per-transaction accounting must list the 48-byte `F_i` commitment and the
fixed-size fee-opening sidecar separately from the 1,742-byte permanent public
transaction encoding, totaling 1,790 permanent bytes. Preserve the fixed
`MAX_LEAF_PROOF_LEN = 524288` (512 KiB). Mempool byte caps, concurrent-verification
limits and complete relay capacity require the production codec ledger and
qualified transaction/576-position settlement measurements.

## Mempool and block validation flow

1. Decode the fixed transaction bytes and proof envelope with bounded lengths.
   Reject unsupported network, suite, format, or proof sizes before expensive
   work.
2. Recompute the canonical transaction binding and verify the native proof
   against the trusted verifier key. The verifier obtains `F` from the
   decoded statement, never from a peer-selected statement.
3. Check duplicate nullifiers against the candidate state and the mempool's
   reservation table. Admission is atomic: a failure changes neither table.
4. Retain the verified transaction binding, `F`, proof digest, and nullifier
   reservations. The miner's private mempool sidecar retains the fee opening
   for ordering and settlement. A node validates the sidecar's transaction
   binding and commitment before retaining it; the node does not log `f` or
   classify the slot.
5. The miner obtains a validated sidecar for every position. It constructs a
   fixed-capacity block, recomputes the issuance reward from the candidate
   height, includes the miner output exactly once, and produces the settlement
   proof. Missing or context-mismatched sidecar data aborts block production.
6. A receiving node verifies the header, compact references, every transaction
   proof, and the settlement proof. It checks that every `F_i` and transaction
   binding occurs exactly once, that every referenced transaction is present,
   and that all nullifiers are unique and unused in the parent state.
7. The node verifies the miner output commitment/ciphertext against the
   settlement proof, applies the common integer-only state transition, and
   only then releases reservations and persists the block.

The producer and validator call the same transition function. Any failure
leaves the state, mempool reservations, fee accounting, and wallet journals
unchanged.

## Rejection and abuse cases

The implementation test plan must reject each case below before state mutation:

- changing any public transaction byte, compact reference, proof statement,
  `F_i`, anchor snapshot, network identity, or suite identifier;
- replacing a transaction proof while retaining its `F_i`, or replacing `F_i`
  while retaining the proof;
- omitting a position, adding a second copy, reordering references without
  rebuilding the bound settlement proof, or using a transaction in two
  positions;
- using a duplicate nullifier within one transaction, in two transactions in
  the block, in the mempool, or against confirmed state;
- selecting a fee other than zero, `b`, or `4*b`, changing the anchor fee
  schedule, or setting a non-boolean tier/dummy witness;
- producing a zero-amount input with a non-canonical dummy witness, or requiring
  a commitment-tree path for that input; zero-amount dummy inputs must skip
  membership while still producing a unique nullifier;
- claiming a non-zero fee commitment for a padding transaction, or a zero fee
  for a real transaction, including attempts to alter either opening after
  mempool admission;
- supplying a forged fee opening, a commitment that does not match its opening,
  or a settlement sum that differs from the fee portion of the miner reward;
- overflowing a fee limb, the per-position total, or `issuance_reward + T`,
  including carries at every boundary;
- claiming a miner amount that is not exactly the issuance reward plus the
  proved private sum, claiming it twice, or moving the miner output to another
  block height;
- reusing a settlement proof, `F_i`, or private fee witness in another network,
  block, suite, or anchor snapshot;
- omitting a sidecar, supplying a sidecar whose opening does not match `F_i`,
  or supplying a sidecar bound to another transaction;
- truncating, extending, or making any proof, transaction, settlement, or
  ciphertext encoding noncanonical; and
- presenting a valid transaction proof but a settlement proof generated from a
  different transaction set or capacity.

Tests must include malformed proofs and oversized inputs so that proof
allocation is bounded. They must exercise the maximum configured capacity and
the largest allowed `b` without relying on host integer overflow behavior.

## Privacy and accounting properties

The protocol exposes the transaction's ordinary public data, proof size, and
relay timing. It does not expose `f_i`, `t_i`, `d_i`, `T`, or a paid-slot
count. `F_i` is a randomized binding digest and is expected to be
computationally hiding under the selected Poseidon2 model; it is not a fee
amount and must not be treated as one by metrics or APIs. Wallets, relays, and
miners must not log or export `f_i` with transaction identifiers.

The fee-binding digest and settlement proof add fixed proof/envelope bytes and
verification work. Capacity, bandwidth, and mempool budgets must include those
bytes, plus the fixed sidecar and retransmissions. The existing 1,742-byte
transaction target alone is not a complete relay budget.

Settlement proofs and sidecars are retained for four weeks after final
confirmation to support reorg handling, archive/checkpoint verification, and
operational recovery. After that period, nodes delete the proof bodies and
sidecars. The public fee commitments `F_i` remain permanently with the
confirmed transaction; no fee opening is retained in the permanent record.

## Open gates before implementation

This design cannot be activated until the following are specified and tested:

- a fixed AIR layout replacing clear fee limbs with the private fee witness
  and `F` statement fields;
- a reviewed fixed-size sidecar codec and handshake integration that gives the
  block prover enough information to construct the private sum without
  exposing fee tiers on the public chain;
- a hash-based, quantum-accounted `NoteCommit` and `Poseidon2_fee_v1` domain
  specification, including the 256-bit blinding representation;
- a fixed-size settlement-proof construction and its cost at capacities 64
  through 576;
- a 576-position three-trial evaluation covering circuit size, proof bytes,
  generation time, verifier time, and per-stage peak memory;
- p3-security reports for the transaction and settlement relations under the
  selected quantum target;
- a proof/envelope byte ledger and DoS limits incorporating `F` and the
  settlement proof; and
- independent tests for duplicate, omission, overflow, replay, forged payout,
  forged openings, wrong commitment sums, non-zero padding fees, zero-fee real
  transactions, zero-amount dummy-input membership skips, missing sidecars,
  sidecar/transaction mismatches, sidecar commitment mismatches, and
  state-atomicity failures.

Until these gates pass, clear fee limbs in the research AIR and any existing
recursive fee total are measurement fixtures only. They must not be presented
as Route A V1 settlement or enabled on the retained network.
