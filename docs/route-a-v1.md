# Native Transaction Proof Design

Status: selected V1 direction; production AIR, codec, parameter selection and
node integration are not complete. Requirements below do not describe an
activated network. V1 selects Scheme B confidential fee settlement as its
direction; the mechanism is documented in [fee-settlement.md](fee-settlement.md)
and has a research reference model and fixed-capacity AIR/prover, but it is not
integrated into node or consensus paths. Witness delivery, security and
qualified-host capacity evaluation remain open. Open design issues explicitly
block a production AIR freeze and V1 inclusion.

## Scope and network boundary

V1 uses one native STARK proof per fixed-shape transaction. Wallets relay
transactions with proofs; nodes verify each proof before mempool admission.
Blocks identify transactions with compact references and retain their public
data without duplicating the proof body. Recursive aggregation and historical
proof compression are deferred to V2. Recursive merge and wrapper work is
paused while the native transaction route is evaluated.

The retained seven-node N=2 network is unchanged. The new route requires an
independent, resettable engineering network, new genesis, network identity,
directories and keys. It imports no retained notes, tickets, proofs or state.
No network launch is authorized by this specification. Historical verifier
activation is deferred until before mainnet.

The engineering block target is 300 seconds, with 64 through 576 transaction
positions in groups of 16. The minimum node uplink is 25 Mbps. Node integration,
block validity changes, pruning and checkpoint synchronization remain design
work until the production transaction AIR and parameter scan pass.

## Suite and security requirements

Use KoalaBear D8, standard Plonky3 Poseidon2 W24 and 12-base-element digests.
Canonical digest encoding is 48 bytes: twelve little-endian u32 elements, each
strictly below the KoalaBear modulus. D4/W16 proxy measurements cannot select
production parameters or resource limits.

Pin `p3-security` to `0.9.0-rc.2`. For the actual transaction AIR, require:

| Term | Screening requirement |
| --- | --- |
| Classical conjectured | At least 128 bits for the complete instance |
| Fiat–Shamir terms | At least 80 bits after halving the Johnson-bound term, including FRI queries and each enforced grinding site |
| Challenge-domain terms | At least 80 bits after halving, including OOD, DEEP, ALI and FRI folding |
| Merkle and commitment collisions | At least 80 bits under the selected BHT model |

The current diagnostic profile's approximately 81.9 quantum-halved Johnson bits
meets the selected 80-bit screen. Every future parameter change must retain at
least 80 bits; this screen does not complete production acceptance. See
[BHT accounting](bht-security-accounting.md) for the separate collision model.

Record every term, the weakest term, model assumptions, actual AIR dimensions,
constraint degrees, hiding rows, quotient chunks and batched-opening geometry.
A query/grinding arithmetic score is not a complete bound. Do not count a
nonce unless the production verifier enforces it at the specified transcript
position. Estimator screening is not an independent quantum soundness theorem;
external review must assess the selected accounting and implementation.

## Existing relation and incomplete coverage

The research D8 slot AIR contains private spend-key/note fields and constraints
for ownership, note commitments, input membership, nullifiers, conservation,
value ranges, output rho and unlock heights. It is a reusable starting point,
not the completed production transaction relation. Its accumulator leaf exposes
fee limbs and delegates recent-root membership to a parent relation. Moving
that path into a native transaction proof still requires private fee settlement
and enforcement of the selected canonical snapshot lifetime.

The existing relation binds a ciphertext digest but does not constrain ML-KEM
encapsulation coins or shared secrets, the sender change secret/KDF, AEAD keys,
nonce generation, plaintext encryption or authentication-tag computation.
These private encryption fields are not proven consistent with output note
openings. Public-data mutation tests establish substitution resistance only.
Native stateful nullifier checks, bounded decoding, wallet erasure and transport
source privacy also remain separate requirements. Iterative code and test
milestones do not establish complete AIR coverage or production acceptance.

### Isolated implementation boundary

The native experiment includes a prepared proof-shape decoder that validates
canonical fields, fixed vector dimensions, FRI paths and complete byte
consumption before dependency deserialization. The body limit is 524,288 bytes;
a separate 4-MiB declared-vector budget bounds requested payloads and vector
headers, not process RSS. Structural acceptance always requires subsequent
cryptographic verification against the locally reconstructed statement.

The canonical snapshot pool resolves trusted roots, checks proofs, reserves both
nullifiers and applies atomic expiry/reorganization eviction. Its caller still
validates canonical blocks, enforces reorganization depth and confirmed-state
conflicts, and supplies authoritative refill history. Integration into the node,
outer relay-envelope bounds and byte/CPU/in-flight quotas remain incomplete.

Wallet helpers authenticate both constructed outputs before returning a checked
pair, retain a zeroizing per-payment opening and generate genuine ephemeral-key
padding ciphertexts. The diagnostic scanner exercises those helpers with
synthetic notes and temporary keys. Durable protected receipt storage,
recoverable change-key management, receipt disclosure controls and the wallet
broadcast path remain integration requirements.

## Fixed transaction relation

Each transaction has two inputs and two outputs. The relation must constrain
both inputs independently, including ownership, nullifier derivation, value
ranges and unlock conditions. A positive-amount input must prove commitment-tree
membership; a zero-amount input uses a canonical dummy witness and skips the
membership check so a miner can construct padding without owning a note. The
zero-amount input still derives a nullifier, and nullifier uniqueness is
enforced within the transaction, across the block and against prior state. The
relation must enforce value conservation, output-seed derivation and
standard/priority fee rules. Native mempool and consensus checks also reject
conflicts across transactions and prior state; those stateful checks cannot be
replaced by the transaction AIR.

The note commitment tree has depth 40. The recent-root tree has depth 12 and
4,096 leaves. An anchor leaf commits to the commitment root, anchor height and
fee-schedule data with a fixed domain tag. Membership in this tree moves into
the transaction AIR. The anchor entry, height, fee witness and membership path
are private. The public proof statement contains the recent-root tree root,
network/suite/format identity, transaction public-data binding and any fee
settlement binding required by the final design. It does not expose the
individual anchor entry or path.

### Canonical snapshot lifetime

Accept the newest 4,096 canonical-chain snapshots, inclusive: the snapshot
4,095 blocks behind the tip is accepted; the one 4,096 blocks behind it is
rejected. At the 300-second target the window spans approximately 14.22 days.
This is a deterministic block-based rule, not a wall-clock timeout. A proof
selects a snapshot by canonical block identity; the verifier resolves the
recent-root-tree root from trusted chain state before verifying the proof.
A root supplied by a peer is not a trust source. The public-data digest binds
the selected height and 32-byte block identity with explicit domain and presence
framing. The verifier reconstructs that context from its canonical selection;
same-root replacement snapshots still require a new proof. This changes the
statement values, not the AIR columns or path depth.

The accepted snapshot window and the tree's 4,096 anchor leaves are separate
bounds. The existing depth-12 AIR path is unchanged. Since an accepted older
snapshot contains older anchors, the combined boundary can admit an anchor
8,190 blocks behind the live tip, approximately 28.44 days. Fee schedules are
committed by the anchor entry and may have corresponding staleness. Capacity,
fee-policy and wallet-expiry analysis must include this effect.

On expiry or reorganization, remove unavailable snapshot identities and evict
all pending transactions referencing them; release their nullifier reservations
and return a reproof condition to the wallet. Do not silently reinterpret an
old identity as a replacement at the same height. A shorter-chain reorganization
may require previously expired snapshots to refill the window from authoritative
canonical history; incomplete history fails closed. Validation and historical
replay use the snapshot window at the candidate block's canonical parent, not
the current live window. Reproof uses fresh proof randomness and the canonical
transaction/nullifier conflict rules.

Root selectors and any unamortized envelope bytes remain outside the
1,790-byte public-body ledger and must be counted in relay/admission budgets.
Tests must accept the 4,096th-newest snapshot, reject the 4,097th, reject orphaned
identities, preserve state on invalid chain replacement and evict affected
pending transactions atomically.

### Fee settlement and padding privacy: Scheme B V1 direction

The implemented recursive relation permits zero fees for all-dummy slots and
standard or priority fees for other slots; the aggregate proof binds the
miner's collected fee total. Native per-transaction proofs remove that
aggregate settlement mechanism. Publishing a zero/nonzero fee, individual fee
amount, fee opening or independently recognizable fee claim identifies filler
transactions or fee tiers. Equal byte lengths alone do not prevent this leak.

V1 selects Scheme B as its fee-settlement direction. Each transaction exposes
only a randomized fee commitment `F_i`; a real transaction commits the private
standard or priority fee and a padding transaction commits zero. Wallets place
the fee opening in a bounded mempool sidecar so a block producer can order
transactions and build settlement; the opening is never written in clear to
the block or chain. A separate native,
non-recursive block proof binds every `F_i` to its opening and proves that the
private sum equals the fee component of the miner reward note. Real and padding
transactions share the same public shape, including dummy nullifiers.

The direction is not yet included in the V1 production scope. The sidecar has
no standalone signature or second encryption layer: nodes recompute `F_i` and
the transaction binding on receipt, while confidentiality and peer
authentication come from the planned X25519 + ML-KEM connection handshake.
Missing sidecars, mismatched openings, and sidecars bound to another
transaction are discarded before state mutation and recorded as bounded peer
abuse. The settlement design requires a reviewed sidecar codec, a reviewed
and frozen
AIR layout, a security report, and qualified-host 64--576 capacity measurements,
with a three-trial 576-position result reporting proof bytes, generation and
verification time, and per-stage peak memory. The four required rejection
cases are explicit:
wrong commitment sum versus the miner reward, forged fee opening, non-zero
padding fee, and zero-fee real transaction. A ciphertext or unbound private
fee witness is insufficient. The 1,742-byte target must not silently exclude
the 48-byte commitment, fee sidecar, proof statement, or relay-envelope
bytes.
Standard and priority amounts remain reward-linked: standard is
`floor(reward / 1,000)` and priority is four times standard. Variable bids are
outside scope. The production AIR cannot be frozen until collection,
non-duplication and padding indistinguishability have a complete, reviewed
design. The research design does not close this gate.

## Encryption and ciphertext binding

The recipient output uses one ML-KEM-768 ciphertext per transaction. The change
output uses ChaCha20-Poly1305 under a 256-bit key derived from sender secret
material with a domain-separated BLAKE3 KDF. The sender secret must use its own
wallet derivation domain and must not reuse an ML-KEM shared secret.

The selected change derivation is:

```text
change_key = BLAKE3-derive_key(
    "siworld route-a change-v1",
    sender_change_secret || change_commitment || output_index)
```

The result is exactly 32 bytes. Use a fresh 12-byte change nonce and authenticate
network, format version, output index and commitment as associated data. Freeze
canonical associated-data framing, nonce generation, recipient KDF domains and
secret erasure behavior before implementation. The recipient's fresh KEM secret
may use the existing one-use zero-nonce construction only under a separately
pinned domain and key-use rule.

A public node without an encryption key cannot verify a ChaCha20-Poly1305 tag.
Canonical decoding checks lengths and field encodings, not decryptability.
Binding every ciphertext byte and view tag to a public digest in the AIR
prevents substitution after proving, but does not prove that the ciphertext
encrypts the corresponding valid output note. Recipient-side tag verification
and rebuilt-commitment checking remain necessary.

V1 selects public-data substitution resistance. Complete ML-KEM and
ChaCha20-Poly1305 encryption correctness is outside the AIR and remains future
research. AEAD associated data must not be described as node-verifiable
encryption correctness. The recipient verifies the tag, decodes the note and
recomputes its output commitment before accepting a payment.

Before broadcast, the sender must decrypt and check both locally constructed
outputs and compare the recovered note commitments. For the recipient output,
the sender uses the shared secret obtained during encapsulation; it does not
possess or require the recipient's private decapsulation key. A failed self-check
must not produce a broadcastable transaction. Retain per-payment encapsulation
coins and the bound recipient/context in protected wallet storage so a selective
payment receipt can reproduce the KEM ciphertext and validate the opened note.
Do not publish or log receipts, coins or plaintexts. Receipt disclosure reveals
that payment and is not an anonymity-preserving public record. Never disclose
wallet master or change-secret material as a receipt.

Padding outputs must execute actual ML-KEM encryption against a fresh valid
ephemeral public key and the same change-encryption algorithm. Do not substitute
random bytes for a ciphertext. Test recipient decryption and commitment checking,
self-check failure before broadcast, receipt mismatch rejection, and identical
public lengths and encoding for real and padding outputs. Equal format is not
an independent indistinguishability proof.

Consensus verifies the byte-bound spend/value relation without an AEAD key.
A sender-created encryption error can make that output unusable for its intended
recipient, while the transaction remains subject to the same commitment,
conservation and nullifier checks. It does not make ciphertext decryptability a
consensus rule or cause unrelated state to become invalid.

## Public-data codec target

The selected wire layout is 1,742 public bytes per transaction, excluding the
native proof and proof/relay-envelope context. The current implementation uses
32-byte digests, two 1,344-byte ciphertexts and a 2,818-byte slot. It is not this codec.

Under Scheme B, each transaction statement adds one canonical 48-byte `F_i`
commitment (twelve D8 field elements). The commitment is public in the proof
statement and relay envelope, while the fee opening remains in the private
mempool sidecar. It is not part of the 1,742-byte base encoding, but it
is retained in the on-chain transaction statement after the proof body is
pruned; absent an explicitly amortized block-context format, the public record
is 1,790 bytes before relay and settlement overhead. Capacity and
denial-of-service accounting must include the 48-byte commitment, sidecar,
proof body, settlement proof, and retransmission reserve as separate ledger
entries.

Keeping the existing 240-byte encrypted plaintext padding while changing four
public digests to 48 bytes and replacing the second KEM ciphertext with a
12-byte-nonce symmetric ciphertext gives **1,806 bytes**. The selected exact
1,742-byte layout instead reduces both padded plaintext bodies to 208 bytes:

| Field | Count | Bytes each | Total bytes |
| --- | ---: | ---: | ---: |
| Input nullifier | 2 | 48 | 96 |
| Output commitment | 2 | 48 | 96 |
| Recipient ML-KEM-768 ciphertext | 1 | 1,088 | 1,088 |
| Encrypted padded note body | 2 | 208 | 416 |
| Poly1305 authentication tag | 2 | 16 | 32 |
| Change nonce | 1 | 12 | 12 |
| Output view tag | 2 | 1 | 2 |
| **Total** | | | **1,742** |

A D8 note body has an 8-byte value, 8-byte unlock height, 48-byte rho and
48-byte rseed: 112 bytes, with owner reconstructed by the recipient. The
208-byte format includes exactly 96 canonical zero-padding bytes. The recipient
ML-KEM output uses a zero nonce only with a fresh encapsulated secret for each
output; the change output carries the explicit 12-byte nonce above. Version,
suite and network identifiers live in the proof/relay envelope rather than
these 1,742 bytes. This is an implementation choice, not an assertion that the
codec is already implemented. Freeze byte order, output roles, canonical scalar
encoding and reserved bytes in the codec. Fee-settlement fields, proof root,
framing and transport overhead require a separate byte ledger; they cannot be
omitted from relay or DoS accounting. If those decisions require extra permanent
fields, revise the target rather than claim a false fixed length.

The recipient-KEM output and symmetric-change output have fixed roles in every
transaction, including filler transactions. Verify that these roles do not
identify real versus filler positions. The codec rejects truncation, trailing
bytes and noncanonical field elements, and the envelope rejects unsupported
versions before costly verification. Invalid AEAD tags are detected by the key
holder unless the final relation explicitly proves encryption correctness.

## Rejection tests before implementation

Write failing tests before adding each validation rule. The minimum matrix is:

1. Mutate every public field independently, including every nullifier and
   commitment limb, ciphertext byte ranges, view tags, public recent-root value,
   network/suite/format identity and fee-settlement binding.
2. Test both input paths, wrong anchor entry, wrong path sibling, wrong index,
   wrong root snapshot, expired snapshot, wrong fee schedule and inconsistent
   anchor height. The private path must never be accepted merely because the
   public root was supplied by the transaction.
3. Test invalid standard/priority tier selection, wrong fee arithmetic, carry
   and range failures, and any fee claim credited twice.
4. Repeat a nullifier within one transaction, across a candidate block and
   against confirmed state. Test mempool conflicts and reorg re-admission.
5. Alter ciphertext/public-data binding after proving. Separately test recipient
   AEAD rejection and commitment reconstruction; do not conflate it with a
   public node's proof check.
6. Test truncated, extended, noncanonical, wrong-suite and oversized encodings,
   wrong trusted key and invalid proof before any state mutation.

Shared production, validation and replay transitions must remain integer-only,
deterministic and atomic. Invalid input leaves state unchanged. Proof inputs
must never select an untrusted verification key. Use synthetic fixtures and
independent network identities.

## Production parameter scan and capacity gate

After the production relation and codec are complete, scan every
`log_blowup` in 4 through 8 with grinding in 16, 20 and 24. Select the smallest
query count satisfying all security terms for each actual configuration. Record
folding, commitment and batch grinding separately; varying one does not credit
an unchecked site. Only rows passing the full security screen proceed to
measurements.

Run three trials on one qualified machine per selected configuration. Record
proof-body and envelope bytes, one-core and four-core generation, single-core
verification, actual worker settings, stage times, charged-memory peaks and
failure attempts. Select the smallest canonical encoded proof whose four-core
generation is at most two seconds. Freeze source, dependencies, AIR shape,
trusted key, codec, security report and binary identities with the result.
Diagnostic rows do not freeze production parameters or admission budgets.

`MAX_LEAF_PROOF_LEN` remains **524,288 bytes (512 KiB)**. It is a fixed
proof-body wire maximum, independent of the largest observed sample. Bound
proof and transaction envelopes separately. The public-data ledger is
1,742 bytes plus the 48-byte confidential fee commitment, or **1,790 bytes**
per position; private sidecars and transport envelopes are additional.

At 576 positions per 300 seconds and three relay copies, maximum-size proofs
plus 1,790-byte public data require **24.24167424 Mbps**. Transfer takes
290.90009088 seconds on a 25-Mbps uplink, leaving 0.75832576 Mbps (3.0333%)
or 9.09990912 seconds per interval. This is a transaction-payload budget,
not full-network acceptance. Settlement proofs, sidecars, envelopes, framing,
missing-proof traffic and retransmissions outside the relay allowance must fit
the remaining margin and be measured before activation.

After the production relation and codec are frozen, if no eligible profile fits
524,288 bytes, first select a larger blowup from the complete scan. If none
fits, report a proposed reduction to **544 positions** with revised resource
budgets. This does not raise the proof maximum or activate a capacity change.
At 544 positions, the same maximum-size payload ledger requires 22.89491456 Mbps
and 274.73897472 seconds on 25 Mbps. No increase above 576 is adopted.

Mempool admission must enforce global/per-peer byte caps, bounded concurrent
verification, work/CPU admission and eviction before expensive verification.
No byte count alone bounds verification work or allocation on malformed proofs.

## Node and block design boundary

The following changes are proposed and are not implemented by this document:

- Verify complete native transaction proofs on mempool admission; cache success
  under the exact transaction, proof, root snapshot and trusted-key identity.
  A cached result never bypasses current nullifier or root-lifetime checks.
- Use groups of 16 with 64 through 576 total positions and a 300-second target.
  Producers generate valid filler transactions without publishing real/filler
  counts or fee classes. Final fee/padding design is a prerequisite.
- Relay compact block inventories with collision-safe transaction identifiers
  and bounded missing-transaction/proof retrieval. Reconstruct and authenticate
  the complete block before applying it. Missing data is not proof validity.
- Set the new route's local `MAX_REORG_DEPTH` to 24. Test depth 23/24/25,
  root-window boundaries and conflict re-admission. A deeper fork requires
  explicit checkpoint recovery rather than silent partial rollback.
- Retain transaction and settlement proofs, together with private fee sidecars,
  for four weeks **after final confirmation**, then delete them from the online
  proof store. Retain each public `F_i` commitment permanently with the
  confirmed transaction. At a 300-second target, 24 blocks correspond to
  two hours nominally; actual finality is a deterministic depth rule, not a
  wall-clock guarantee. Specify four-week expiry using deterministic chain
  metadata and a local deletion policy that cannot shorten required evidence.
- Preserve public transaction data and accepted state. Optional archival nodes
  retain the complete native proofs beyond online expiry. Independent replay
  from genesis requires the complete historical proof set, including its
  authenticated transaction data and trusted verifier identities. Archive
  availability is not a theorem that these data remain obtainable from every
  node.
- Define checkpoint bootstrap: authenticate network/genesis and checkpoint
  roots, identify who vouches for the checkpoint, verify included state
  commitments and cumulative work, and validate every subsequent block. Once
  historical proofs are deleted, a new pruned node must trust an authenticated
  checkpoint source or an already fully verified node; it does not gain
  trustless genesis verification from public data alone. Header work and matching
  public roots do not independently prove the deleted transactions. Test stale,
  conflicting, incomplete and wrong-network checkpoints and archive
  unavailability.

## Work estimates and milestones

Estimates are engineering days for one engineer familiar with the existing
Rust prover, excluding external review and unresolved cryptographic design.
They are conditional planning ranges, not delivery commitments.

| Milestone | Work | Estimate | Exit condition |
| --- | --- | ---: | --- |
| M1 | Evaluate the research fee-settlement candidate, enforce the selected 4,096-snapshot policy and V1 byte-binding boundary, and freeze the exact byte ledger | 3–6 days | Reviewed, internally consistent relation and codec specification; unresolved choices block AIR freeze |
| M2 | Native D8/W24/12 transaction AIR, trace, two-input/two-output constraints and test-first rejection matrix | 8–14 days | Native proof generation/verification and rejection tests pass with extracted actual shapes |
| M3 | Actual-AIR security scan and three-trial byte/time/memory measurements; limits and capacity report | 3–6 days | Eligible smallest-proof configuration and bounded production codecs selected, or infeasibility reported |
| M4 | Node/block integration design: admission, grouping, filler lifecycle, compact relay, reorgs, retention and checkpoint/archives | 3–5 days, parallel | Interfaces, trust assumptions, budgets and test plan reviewed; no implementation in this scope |
| M5 | X25519 + ML-KEM handshake and Dandelion++ or reviewed relay alternative | 6–10 days after M2/M3 | End-to-end handshake, failure, reconnect and source-privacy tests pass before the new engineering network |

M2 cannot close with only a surrogate AIR, an unbound ciphertext digest or an
unapproved fee-settlement mechanism. M3 cannot close using proxy measurements.
M4 may proceed in parallel as design, but cannot silently settle consensus
choices in code. Network privacy follows the transaction AIR and scan and is
required before launching the new engineering network. N=32 and recursive V2
work remain outside this V1 implementation scope.
