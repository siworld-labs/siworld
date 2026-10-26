# Native Transaction Proof Design

Status: selected V1 direction; production AIR, codec, parameter selection and
node integration are not complete. Requirements below do not describe an
activated network. Open design issues explicitly block a production AIR freeze.

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
positions in groups of 16. The minimum node link is 20 Mbps. Node integration,
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
that path into a native transaction proof does not resolve private fee
settlement or root-snapshot lifetime.

The existing relation binds a ciphertext digest but does not constrain ML-KEM
encapsulation coins or shared secrets, the sender change secret/KDF, AEAD keys,
nonce generation, plaintext encryption or authentication-tag computation.
These private encryption fields are not proven consistent with output note
openings. Public-data mutation tests establish substitution resistance only.
Native stateful nullifier checks, bounded decoding, wallet erasure and transport
source privacy also remain separate requirements. Iterative code and test
milestones do not establish complete AIR coverage or production acceptance.

## Fixed transaction relation

Each transaction has two inputs and two outputs. The relation must constrain
both inputs independently, including ownership, nullifier derivation,
commitment membership, value ranges and unlock conditions. It must enforce
value conservation, output-seed derivation and standard/priority fee rules.
Duplicate nullifiers within the transaction are invalid. Native mempool and
consensus checks also reject conflicts across transactions and prior state;
those stateful checks cannot be replaced by the transaction AIR.

The note commitment tree has depth 40. The recent-root tree has depth 12 and
4,096 leaves. An anchor leaf commits to the commitment root, anchor height and
fee-schedule data with a fixed domain tag. Membership in this tree moves into
the transaction AIR. The anchor entry, height, fee witness and membership path
are private. The public proof statement contains the recent-root tree root,
network/suite/format identity, transaction public-data binding and any fee
settlement binding required by the final design. It does not expose the
individual anchor entry or path.

### Root lifetime is an open design issue

Updating a recent-root tree changes its root even while an individual anchor
remains in its 4,096-leaf window. A proof tied to one root does not become a
proof for the next root automatically. Reusing the current parent/grandparent
root allowance would make a relayed transaction expire after approximately two
blocks, even if its anchor is still retained.

Before freezing the AIR, specify a deterministic accepted-root window, how the
proof envelope identifies its root snapshot, and how admission, inclusion,
reorgs and expiry use that window. Specify wallet reproof/rebroadcast behavior
when a snapshot expires, including nullifier reservations. A retained root
must commit to valid consensus state and a valid fee schedule. Accepting an
arbitrary public root supplied by a peer is invalid. Larger root windows have
storage, fee-staleness and replay consequences that require explicit review.
The final codec and capacity calculation must include any root-snapshot fields
that are not amortized by block or proof context.

### Fee settlement and padding privacy are open design issues

The implemented recursive relation permits zero fees for all-dummy slots and
standard or priority fees for other slots; the aggregate proof binds the
miner's collected fee total. Native per-transaction proofs remove that
aggregate settlement mechanism. Publishing a zero/nonzero fee, individual fee
amount, fee opening or independently recognizable fee claim identifies filler
transactions or fee tiers. Equal byte lengths alone do not prevent this leak.

V1 must define a confidential fee-settlement binding and hidden coinbase fee
total that nodes can validate, that credits the producer exactly once, and
that preserves the same public shape for paid and filler transactions.
Alternatively, a different explicitly reviewed fee and padding model is required. A ciphertext or unbound private
fee witness is insufficient. No such mechanism is selected here, and the
1,742-byte target must not silently exclude extra fee-settlement fields.
Standard and priority amounts remain reward-linked: standard is
`floor(reward / 1,000)` and priority is four times standard. Variable bids are
outside scope. The production AIR cannot be frozen until collection,
non-duplication and padding indistinguishability have a complete design.

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

The required meaning of ciphertext/output binding must be fixed before AIR
freeze: either retain public-data substitution resistance and explicitly leave
sender-created undecryptable outputs outside the proven relation, or implement
a complete encryption-correctness relation with its additional witness,
constraints and cost. AEAD associated data alone must not be described as
node-verifiable encryption correctness. This distinction affects the AIR scan,
auditing scope and proof-generation target.

## Public-data codec target

The selected wire layout is 1,742 public bytes per transaction, excluding the
native proof and proof/relay-envelope context. The current implementation uses
32-byte digests, two 1,344-byte ciphertexts and a 2,818-byte slot. It is not this codec.

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
No current proxy row is eligible for `MAX_LEAF_PROOF_LEN`.

At 576 positions per 300 seconds, the position rate is 1.92/s. At three relay
copies and a 20-Mbps link, the total per-position relay allowance is
approximately 434,027.78 bytes before protocol reserve. The earlier provisional
431,029-byte proof threshold reserves 2,998 bytes for other data; that reserve
must be replaced with the actual production envelope ledger. Keep this
threshold as a conservative comparison until that ledger is fixed, and reserve
additional capacity for missing-proof requests, retransmissions and other peer
traffic.

If eligible production proofs exceed 431,029 bytes, prefer a larger-blowup
configuration that meets the security and generation gates. If none meets the
threshold, reduce the proposed ceiling to 512 positions and report the revised
bandwidth and queue budget. At 512 positions per 300 seconds, the gross
per-position relay allowance is 488,281.25 bytes before non-proof data and
protocol reserve. Neither threshold authorizes activation or capacity increases.

Set `MAX_LEAF_PROOF_LEN` from the selected canonical encoded production proof,
with a reviewed explicit bound. Bound the transaction envelope separately.
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
- Retain proofs for four weeks **after final confirmation**, then delete them
  from the online proof store. At a 300-second target, 24 blocks correspond to
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
| M1 | Resolve fee/padding settlement, root-snapshot lifetime, encryption-correctness scope and exact byte ledger | 3–6 days | Reviewed, internally consistent relation and codec specification; unresolved choices block AIR freeze |
| M2 | Native D8/W24/12 transaction AIR, trace, two-input/two-output constraints and test-first rejection matrix | 8–14 days | Native proof generation/verification and rejection tests pass with extracted actual shapes |
| M3 | Actual-AIR security scan and three-trial byte/time/memory measurements; limits and capacity report | 3–6 days | Eligible smallest-proof configuration and bounded production codecs selected, or infeasibility reported |
| M4 | Node/block integration design: admission, grouping, filler lifecycle, compact relay, reorgs, retention and checkpoint/archives | 3–5 days, parallel | Interfaces, trust assumptions, budgets and test plan reviewed; no implementation in this scope |
| M5 | X25519 + ML-KEM handshake and Dandelion++ or reviewed relay alternative | 6–10 days after M2/M3 | End-to-end handshake, failure, reconnect and source-privacy tests pass before the new engineering network |

M2 cannot close with only a surrogate AIR, an unbound ciphertext digest or an
unspecified fee settlement mechanism. M3 cannot close using proxy measurements.
M4 may proceed in parallel as design, but cannot silently settle consensus
choices in code. Network privacy follows the transaction AIR and scan and is
required before launching the new engineering network. N=32 and recursive V2
work remain outside this V1 implementation scope.
