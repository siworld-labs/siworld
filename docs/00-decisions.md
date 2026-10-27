# Current Protocol Decisions

Status: selected V1 design direction. The native transaction route is not
activated and its production relation, parameter freeze and node admission
budgets remain subject to the gates in [the specification](route-a-v1.md).

## Network and proof architecture

Preserve the existing seven-node N=2 network, verifier, history and keys.
Native V1 uses a separate resettable engineering network with independent
genesis, directories, keys and network identity. No existing notes or proofs
are imported. V1 uses per-transaction native STARK proofs; recursion and
historical proof compression are V2 work. N=32 is outside the current scope.

Use KoalaBear D8, standard Poseidon2 W24 and twelve-element digests. Require
classical conjectured security of at least 128 bits and quantum-halved Johnson
Fiat–Shamir terms, including query and enforced grinding terms, of at least
80 bits. Challenge-domain and selected BHT collision terms must also meet
80 bits. The approximately 81.9-bit diagnostic challenge ledger meets the
selected screen; all future parameter changes must retain at least 80 bits.
The [collision ledger](bht-security-accounting.md) distinguishes raw classical
reports from quantum model conversions and application hashes.

## Root snapshots and output-encryption boundary

Accept the newest 4,096 canonical-chain snapshots of the recent-root tree.
The newest snapshot has age zero; age 4,095 is accepted and age 4,096 is
rejected. At the 300-second target this is approximately 14.22 days. A snapshot
is selected by canonical block identity and resolved to a locally trusted root;
a peer-supplied root is never authoritative. Bind the snapshot height and block
identity into the existing public-data digest, so a proof cannot be reused under
a replacement identity even if its tree root is identical. Remove noncanonical
snapshots on reorganization. Evict pending transactions that reference an expired or removed
snapshot, release their nullifier reservations, and require wallet reproof.
Historical validation uses the canonical snapshot window at the block being
validated, rather than the live tip or elapsed wall time.

This retention window is distinct from the depth-12 recent-root tree, which
already contains 4,096 anchor entries. The existing AIR depth remains unchanged.
Allowing older tree snapshots also permits anchors older than the current
anchor ring: at the full boundary an anchor may be 8,190 blocks behind the tip.
Fee-schedule staleness and snapshot metadata storage must account for both
windows. Reorganizations that shorten the chain require authoritative history
to refill the accepted window; missing history fails closed.

V1 proves ciphertext-byte binding, not ML-KEM or ChaCha20 encryption correctness.
The AIR binds every encoded ciphertext byte through the public-data digest.
The recipient verifies AEAD authentication and reconstructs the note commitment.
The sender must locally open and check both outputs before broadcast, using the
payment encapsulation secret for the recipient output, and retain per-payment
encapsulation randomness in protected wallet storage for selective payment
receipts. Receipts are private disclosures, never public transaction fields or
logs; they must not reveal a wallet master or change secret.

Padding uses actual ML-KEM encryption to a fresh valid ephemeral recipient key,
plus the same fixed-format change encryption. Random byte padding is forbidden.
Real and padding outputs share lengths and codecs. These checks do not prove
computational indistinguishability. A malicious sender can still prove a
byte-bound, undecryptable output: it is unusable by its recipient, but does not
change the consensus value-conservation or spend-validity relation. Complete
encryption-correctness circuits remain future research.

## Capacity and resource boundaries

The block target is 300 seconds with 64 through 576 positions in groups of 16.
Minimum node uplink is 25 Mbps. Preserve `MAX_LEAF_PROOF_LEN = 524288`
(512 KiB); do not derive a larger maximum from bandwidth or observed samples.
Each position has 1,742 bytes of public transaction body and a 48-byte fee
commitment, totaling 1,790 bytes, before sidecar/envelope traffic.

At 576 positions and three relay copies the maximum-size transaction payload
requires 24.24167424 Mbps, leaving 3.0333% uplink margin. Full-network acceptance
must additionally account for settlement, sidecars, framing and recovery.
If the frozen production proof exceeds the cap, first evaluate larger blowup.
If no eligible profile fits, report a proposed 544-position capacity and revised
budgets; this fallback does not increase the proof cap or authorize activation.

## Confidential fees and retention

Use confidential fee commitments with native fixed-capacity settlement.
Nodes validate fee-opening sidecars against the transaction and commitment
before admission; no additional sidecar signature or encryption layer is
selected. Planned hybrid X25519 + ML-KEM transport handles connection secrecy.
Transaction and settlement proofs and private sidecars remain online for four
weeks after final confirmation, then are deleted. Public fee commitments remain
permanent. See [fee settlement](fee-settlement.md) for unresolved production gates.

## Release gates

Freeze the production AIR, deterministic codec maximum, dependency revision,
trusted key and full security report before selecting production parameters.
Pin the modified Plonky3-recursion source by the full revision and tree recorded
in [the dependency lineage](d8-dependency-patch.md); no upstream merge is required.
Choose the smallest eligible proof with four-worker generation at most two
seconds. Measure generation and verification memory independently and bound
malformed-input work before adopting mempool/DoS constants. A hosted cgroup
measurement is resource evidence, not proof of complete relation coverage,
cryptographic approval, dedicated target hardware performance or node activation.
