# Current Protocol Decisions

Status: engineering-frozen native V1 proof profile, bound to the source,
public verifier keys and security reports in the
[freeze bundle](../crates/bench-d8/artifacts/v1-native-freeze.json).
Independent cryptographic approval, hosted resource acceptance and network
activation remain separate requirements. Resource artifacts identify the
measured commit and actual CPU.

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
Each position permanently retains 1,742 public body bytes, a 48-byte fee
commitment and a 40-byte snapshot selector: 1,830 bytes. The relay prefix is
1,899 bytes and the private sidecar is 78 bytes. Maximum combined payload is
526,265 bytes. Statement identity excludes proof randomness and sidecars.
The settlement prefix is 159 bytes with a 524,288-byte proof cap.

At 576 positions and three copies, transaction traffic requires 24.25029120 Mbps,
or 291.00349440 seconds at 25 Mbps. The remaining 28,114,080 bytes per interval
must cover settlement, headers, framing and recovery. This is not measured
full-network capacity.
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
permanent. Openings use eight independent canonical KoalaBear elements,
approximately 247.91 bits of entropy. The corrected settlement AIR keeps the
fee total and miner amount private and proves the ordinary reward-note
commitment, height-derived rho and maturity. Network, height and the ordered
transaction list enter its public context. Transaction proofs enforce private
anchor fee schedules; settlement opens and sums commitments without imposing
one current tier on old-snapshot transactions. See [fee settlement](fee-settlement.md).

## Frozen profile and operational resource policy

Both native proofs use `log_blowup=8`, 36 queries, query grinding 20,
opening-batch grinding 20, commitment grinding 0, binary folding and
`log_final_poly_len=0`. The bundle records actual AIR shapes, fixed
`p3-security=0.9.0-rc.2` reports, source/dependency hashes and canonical public
verifier artifacts. Source, envelope, key or parameter drift fails CI.
A new profile requires review. The dependency revision is fixed in
[its lineage](d8-dependency-patch.md); upstream merging is not required.

Independent verifiers load public keys without prover setup. The local policy
is 128 MiB charged memory, zero swap, 250 ms CPU per proof, a two-second wall
watchdog and two concurrent workers. CPU accounting is sampled at intervals
of at most 10 ms; overshoot fails the resource check. This is not a fractional
kernel CPU quota. The serial allowance is 144 seconds for 576 transaction
checks, or 144.25 seconds including settlement. Actual measurements are
reported separately; repeated-proof work is not valid stateful block validation.
Local exhaustion is retryable unavailability, never consensus invalidity.

Verified pool: 512 MiB/2,048 entries. Unverified queue: 64 MiB/128 entries.
Per peer: 2 MiB/four unverified and 16 MiB/64 verified entries. Apply byte
limits first, including owned metadata, and reserve before reading. The codec
has a separate 4-MiB declared-vector budget, not an RSS bound. Negative and
abuse caches are 1 MiB each; reconstruction is 640 MiB/two blocks. TTLs and
admission rules are in [the integration plan](v1-node-network-plan.md).

Maintain at least 64 usable pregenerated padding transactions when ready,
with at most 128 entries and 65 MiB of serialized payload. Account metadata
separately. Use fresh nullifiers, genuine ephemeral-recipient ML-KEM encryption
and the same proof profile. Expiry, orphaning, inclusion and confirmed/pending
nullifier conflicts invalidate entries before selection and release their
reservations. Refill below 64; shortages delay production rather than permit
invalid padding or exceeding caps.

## Node and network implementation

The [integration plan](v1-node-network-plan.md) covers the shared atomic block
transition, bounded admission, compact relay, four-week retention, archive and
checkpoint synchronization, X25519 + ML-KEM transport and Dandelion++ or a
reviewed relay. Use groups of 16, 64–576 positions and `MAX_REORG_DEPTH=24`.
The fixed settlement AIR has 576 openings; smaller blocks derive canonical
zero-fee internal tails without additional chain transactions. Checkpoint
bootstrap has an explicit trust assumption after historical proof deletion.
Estimated effort is 29–49 engineering days excluding independent review;
parallel work is possible. New-network launch requires payment, resource,
transport, privacy and recovery acceptance. The retained seven-node network,
history and keys remain unchanged.
