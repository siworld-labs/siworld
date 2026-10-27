# Current Protocol Decisions

Status: V1 proof parameters and codec are reopened for the required
multi-asset, two-input/three-output relation. The previous single-asset
[freeze bundle](../crates/bench-d8/artifacts/v1-native-freeze.json) remains an
unchanged, reproducible diagnostic baseline; it is not acceptance of the new
relation.
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
The sender must locally open and check all three outputs before broadcast, using the
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
Minimum node uplink is 30 Mbps; deployment recommends 100 Mbps. Preserve `MAX_LEAF_PROOF_LEN = 524288`
(512 KiB); do not derive a larger maximum from bandwidth or observed samples.
The implemented isolated private asset-ID, three-output codec uses 2,027 public body
bytes, 48 fee-commitment bytes and a 40-byte snapshot selector: 2,115 permanent
bytes per position. Its proposed relay prefix is 2,184 bytes and a private
sidecar is 78 bytes. The maximum combined transaction payload is 526,550 bytes
at the retained proof cap. The body encoding is tested; complete envelope
framing still requires node integration. The settlement prefix remains a baseline
159 bytes and must be rechecked after the reward-note asset binding changes.
At 576 positions and three copies including a capped settlement envelope,
the provisional payload requires 24.30537976 Mbps, before inventories,
framing, retransmissions, issuance and recovery traffic. A payload fit is not
full-network acceptance. The [conditional full wire budget](v1-network-budget.md)
adds explicit protocol/control, packetization, reciprocal ACK, bounded issuance,
handshake, retransmission and recovery assumptions: approximately 29.252 Mbps,
leaving 2.49% additional margin at 30 Mbps. Qualify actual traffic before launch.
If the frozen production proof exceeds the cap, first evaluate larger blowup.
If no eligible profile fits, report a proposed 544-position capacity and revised
budgets; this fallback does not increase the proof cap or authorize activation.
Reducing block capacity cannot make an individually oversized proof valid;
a profile at or below 512 KiB is still required before activation.

## Confidential fees and retention

Use confidential fee commitments with native fixed-capacity settlement.
Nodes validate fee-opening sidecars against the transaction and commitment
before admission; no additional sidecar signature or encryption layer is
selected. Planned hybrid X25519 + ML-KEM transport handles connection secrecy.
Transaction and settlement proofs and private sidecars remain online until
three elapsed days after final confirmation, then are deleted. Public data is
permanent on every node; no V1 archive-node role retains proof bodies beyond
that window. Openings use eight independent canonical KoalaBear elements,
approximately 247.91 bits of entropy. The corrected settlement AIR keeps the
fee total and miner amount private and proves the ordinary reward-note
commitment, height-derived rho and maturity. Network, height and the ordered
transaction list enter its public context. Transaction proofs enforce private
anchor fee schedules; settlement opens and sums commitments without imposing
one current tier on old-snapshot transactions. See [fee settlement](fee-settlement.md).

## Prior profile and provisional operational resource policy

The prior two-output baseline used `log_blowup=8`, 36 queries, query grinding 20,
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
transition, bounded admission, compact relay, three-day proof retention,
permanent public-data storage, checkpoint-plus-PoW synchronization, authenticated X25519 + ML-KEM transport and
Dandelion++. Use groups of 16, 64–576 positions and `MAX_REORG_DEPTH=24`.
The fixed settlement AIR has 576 openings; smaller blocks derive canonical
zero-fee internal tails without additional chain transactions. Checkpoint
bootstrap has an explicit trust assumption after historical proof deletion.
N1–N7 require an estimated 33–56 engineering days including dual-identity
transport work; wallet durability and private monitoring add separate 6–10
and 3–5 day estimates. These exclude review, infrastructure and elapsed
observation windows. New-network launch requires [native V1 acceptance](prover-acceptance.md).
The retained seven-node network, history and keys remain unchanged.

## Deployment qualification and visibility

The 5-GiB zero-swap generation measurements do not set a formal miner RAM
requirement. The [qualification profiles](v1-deployment.md) start at four
reference-class vCPUs/16 GiB for validators and at least four vCPUs/32 GiB for
miners, with 500 GB usable SSD minimum and 1 TB recommended, plus separately
budgeted backups. These profiles
are unqualified until sustained integrated measurements pass. Linux x86-64-v3
is the measured platform; macOS and Windows need their own adapters and
qualification. Keep the 30-Mbps uplink floor; prefer 100-Mbps links for margin
and qualify actual full-capacity relay/recovery at both bandwidth classes.

At the target block rate, ordinary proofs/sidecars including nominal
depth-24 finality require 268,672,484,352 rolling bytes. One additional capped
issuance proof/block adds 465,567,744 bytes. The 2,115-byte position
codec adds 128,061,388,800 permanent bytes/year at full load. The
[finite storage planning model](v1-storage-and-sync.md) additionally reserves
8 KiB/block for permanent block records, 16 KiB/block for issuance records,
25% of all permanent records for indexes/state, 16 GB database working space,
20 GB system files and 20% device free. These are proposed budgets, not
measured final record/database costs or activated issuance limits.

Under that scenario, 1 TB lasts approximately three full-load years, while
500 GB lasts more than five years at the stated early 10k/50k-per-day usage.
Freeze actual encoded sizes, issuance byte/work limits and measured database
growth/maintenance before qualification; revise the horizons if they exceed
the allowances. Faster blocks increase elapsed-time retention storage. Never
prune required public records or unexpired proofs.

Every validator independently enforces consensus. Miners add production;
bootstrap nodes add discovery; project-operated object storage backs up public
data without retaining deleted proofs. There is no privileged
main node. Use an independent private collector/panel with outbound read-only
telemetry, five-second samples and stale marking after 15 seconds. Monitoring
failure cannot stop consensus. Exclude addresses, timed nullifiers, fees,
real/padding classifications and padding-queue counts.

Qualification requires a 72-hour maximum-load hardware run and a seven-day
independent-host soak containing at least 72 hours at maximum load; windows
may overlap on the frozen configuration. Observe a real three-day-after-finality
retention lifecycle as well as accelerated deletion/recovery tests. The
[acceptance matrix](prover-acceptance.md#gate-6-sustained-observation-retention-and-recovery)
defines RPO zero for durable records, ten-minute ordinary restart and a
30-minute at-most-24-block catch-up target on the 100-Mbps reference.
Lower-bandwidth recovery requires its own measured spare-bandwidth budget.
These are test targets, not completed measurements.

## Transport identity and checkpoint trust

The [V1 network design](v1-network-design.md) selects ephemeral X25519 plus
ML-KEM-768, with Ed25519 and ML-DSA-65 identity signatures both required over
the bound identity/transcript. Use a reviewed hybrid combiner, key confirmation
and fixed protocol profile, with no classical fallback. These choices still
require implementation and independent security review. A classical PeerId
alone does not bind the post-quantum identity.

Dandelion++ is the selected source-relay path. Its routing/timer parameters
and library/combiner profile must be frozen after adversarial evaluation.
Hybrid transport protects content, not network endpoints; Dandelion++ does
not guarantee anonymity against global observation or malicious first hops.
Fee-sidecar recipients learn openings and can identify a zero fee; the
on-chain commitment does not hide that information from its recipient.

Pruned bootstrap uses opt-in trust in a fixed, genesis-pinned two-of-three
independent checkpoint-authority roster, with dual identity signatures and
authenticated cumulative work. A release checkpoint plus PoW is the default
new-node synchronization path; full proof replay from genesis is a future
upgrade. Checkpoint
manifests bind network, block/work, verifiers, complete state and snapshot
window. Reject conflicts and never automatically roll back accepted history.
The quorum is an explicit trust policy, not a proof of deleted history or
Byzantine-consensus safety. Authority setup creates no keys or genesis as part
of this design; identity custody and review remain launch requirements.

## V1 assets, durable public data and issuance audit

V1 supports permissionless issued assets in the same privacy pool as SI.
Notes bind a private asset ID into their commitment and ciphertext. All
transactions have two inputs and three outputs, including SI-only and padding
transactions. The AIR balances every private asset independently; fees are
paid only in SI. Issuance publishes declared supply, name and precision and
uses a domain-separated ML-DSA-65 signature verified natively by the node.
The isolated native implementation covers ID derivation and fixed-supply issuance-to-note binding in
[the reopened design](v1-multi-asset.md). The SI issuance-fee amount/destination,
asset-aware minimum output rule, metadata/note limits and per-block issuance
byte/CPU budget remain open protocol values; do not settle them implicitly in
consensus code. All remain implementation/review gates rather than enabled rules.
No private transfer asset ID or holding is published. The unresolved values
and qualification evidence are recorded in [the open-question register](11-risks-open-questions.md).

All nodes permanently retain headers/PoW, output commitments and tree state,
ciphertexts, nullifiers, fee commitments, proof-free settlement declarations,
miner reward notes, development-fund spend records with ML-DSA signatures,
asset issuance records and recent-root snapshots. Only transaction proofs,
settlement proofs and sidecars expire, three elapsed days after finality.
There is no V1 archive role. Release-pinned checkpoint plus PoW is the default
new-node path; full historical proof validation is a future upgrade.

V1 requires an integer-only height-by-height SI issuance audit
tool using the shared reward schedule and fund transition. It must verify
subsidy/fund credits, signed spending, cumulative issuance and public asset
issuance limits without exposing hidden fees or balances. This tool remains
required implementation work. Project-operated permanent-public-data backups
and mandatory mnemonic backup/full ciphertext rescan are described in
[deployment](v1-deployment.md) and [the storage model](v1-storage-and-sync.md).

## Multi-asset implementation and diagnostic result

The isolated [multi-asset crate](../crates/bench-multi-asset/README.md) implements
native two-input/three-output asset conservation, the 2,027-byte public codec,
ML-DSA-authenticated fixed-supply issuance and the SI-only reward asset inside
the settlement AIR. No retained node uses this crate. Public body plus fee
commitment and snapshot selector is 2,115 bytes per position; relay-envelope
framing remains proposed until node integration.

The actual `p3-security` scan and [native measurements](v1-multi-asset-evaluation.md)
reopen parameter selection. Requested log blowups 4--8 exceed the proof cap.
A log-blowup-9, 31-query, 24-bit query/batch-grinding diagnostic fits the cap in
observed samples and gives approximately 81.706 bits in the selected quantum
Johnson challenge ledger. Its local four-worker generation median is 4.7473
seconds, above the two-second target. It is not a frozen production profile.
The matching source commit was measured on a hosted EPYC 7763 with two
exposed physical cores and four vCPUs: generation median 6.3081 seconds,
one-worker verification median 14.8915 ms, maximum whole-process cgroup peak
2,083,336,192 bytes, and observed bodies 512,469--523,702 bytes. All memory
event deltas were zero under the diagnostic five-GiB scope with swap disabled.
The near-cap samples are not a deterministic proof-length bound.
Keep the 524,288-byte cap, 576-position limit and security target unchanged;
report failed qualification before any production integration or activation.
