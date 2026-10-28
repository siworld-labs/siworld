# Current Protocol Decisions

Status: the V1 economics revision reopens transaction and settlement proof
qualification. Source-bound profiles and measurements retained in the repository
are baselines for the earlier relation; they do not qualify the revised input
unlock or multi-note reward constraints. Re-extract actual-AIR security, reproduce
public preprocessing keys and measure fresh proofs before refreezing. No external
audit approval or network activation is implied.

## Network and proof architecture

Preserve the existing seven-node N=2 legacy recursive classical engineering
testnet, verifier, history and keys.
Native V1 uses a separate resettable engineering network with independent
genesis, directories, keys and network identity. No existing notes or proofs
are imported. V1 uses per-transaction native STARK proofs; recursion and
historical proof compression are V2 work. N=32 is outside the current scope.

Use KoalaBear D8, standard Poseidon2 W24 and twelve-element digests. Require
classical conjectured security of at least 128 bits and quantum-halved Johnson
Fiat–Shamir terms, including query and enforced grinding terms, of at least
80 bits. Challenge-domain and selected BHT collision terms must also meet
80 bits. The earlier baseline reported quantum-halved Johnson challenge ledgers of
81.6922 bits for transactions, 81.9837 for fixed-576 settlement and 81.8987 for
three-note issuance. Revised relations require their own actual-AIR reports. All future parameter changes must retain at least 80 bits.
The [collision ledger](bht-security-accounting.md) distinguishes raw classical
reports from quantum model conversions and application hashes.

## Subsidy, reward modes and fund allocation

Amounts use SIP: one SIP is 100,000,000 atoms. Native V1 pays an initial
3,394,524,515 atoms per 300-second block. Blocks 1 through 4,032 use that
amount; block 4,033 first applies `DECAY_Q32 / 2^32`. Subsequent epochs contain
4,032 blocks. The native floor is 100,000,000 atoms per block; the equivalent
60-second tail constant is 20,000,000 atoms. Retained legacy issuance behavior
is not changed by this versioned native rule.

Subsidy allocates 3% to the public Holder pool, 10% to development-fund
wallets and the residual to the miner base. Each fund wallet has its own
explicit share, credit history, released entitlement and spent counter. Its
50% direct portion matures after 24 blocks; its other 50% releases in daily
height-based steps over 1,461 days, with 288 blocks per day. Each credit vests
independently; cumulative released atoms use integer floors, releasing all
remaining atoms on the last day. A wallet may spend only its own released
unspent entitlement, authenticated by its existing ML-DSA-65 authorization.
Fund wallets do not share expenditure allowances.

The launch-time number of fund wallets and individual shares remain
unconfigured. Reserve an explicit allocation interface, bind the selected
configuration to genesis and reject new-network block production without it.
Do not infer equal shares or create replacement keys. Synthetic allocations
used by tests are not a production allocation decision.

The public block mode is explicitly selected without a miner default:

- Voyager: floor(5% of miner base) is burned, floor(20%) enters the Holder pool
  and the residual becomes one reward note maturing after 24 blocks.
- Holder: four notes each receive floor(10% of miner base), unlocking after
  52,560 / 105,120 / 157,680 / 210,240 blocks. The residual, confidential fees
  and pool payment form the fifth note, which matures after 24 blocks.

Credit the block's 3% pool allocation before computing a Holder payment as
floor(pool balance / 4,032). Voyager never draws from the pool. Fees are
transfers and all enter reward note zero; fees do not participate in subsidy
splits. Template creation snapshots the selected mode, so preference changes
cannot modify an already prepared candidate. Reward note nonces bind height
and ordered note index, preventing repeated nullifiers across tranches.

Cumulative issued subsidy equals cumulative miner subsidy-note credits plus
Holder pool balance, burned subsidy and fund entitlements. Count neither fees
nor fund transfers as issuance. Block acceptance and reorganizations atomically
include pool, burn, fund and future unlock schedules. Public locked/circulating
figures describe scheduled subsidy/fund accounting, not an exact sum of private
unspent balances. The [economic specification](v1-economics.md) defines the
integer formulas, projections and test requirements.

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
Keep the maximum at 576; there is no capacity-reduction fallback. Prioritize
transaction proving within two seconds on the EPYC 7763 four-vCPU reference.
Select from log blowups 5 through 8 and query/batch grinding 20 or 24, using
three fresh trials per configuration. All three generation times must pass;
rank passing configurations by their largest observed serialized proof.

The pre-economics baseline used `log_blowup=7`, 41 queries, query grinding 20, opening-batch grinding 20,
commitment grinding zero, binary folding and `log_final_poly_len=0`.
The [actual-AIR report and measurements](v1-multi-asset-evaluation.md) record
three generation times of 1.332143, 1.315662 and 1.316440 seconds, maximum
whole-process charged memory 531,668,992 bytes and quantum-halved Johnson
challenge union 81.692219 bits. These are three-sample qualification results,
not worst-case latency or independent cryptographic approval.

The revised-relation admission target remains `MAX_LEAF_PROOF_LEN = 655,360` bytes (640 KiB). This is the
smallest 64-KiB multiple at least 10% above the largest observed selected proof
of 584,848 bytes, giving 12.056% sample headroom. It is an enforced admission
requirement for the new integration, not a mathematical encoded-size bound.
Settlement and issuance proof caps remain independently 524,288 bytes.
The old 512-KiB decoder and retained network are unchanged. The native
integration's prepared multi-asset decoder and envelope enforce this profile. Worker isolation and deployed-network resource qualification
remain required before activation.

The implemented public body is 2,027 bytes; its fee commitment and snapshot
selector bring permanent bytes to 2,115 per position. The native codec's
2,184-byte relay prefix and 78-byte sidecar bring the capped combined payload to
657,622 bytes. Full three-copy traffic for 576 positions, settlement, bounded
issuance, inventories, requests, AEAD/multiplexing, IPv6/TCP/link framing,
reciprocal ACKs, handshakes, retransmission and recovery is modeled at
36.501639 Mbps. Require at least 43 Mbps sustained uplink, computed as
`ceil(wire_mbps / 0.85)`; 15.112% remains unused at that floor. Deployment
recommends 100 Mbps. The [full wire budget](v1-network-budget.md) is conditional
planning; measure the actual transport before network acceptance.

The [independent layout prototype](multi-asset-air-optimization.md) targets
fewer columns and smaller openings. It does not change the frozen relation or
block capacity. Re-screen and measure any adopted optimization before
refreezing its key and reducing proof/bandwidth limits.

## Confidential fees and retention

Use confidential fee commitments with native fixed-capacity settlement.
Nodes validate fee-opening sidecars against the transaction and commitment
before admission; no additional sidecar signature or encryption layer is
selected. Planned hybrid X25519 + ML-KEM transport handles connection secrecy.
Transaction, settlement and native issuance proofs and private sidecars remain online until
three elapsed days after final confirmation, then are deleted. Public data is
permanent on every node; no V1 archive-node role retains proof bodies beyond
that window. Openings use eight independent canonical KoalaBear elements,
approximately 247.91 bits of entropy. The corrected settlement AIR keeps the
fee total and miner amount private and proves the mode-selected reward-note
commitments, height/index-derived nonces and authenticated unlock plan. Network, height and the ordered
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
with at most 128 entries and 65 MiB of serialized payload. At the new wire
maximum the byte cap permits at most 103 entries before metadata; 64 entries
need 42,087,808 bytes and fit. Account metadata separately. Use fresh nullifiers, genuine ephemeral-recipient ML-KEM encryption
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
The original N1–N7 planning range is 33–56 engineering days including
dual-identity transport work; wallet durability and private monitoring add
separate 6–10 and 3–5 day estimates. These are scope estimates, not remaining
work or completed acceptance. They exclude review, infrastructure and elapsed
observation windows. The current implementation boundary is recorded below.
New-network launch requires [native V1 acceptance](prover-acceptance.md).
The retained seven-node network, history and keys remain unchanged.

## Deployment qualification and visibility

The 5-GiB zero-swap generation measurements do not set a formal miner RAM
requirement. The [qualification profiles](v1-deployment.md) start at four
reference-class vCPUs/16 GiB for validators and at least four vCPUs/32 GiB for
miners, with 500 GB usable SSD minimum and 1 TB recommended, plus separately
budgeted backups. These profiles
are unqualified until sustained integrated measurements pass. Linux x86-64-v3
is the measured platform; macOS and Windows need their own adapters and
qualification. Keep the 43-Mbps uplink floor; prefer 100-Mbps links for margin
and qualify actual full-capacity relay/recovery at both bandwidth classes.

At the target block rate, proofs and sidecars including the nominal depth-24
finality tail require 336,179,807,232 rolling bytes at the separate caps.
The 2,115-byte position codec adds 128,061,388,800 permanent bytes/year at
full load. The [finite storage model](v1-storage-and-sync.md) also reserves
8 KiB/block for permanent block records, 16 KiB/block for issuance records,
25% of permanent records for indexes/state, 16 GB database working space,
20 GB system files and 20% device free. These remain proposed allowances
pending actual database and encoded-record measurements.

With that free-space reserve, full-load device needs at years 1/3/5 are
669.357/1,077.622/1,485.887 GB. One TB therefore does not cover three full-load
years with the reserve intact. At 10,000 submitted transactions/day, the
minimum-block case needs 118.996/171.535/224.074 GB. At 50,000/day, adaptive
packing needs 236.827/365.521/494.216 GB; uniform 176-position blocks require
239.387/369.741/500.095 GB. A 500-GB device is an early-load profile, not a
full-load year-one guarantee. Retain the 500-GB minimum and 1-TB recommendation
as workload-qualified profiles and plan expansion from measured growth.
Never shorten retention or prune permanent public data to meet a disk target.

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

V1 supports permissionless issued assets in the same privacy pool as SIP.
Notes bind a private asset ID into their commitment and ciphertext. All
transactions have two inputs and three outputs, including SIP-only and padding
transactions. The AIR balances every private asset independently; fees are
paid only in SIP. Issuance publishes declared supply, name and precision and
uses a domain-separated ML-DSA-65 signature verified natively by the node.
The isolated native implementation covers ID derivation and fixed-supply issuance-to-note binding in
[the multi-asset design](v1-multi-asset.md). Testnet asset issuance requires
exactly **50 SIP (5,000,000,000 atoms)**, credited entirely to a dedicated
development-fund account. That account is not yet configured: issuance admission
must remain closed and fail closed until its authenticated destination and the
atomic fee-payment consumption transition are implemented and configured.
An absent destination must not select a default account or waive the fee.
The mainnet issuance fee remains undecided. Asset-aware minimum outputs,
metadata/note limits and per-block issuance byte/CPU budgets remain open
protocol values; do not settle them implicitly in consensus code.
No private transfer asset ID or holding is published. The unresolved values
and qualification evidence are recorded in [the open-question register](11-risks-open-questions.md).

All nodes permanently retain headers/PoW, output commitments and tree state,
ciphertexts, nullifiers, fee commitments, proof-free settlement declarations,
miner reward notes, development-fund spend records with ML-DSA signatures,
asset issuance records and recent-root snapshots. Only transaction proofs,
settlement proofs, native issuance proofs and sidecars expire, three elapsed
days after final confirmation.
There is no V1 archive role. Release-pinned checkpoint plus PoW is the default
new-node path; full historical proof validation is a future upgrade.

V1 requires an integer-only height-by-height SIP issuance audit using the
shared reward schedule and fund transition. The native offline command and
library now independently replay canonical proofs, check SIP subsidies and
direct/locked fund credits and bind the report to the accepted height, tip and
state fingerprint. Signed fund spending is included by the economic transition when existing
verification keys and allocation are explicitly configured. Asset issuance
admission and private wallet receipt checks remain separate audit scopes.
Project-operated permanent-public-data backups
and mandatory mnemonic backup/full ciphertext rescan are described in
[deployment](v1-deployment.md) and [the storage model](v1-storage-and-sync.md).

## Multi-asset implementation and reopened qualification

The isolated [multi-asset crate](../crates/bench-multi-asset/README.md) implements
native asset conservation, the fixed three-output codec, ML-DSA-authenticated
fixed-supply issuance and SIP-only settlement rewards. The economic revision
adds trusted snapshot-height lock eligibility and mode-selected reward notes.
Ordinary transaction and issuance outputs use unlock height zero; consensus
reward notes obtain their locks from the authenticated reward plan.

The [prior transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
and [prior relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
remain diagnostic baselines. They are not approval for the changed sources.
New security reports, public keys and three-trial measurements must reproduce
before replacing their role in the native verifier. Transaction proving must
remain within two seconds on the EPYC 7763 four-vCPU reference, with a
655,360-byte cap and at least 80 quantum-halved Johnson bits. Settlement and
issuance retain separately evaluated 524,288-byte targets. Keep 576 positions;
report any resource failure and bandwidth impact rather than reducing capacity.

Independent verifier qualification, valid-block timing, configured testnet
issuance-fee collection, durable wallet recovery, retention and network
acceptance remain separate gates. A successful isolated proof does not
activate a public network.


## Native engineering integration boundary

The separate [engineering runtime](v1-native-runtime.md) integrates
native transaction and fixed-576 settlement verification with strict ascending
BLAKE3 statement-ID ordering, all-input reuse checks, the canonical snapshot
window and an atomic append/replay transition. It creates independent disposable
engineering directories and imports no retained chain, key or wallet data.
The economics revision requires fresh source-bound relation keys and qualification.

Continuous production uses a new independent ASERT engineering directory with
configuration format v2, fresh network identity and genesis, immutable
initially calibrated work rules and a 300-second target interval. Producer and
validator share the integer-only timestamp, ASERT target and sequential BLAKE3
work checks. A resident prover and bounded private pre-generation queue supply
64-position blocks. Existing engineering directories and the retained
seven-node network are not migrated or changed. Public genesis activation and
epoch recalibration remain separate decisions.

Before the first development-network deployment stage, require one genuine
24-hour single-node observation on the frozen binary and configuration, without
abnormal exit, OOM, proof failure, state inconsistency or stalled actual work.
The observer independently measures monotonic time, checks process ownership
and reads private exports without opening the live database. A stochastic long
block interval below two hours is permitted with fresh PoW progress. Once
ready, two hours without accepted-height progress makes the observation
incomplete independently of hashing progress. This operational threshold is not
a consensus validity rule or a deterministic block-interval guarantee. Any restart or evidence
gap invalidates continuity; prior elapsed wall time cannot complete a new
window. Completion also requires graceful shutdown and an independent offline
full replay/reward-recovery check matching the final accepted state. This
document records the requirement, not a completed observation or deployment.
The 72-hour maximum-load and seven-day independent-host acceptance requirements
remain additional gates.

The native node library composes the same store/transition with a bounded
verified mempool, padding preparation, real-transaction candidate assembly and
private fee settlement. Admission checks the canonical snapshot, both pending
nullifiers, all outputs, matching sidecar and independent frozen proof before
insertion. The verified-pool policy is 512 MiB/2,048 entries, 16 MiB/64 entries
per opaque peer and at most 4,096 peer identities. These logical limits do not
supply isolated workers, ingress queues or a process-memory guarantee.

The authenticated-stream interface binds network, genesis and frozen verifier
manifest, with bounded framing and declared peer roles, full-proof batches and exact-proof
compact recovery. Sync attempts pin peer/base/ancestor/continuation and retain
budget reservations until adoption or discard. There is no production hybrid
authenticator or enabled listening service. A reviewed X25519 + ML-KEM,
Ed25519 + ML-DSA provider, authenticated record protection, actual-listener
failure tests and Dandelion++ remain required before network activation.

Fork choice compares cumulative verified work only; equal work retains the
current chain. Candidate blocks replay through the common transition and may
detach at most 24 blocks. Replacement canonical rows, accepted head/fingerprint
and checksummed detached evidence commit atomically. The default policy permits
32 candidate blocks, a 640-MiB logical candidate budget and 1 GiB of retained
detached evidence. Transport has its own shared 640-MiB logical budget; the two
budgets do not establish a combined process-memory bound. Non-tip ancestor reconstruction replays from
genesis and has a height-4,096 local work guard; exceeding it is resource
unavailability, not invalidity or a consensus horizon. Tip extension does not
need that replay. Qualified checkpoint/replay and time-based evidence pruning
remain necessary for long-lived deployment.

Seed-wallet APIs derive independent spend, deterministic ML-KEM view and
256-bit change keys per network/account, authenticate output recovery after
complete canonical replay, reconcile orphan receipts/spends and prepare fixed
SIP or asset transfers with SIP-only standard/priority fees. Native proving
returns the transaction, matching sidecar and private payment opening.
Mnemonic backup, protected persistence, valid-chain seed-wallet funding,
pruned-public-history rescan and full M2 workflow acceptance remain incomplete.
Seed-backed mining destinations and ordered per-note encryption receipts are
required for recovery. Existing artifacts are earlier-relation baselines.

The dedicated native runtime CI job compiles the integration and runs
synthetic-verifier state/transport tests and native-proof tests. Tests with
synthetic funding do not establish end-to-end valid-chain wallet acceptance or
production cryptographic transport. Unsupported issuance operations remain
absent until the dedicated testnet fund account, atomic fee collection and
resource bounds are configured and implemented. Three-day proof/sidecar
retention, checkpoint bootstrap, fund spending, protected wallet durability,
transport privacy and sustained network acceptance remain separate gates.
No library test changes the frozen single-node observation or the retained
seven-node network.
