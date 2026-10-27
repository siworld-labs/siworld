# V1 Storage, Retention and Bootstrap

Status: selected retention policy and component capacity model for the
multi-asset V1 format. Final persistent record sizes and long-run whole-node
resource qualification remain incomplete. Transaction proof caps are selected
independently of settlement and issuance caps.

## Retention classes

Every node permanently retains the following public data without pruning:

- block headers, proof of work and cumulative-work metadata;
- output commitments and commitment-tree state;
- ciphertexts and view tags;
- the nullifier set;
- fee commitments;
- per-block settlement declarations without settlement proofs;
- miner reward notes;
- development-fund expenditure records and ML-DSA signatures;
- public asset issuance records, declared supplies and metadata; and
- recent-root tree snapshots and canonical block identities.

Only transaction proofs, settlement proofs and private fee-opening sidecars
expire. A proposed native issuance proof is a transaction-proof kind with the
same lifecycle; its signed declaration and initial note commitments remain
permanent. Keep them for at least 259,200 elapsed seconds after final
confirmation, then delete them. Persist the finality/deletion metadata and
extend retention on clock or recovery uncertainty. Age alone cannot delete an
unfinalized block's proof. At a five-minute target and depth-24 finality, the
nominal rolling store covers 888 blocks: 24 unresolved blocks plus three days
of finalized blocks. Faster blocks require more storage; 888 is a sizing
example, not permission to delete by block count.

Unconfirmed transactions use bounded mempool TTL/expiry and byte admission;
they do not create an unbounded disk spill. Orphaned data follows the
reorganization/recovery policy, rather than being mistaken for finalized data.
No V1 archive-node role or long-term proof-body backup is selected. The existing
seven-node network and retained private engineering evidence remain unchanged.

## Bootstrap and wallet recovery

Default new-node synchronization uses the confirmed checkpoint distributed
with the release, authenticated by the genesis-pinned checkpoint quorum and
bound to network identity, height, block ID, cumulative PoW, state roots,
recent-root snapshots, public-data manifest and trusted verifier artifacts.
The node verifies PoW and normal transaction/state validity after that starting
point. Follow [the checkpoint trust design](v1-network-design.md); a matching
peer root or PoW does not prove deleted historical transactions.

A release bundles a confirmed checkpoint and pins the authentication policy.
If that bundled checkpoint is too old to validate its complete proof tail,
fetch a newer confirmed checkpoint authenticated under the same pinned roster
and network/verifier policy. The six-hour checkpoint publication cadence is
independent of binary release cadence. Refuse bootstrap if no authenticated
checkpoint with an available proof tail can be obtained; old release data plus
PoW alone cannot bridge deleted proofs.

Pre-checkpoint state is an explicit trust assumption in the release/checkpoint
process. Full genesis-to-tip verification of deleted historical proofs is a
future optional proof-archive or V2 compression upgrade, not a V1 capability.
Wrong-network, stale, conflicting, incomplete or unauthenticated checkpoints
fail closed. Never restore an older state over accepted history automatically.

Wallet creation requires mnemonic backup confirmation and a successful local
recovery check before readiness. Restore derives spending/view/change keys
from the backed-up material and scans permanent ciphertexts from genesis, or an
authenticated wallet birth height, including segments older than the node's
bootstrap checkpoint. Authenticate those segments against the permanent-data
manifest, check AEAD and note commitments, recover SI and asset IDs/amounts,
and reconcile spends against permanent nullifiers. A state checkpoint does not
allow skipping old ciphertexts when recovering an old unspent note. Test
offline recovery across proof deletion, checkpoints, reorganization and backup
restoration; no finite offline duration may silently omit a receipt.

## Encoding and component model

The isolated multi-asset codec implements one recipient ML-KEM output and
two symmetric sender-change outputs. Each 208-byte encrypted plaintext contains
144 meaningful bytes, including the 32-byte asset ID, and 64 padding bytes.
The encoded public transaction body is exactly 2,027 bytes. Adding the 48-byte
fee commitment and proposed 40-byte canonical snapshot selector gives a
2,115-byte permanent-position planning ledger. The body codec and AIR are
implemented; final relay/block serialization, persistent record layout and
measured database overhead remain integration work.

Use decimal GB, 365-day years, 288 target blocks/day and 576 positions/block.
Use the selected **655,360-byte (640-KiB) transaction proof cap** independently
of the 524,288-byte settlement and issuance caps, plus 78-byte sidecars. The nominal rolling window
is 888 blocks; it does not accumulate again each year. A larger proof cap adds
rolling storage while the permanent 2,115-byte position ledger is unchanged.

At the selected transaction cap, the nominal full-load rolling store is:

| Rolling component (888 blocks) | Bytes |
| --- | ---: |
| Transaction proofs | 335,208,775,680 |
| Settlement proofs | 465,567,744 |
| Sidecars | 39,896,064 |
| Ordinary transaction, settlement and sidecar subtotal | 335,714,239,488 |
| Additional issuance proof allowance | 465,567,744 |
| Total rolling allowance | 336,179,807,232 |

The finite issuance scenario reserves one additional capped native issuance
proof/block beyond ordinary positions. The total rolling allowance is
**336.180 GB**. This overcounts if issuance occupies an ordinary transaction
position. The selected cap increases rolling storage, while permanent public
records and their annual growth are unchanged.

Permanent position records add 128.061 GB/year at maximum load. To include
the other categories explicitly, the revised planning scenario uses:

| Category | Finite planning allowance | Qualification requirement |
| --- | ---: | --- |
| Permanent block records | 8 KiB/block | Extract headers/PoW, settlement declaration, reward notes, fund records/signatures, snapshot metadata and container overhead from the final codec |
| Permanent issuance records | 16 KiB/block | Bound metadata, issuer key/signature, initial commitments and record count; this is an average budget ceiling to adopt, not an enacted consensus rule |
| Issuance proof bodies | One additional 512-KiB proof/block in the rolling window | Freeze actual native issuance proof size and byte/work admission limits |
| Indexes and accepted state | 25% of all permanent position, block and issuance bytes | Measure real commitment/nullifier/asset trees, redb pages, allocator/file and index overhead |
| Database working space | 16 GB above steady records/state | Measure WAL, crash recovery and worst atomic-write/compaction peaks; use in-place/segmented compaction or increase this allowance if a full copy is required |
| System and service recovery | 20 GB | Measure OS, package, bounded logs and service artifacts; independent backups are additional |
| Device free reserve | 20% | Preserve free space after all modeled used bytes |

The block/issuance allowances are sizing assumptions requiring final byte
ceilings and tests. ML-DSA-65's 1,952-byte public key and 3,309-byte signature
fit the issuance allowance only with bounded metadata and initial outputs.
Permissionless issuance without per-record/per-block byte and CPU limits has
no finite worst-case storage or network bound. The full record/state layout
and database working peak have not yet been measured; do not label the
allowances as actual database overhead or finalized consensus limits.

| Maximum load | Permanent positions | Block allowance | Issuance allowance | Index/state allowance | Used capacity | Device with 20% free |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Year 1 | 128.061 GB | 0.861 GB | 1.722 GB | 32.661 GB | 535.486 GB | 669.357 GB |
| Year 3 | 384.184 GB | 2.583 GB | 5.167 GB | 97.984 GB | 862.098 GB | 1,077.622 GB |
| Year 5 | 640.307 GB | 4.306 GB | 8.611 GB | 163.306 GB | 1,188.710 GB | 1,485.887 GB |

Used capacity includes the rolling allowance, 16-GB database working space
and 20-GB system allowance. Required device capacity divides used bytes by
0.8 to preserve the free-space reserve; it is not additional retained data.

At lower synthetic demand, retain the 300-second target and minimum
64-position blocks; do not omit empty blocks. At 10,000/day this still stores
18,432 encoded positions/day. The finite scenario keeps the same per-block
issuance/block allowances even at low demand:

| Workload | Rolling store | Used year 1 | Used year 3 | Used year 5 |
| --- | ---: | ---: | ---: | ---: |
| Maximum 576 positions/block | 336.180 GB | 535.486 GB | 862.098 GB | 1,188.710 GB |
| 10,000/day, minimum 64-position blocks | 38.181 GB | 95.197 GB | 137.228 GB | 179.259 GB |
| 50,000/day, adaptive grouping | 101.984 GB | 189.462 GB | 292.417 GB | 395.373 GB |
| 50,000/day, uniform 176 positions | 103.368 GB | 191.510 GB | 295.793 GB | 400.076 GB |

| Workload | Device year 1 | Device year 3 | Device year 5 |
| --- | ---: | ---: | ---: |
| Maximum 576 positions/block | 669.357 GB | 1,077.622 GB | 1,485.887 GB |
| 10,000/day, minimum 64-position blocks | 118.996 GB | 171.535 GB | 224.074 GB |
| 50,000/day, adaptive grouping | 236.827 GB | 365.521 GB | 494.216 GB |
| 50,000/day, uniform 176 positions | 239.387 GB | 369.741 GB | 500.095 GB |

Reproduce with `python3 scripts/v1-storage-budget.py`, using
`--transaction-proof-cap-bytes` to specify a different transaction body limit.
Settlement and issuance limits have separate arguments; do not raise them
implicitly when changing the transaction limit. `--legacy-baseline` restores
the earlier 524,288-byte caps. Rolling positions round
up to complete groups of sixteen. Low-demand cases assume steady traffic and
the stated packing; arbitrary bursts or faster block production can need the
full rolling reserve. A dedicated `extra_permanent_bytes` term permits adding
measured costs beyond these allowances without hiding them.

Both miners and validators retain **500 GB usable SSD as the installation
minimum**, with **1 TB recommended**. The installation minimum does not qualify
continuous maximum load: year-one used bytes already exceed 500 GB and require
669.357 GB with the free reserve. At full load a 1-TB device reaches the modeled
20% free threshold after approximately 2.62 years. Year three requires
1,077.622 GB, so a 1-TB device does not meet the modeled three-year full-load
requirement.

At 10,000/day, 500 GB has substantial modeled headroom beyond five years.
At 50,000/day it is workload-sensitive: adaptive packing needs 494.216 GB at
year five, leaving only 5.784 GB beyond the free reserve, while uniform
176-position blocks need 500.095 GB and already exceed that device size.
A workload-independent five-year capacity guarantee does not follow for
50,000/day; packing, bursts and measured database overhead affect that horizon. Expansion planning must preserve all
576 positions and the complete three-day-after-finality retention window.

These are conditional planning horizons, not promises independent of actual
record sizes, workload or database layout. Replace every allowance with final
encoded/measured evidence before deployment qualification. Monitor growth and
expand before free-space reserves are consumed. Never reclaim permanent
public data or unexpired proofs to avoid an orderly storage stop.

## Backup and monitoring

Project-operated object storage backs up permanent public data only; it is not
an archive for expired proofs or sidecars. Upload finalized segments at least
every six hours with immutable object hashes/versioning, publish signed daily
manifests and create weekly full checkpoint snapshots. The backup RPO is at
most six hours; acknowledged local durable records still require RPO zero.

Restore into a fresh isolated directory: verify manifest signatures, hashes,
network and checkpoint identity; fetch all ordered public segments; rebuild
indexes/state and audit emission; compare roots and cumulative work; validate
the post-checkpoint proof tail; run wallet rescanning before promotion.
Never overwrite a newer accepted database. Run monthly isolated restore tests
and quarterly replacement-host tests, recording missing objects, recovery
duration and public-root reconciliation. Credentials and wallet secrets are
not public backup inputs.

Monitor total encoded bytes/positions, proof-age/deletion lag, separate permanent
data/index/state growth, free-space reserve, backup lag and recovery failures.
Never emit real/padding counts, hidden fees, peer addresses or timed nullifiers.
One real three-day-after-finality lifecycle is required by
[V1 acceptance](prover-acceptance.md), alongside accelerated crash/clock tests.

## Supply audit implementation requirement

Provide an integer-only height-by-height SI issuance auditor using the shared
subsidy schedule and fund transition. Recompute subsidy, 90/5/5 credits, fund
maturities/releases, valid ML-DSA expenditures and counters, and cumulative SI
emission against the curve. Transfers and fee recycling are not new issuance.
Verify public asset declarations and the native issuance-to-note supply
relation separately; do not infer private holdings or reveal fee openings.

Authenticate audit inputs through the permanent record/checkpoint manifest.
Report the first bad height and reproducible cumulative totals. Tests must
reject altered subsidy, fund credits, payout signatures/counters, duplicate
issuance and over-minting, and reconcile reorganization rollback. The tool is
an implementation gate; a size table or an unauthenticated JSON sum does not
constitute a supply audit.

## Backup checkpoint freshness

A weekly full snapshot alone is insufficient once proofs expire after
three days. Export an authenticated, consistent confirmed-state checkpoint
(full or a complete authenticated delta chain) at least every six hours,
together with the public-data manifest. Weekly full snapshots remain a
compaction/recovery convenience. Before replaying a restored checkpoint's
proof tail, confirm every required proof is still available. If not, obtain a
newer quorum-authenticated checkpoint under the explicit trust policy, or
stop recovery; public records and PoW cannot replace deleted proof validity.
The checkpoint binds the asset registry, fund state, permanent-data manifests
and complete accepted root window. Never synthesize missing state or silently
trust an unauthenticated peer.
