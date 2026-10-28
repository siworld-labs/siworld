# Risks and Open Protocol Questions

Status: unresolved V1 multi-asset protocol and qualification questions. This
register records open work under [the decisions](00-decisions.md) and
[multi-asset design](v1-multi-asset.md). Experimental behavior, caller-supplied
policies and planning allowances do not implicitly adopt consensus rules.
The retained seven-node network, its history, keys and verifier are unchanged.

| Topic | Required decision or evidence |
| --- | --- |
| Development-fund allocation | At testnet launch, supply wallet count, immutable genesis recipients and each independent subsidy ratio totaling 10%. The adopted per-wallet integer floor sends residual atoms to the miner. Reserve the interface now; unconfigured new-network production must fail closed. The earlier two-wallet 5%/5% allocation is superseded. Each wallet independently receives half after 24-block maturity and half over 1,461 height-based days; existing key settings remain unchanged. No aggregate spending budget is adopted. |
| Economic revision and requalification | Implement the selected [monetary rules](v1-economics.md), mode-dependent one/five-note settlement, snapshot-height locks, pool/burn/fund rollback and exact supply audit. Earlier keys and measurements do not qualify the revision. Re-screen actual AIRs and complete fresh three-trial resource measurements before freezing. |
| Public supply metrics | Publish scheduled subsidy locks/circulation and pool/fund counters. Exact private unspent locked holdings cannot be derived without a separate privacy-affecting protocol; do not expose transaction classification or fee openings. |
| Wallet authorization evolution | Preserve the opaque owner commitment width. V2 may add a versioned in-circuit policy and uniform signature slots; V1 does not reinterpret existing owner preimages or reserved-zero ciphertext bytes. See [the V2 design](v2/multisignature.md). |
| Testnet issuance-fee activation | The testnet fee is fixed at 50 SIP (5,000,000,000 atoms), credited entirely to a dedicated development-fund account. That account is not configured: keep issuance admission closed and fail closed. Configure its authenticated destination and implement atomic payment consumption/fund credit, replay rejection and reorg restoration alongside issuance acceptance. The isolated proof's external SIP-payment verification gate is not that state transition. The mainnet issuance fee remains undecided. |
| Non-SIP minimum output | Review the experimental minimum of one atomic unit for non-SIP outputs and 10,000 atoms for SIP. Define the adopted asset-aware rule and its wallet implications before activation; the pre-economic-revision profile records the earlier experimental relation. |
| Issuance resource bounds | Adopt canonical metadata/name limits, initial-note limits, record/ciphertext/proof limits and per-block issuance byte and CPU limits. Until then, planning issuance allowances cannot establish complete worst-case bandwidth or permanent storage. |
| Final envelope | Freeze the canonical three-output envelope, version/suite framing and admission identity. The body codec implements 2,027 bytes; the 2,115-byte permanent-position ledger and 2,184-byte envelope prefix include proposed framing and are not activated node formats. |
| Standalone verifier limits | Qualify malformed-proof decoding and allocation, per-proof CPU and charged-memory bounds, concurrency/in-flight limits and full-block verification under the new relation. Prior two-output verifier budgets do not automatically qualify multi-asset admission. |
| Database and storage overhead | Measure actual block/issuance encodings, indexes, state trees, write amplification, WAL and compaction peaks under sustained load. Disk-lifetime estimates remain conditional until these costs and issuance bounds are qualified. |
| Multi-asset admission integration | The pre-economic-revision b7/q41/g20 profile met the three-trial two-second generation criterion and has a 655,360-byte transaction cap. Implement and qualify its canonical wallet/envelope/node decoder; the unchanged prior two-output decoder remains limited to 524,288 bytes. The cap is not a mathematical bound on every randomized proof. |
| Runtime and optimization evidence | Three qualified proving trials do not bound grinding tails, shared-host contention or whole-node sustained load. Column/opening-size optimization remains separate; adopt smaller caps or lower bandwidth only after a source-bound profile revision and equivalent security/resource measurements. |

Node integration must resolve these questions through one deterministic,
integer-only, atomic block transition shared by production and validation.
Independent security review, wallet recovery, backup restoration, real
three-day retention and full-network resource acceptance remain additional
activation gates. No active-network change follows from this document.
