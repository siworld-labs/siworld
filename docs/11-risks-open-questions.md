# Risks and Open Protocol Questions

Status: unresolved V1 multi-asset protocol and qualification questions. This
register records open work under [the decisions](00-decisions.md) and
[multi-asset design](v1-multi-asset.md). Experimental behavior, caller-supplied
policies and planning allowances do not implicitly adopt consensus rules.
The retained seven-node network, its history, keys and verifier are unchanged.

| Topic | Required decision or evidence |
| --- | --- |
| Issuance fee | Fix the SI-denominated amount, accounting destination and authenticated payment-consumption rule. Specify atomic consumption, replay rejection and reorg restoration alongside issuance acceptance. The isolated proof's external SI-payment verification gate is not that state transition. |
| Non-SI minimum output | Review the experimental minimum of one atomic unit for non-SI outputs and 10,000 atoms for SI. Define the adopted asset-aware rule and its wallet implications before activation; the engineering-frozen proof profile records the current experimental relation. |
| Issuance resource bounds | Adopt canonical metadata/name limits, initial-note limits, record/ciphertext/proof limits and per-block issuance byte and CPU limits. Until then, planning issuance allowances cannot establish complete worst-case bandwidth or permanent storage. |
| Final envelope | Freeze the canonical three-output envelope, version/suite framing and admission identity. The body codec implements 2,027 bytes; the 2,115-byte permanent-position ledger and 2,184-byte envelope prefix include proposed framing and are not activated node formats. |
| Standalone verifier limits | Qualify malformed-proof decoding and allocation, per-proof CPU and charged-memory bounds, concurrency/in-flight limits and full-block verification under the new relation. Prior two-output verifier budgets do not automatically qualify multi-asset admission. |
| Database and storage overhead | Measure actual block/issuance encodings, indexes, state trees, write amplification, WAL and compaction peaks under sustained load. Disk-lifetime estimates remain conditional until these costs and issuance bounds are qualified. |
| Multi-asset admission integration | The engineering-frozen b7/q41/g20 profile meets the three-trial two-second generation criterion and has a 655,360-byte transaction cap. Implement and qualify its canonical wallet/envelope/node decoder; the unchanged prior two-output decoder remains limited to 524,288 bytes. The cap is not a mathematical bound on every randomized proof. |
| Runtime and optimization evidence | Three qualified proving trials do not bound grinding tails, shared-host contention or whole-node sustained load. Column/opening-size optimization remains separate; adopt smaller caps or lower bandwidth only after a source-bound profile revision and equivalent security/resource measurements. |

Node integration must resolve these questions through one deterministic,
integer-only, atomic block transition shared by production and validation.
Independent security review, wallet recovery, backup restoration, real
three-day retention and full-network resource acceptance remain additional
activation gates. No active-network change follows from this document.
