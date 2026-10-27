# Local RPC, Custody and Recovery

> **Superseded by V1 (Route A).** This page documents the legacy recursive implementation. The retained seven-node N=2 engineering testnet uses this classical proof route; it is not a native V1 testnet or post-quantum acceptance result. See the [current V1 overview](../v1-overview.md).

## Transport

RPC is newline-delimited JSON over loopback TCP, not HTTP or JSON-RPC 2.0. Every request carries a 64-hex bearer credential in `auth`. Authentication and method authorization are per request. The CLI uses `--auth-file FILE`; live secrets must not enter arguments, environment variables, URLs or logs.

The listener limits concurrent connections to 32, request lines to 64 KiB and read/write deadlines to 30 seconds. Malformed JSON and HTTP close the connection without processing a following body. Errors do not echo malformed input. Unknown methods fail closed.

## Capabilities

| File | Authority | Server enablement |
|---|---|---|
| `rpc-read.token` | Chain, address and wallet-status reads | Default |
| `rpc-spend.token` | Reads, wallet locking and payments | `--enable-wallet-spend` |
| `rpc-devfund.token` | Fund status, grants, approvals and payouts | Explicit fund configuration and mining |

Credentials are distinct. Forged permission fields grant nothing. RPC read mode is not cryptographic watch-only recovery. Wallet-spend capability has no general per-payment amount budget of its own.

## Custody

Wallet files use Argon2id and XChaCha20-Poly1305. Unlock reconstructs notes; lock removes owned spend/view keys and tracked plaintexts. Fund keys use separate encrypted custody and timed bounded grants.

Unix secret reads reject symlinks, non-regular files, foreign ownership, group/other permissions and multiple hard links. Parent directories must remain trusted. Rotate credentials with the node stopped, using `rpc-keygen`, then restart.

Owned secret buffers have redacted diagnostics and erasure where implemented. Compiler copies, traces, dependency work buffers, swap and crash dumps are not covered by a complete-memory-erasure guarantee.

## Durable submission

A payment ID identifies one immutable intent. Wallet inputs are reserved durably before proving; serialized artifacts survive restart. The bundled CLI additionally records an independent order and dispatch marker before RPC. Keep ledger, witness and independently current checkpoints in separate trust domains.

Timeout does not cancel a dispatched operation. Retry only the same ID, recipient, amount and priority. A new ID creates a distinct payment. Unknown outcomes require reconciliation. Only tracked orders known never to have been dispatched qualify for explicit cancellation.

## Recovery

Key-only backups preserve identity but omit pending payments. Full snapshots retain keys and journals and gate restored custody behind explicit reconciliation. Safe recovery also needs independently retained orders, current checkpoints and an authenticated network view. A stale backup cannot prove its own freshness.

Fund payouts use distinct payout IDs, durable intent/artifact records, witness checkpoints, single-use approvals and persistent cumulative budgets. Timed grants cannot refill persistent allowances. Restart does not restore active signing grants. Policy amendments and recovery require independent authenticated records.

The binaries' usage output defines command arguments. Tests under `crates/node/tests` cover authentication, capability separation, durable IDs, interrupted persistence, snapshots, orders, fund controls and reconciliation. They do not replace operational recovery drills.
