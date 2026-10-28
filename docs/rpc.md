# Native V1 RPC and Control Boundary

Status: native V1 RPC and wallet integration remains design work. Existing
newline-delimited loopback RPC commands belong to the
[legacy runtime](legacy/rpc.md). No HTTP native node API or native reset/mining
control is implied by the control-panel interface.

## Required capabilities

Separate read-only health access from wallet, mining and recovery capabilities.
Authenticate each endpoint, bind it to the intended network and node, and
limit request/response sizes and concurrent operations. Remote monitoring
collectors must not hold spend keys or permit arbitrary shell execution.

Read APIs should expose public chain/work progress, explicit busy/idle state,
sample freshness, bounded resource accounting and durable incident state.
Do not return individual fee openings, nullifier/time associations, public
padding classifications or sender endpoint information.

Mutation APIs need operation IDs, serialized execution, durable status and
idempotent recovery. Timeout is an unknown outcome until reconciliation; it
must not silently create a new payment or repeat a destructive operation.
Reset must distinguish disposable engineering state from retained keys,
wallet journals and permanent public data. A panel button cannot bypass
acceptance, checkpoint authentication or atomic state-transition rules.

## Wallet and recovery requirements

Durable payment identity, input reservations, local output self-check, protected
receipt material and exactly-once reconciliation are required. Backup creation
must protect secrets and require mnemonic recovery verification. Restoration
must scan permanent ciphertexts and reconstruct accepted notes without
claiming that public RPC access is cryptographic watch-only custody.

The [node/network plan](v1-node-network-plan.md),
[deployment requirements](v1-deployment.md) and
[testnet acceptance](prover-acceptance.md) define implementation and validation
milestones. No native V1 API is complete merely because those requirements
are documented.
