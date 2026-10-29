# Native V1 RPC and Control Boundary

Status: native V1 transport activation and wallet integration remain incomplete.
The native runtime supplies the bounded local issuance dispatcher described
below; it does not open a socket or provide endpoint authentication. Existing
newline-delimited loopback RPC commands belong to the
[legacy runtime](legacy/rpc.md). No HTTP native node API or native reset/mining
control is implied by the control-panel interface.

## Native issuance dispatcher

`runtime::Node::dispatch_issuance_rpc` accepts a bounded UTF-8 JSON object with
exactly two fields: `method` set to `submitissuance`, and `record` containing
lowercase hexadecimal `IssuanceRecord` bytes. The caller must authorize the
local wallet before dispatch. A successful response returns `accepted: true`
and the public declaration digest; it acknowledges admission, not confirmation.
An exact repeat returns the same digest. A changed record cannot reuse an
already admitted declaration.

Admission checks the immutable network/policy, ML-DSA-65 signature, frozen
native issuance proof, ciphertext digests and a declaration-bound 50-SIP
payment output in canonical history or an independently admitted transaction. The dedicated fund
destination and per-block engineering limits must be configured explicitly.
An unconfigured destination fails closed. A template includes an issuance only
when its fee is already canonical or its fee transaction is included in that
template. The common block transition checks the receipt again before
atomically changing the registry. Mining the fee transaction before its
declaration therefore does not strand the payment or require a second fee.

The canonical registry and exactly-once fee receipts are recovered by verified
database replay and roll back with canonical branch replacement. Pending RPC
admissions are volatile and must be reconciled or resubmitted after restart.
Do not expose this dispatcher on a public endpoint before the authenticated
resident service and ingress resource controls are qualified.

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
