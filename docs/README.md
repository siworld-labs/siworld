# Technical Documentation

The selected native V1 economic revision adds Voyager/Holder allocation,
height-locked notes, a public Holder pool, burn accounting and per-credit
development-fund vesting. This reopens the transaction, settlement and issuance
proof freeze. Earlier source-bound keys and measurements are retained baseline
evidence; they do not qualify the revised relations. Native integration,
independent review and public testnet acceptance remain outstanding.

## Native V1

1. [System overview](v1-overview.md): selected design, implementation status and trust boundaries.
2. [Current decisions](00-decisions.md): authoritative requirements and freeze scope.
3. [Architecture](architecture.md), [protocol](protocol.md), [cryptography](cryptography.md) and [security model](security-model.md).
4. [Monetary rules](v1-economics.md), [transaction specification](route-a-v1.md), [multi-asset relation](v1-multi-asset.md) and [confidential fee settlement](fee-settlement.md).
5. [Pre-revision proof-profile reproduction](native-proof-profiles.md), [transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json) and [actual-instance measurements](v1-multi-asset-evaluation.md).
6. [Node/network milestones](v1-node-network-plan.md), [single-node engineering runtime](v1-native-runtime.md) and [testnet acceptance](prover-acceptance.md).

## Proof implementation and measurement

- [Native proof workspace](../crates/bench-multi-asset/README.md): transaction, issuance and settlement relations and reproducible checks.
- [Collision accounting](bht-security-accounting.md), [dependency patch](d8-dependency-patch.md) and [settlement evaluation](fee-settlement-evaluation.md).
- [Measurement procedure](benchmarks.md), [Linux resource measurement](linux-proof-measurement.md) and [memory accounting](memory-budgets.md).
- [Circuit optimization](multi-asset-air-optimization.md): separate experimental work; revised production profiles require fresh screening and measurements.
- [Wallet and custody protection](v1-wallet-protection.md): lock recovery, delayed consolidation, threshold backups and offline signing interfaces.

The [two-output native baseline](../crates/bench-d8/artifacts/v1-native-freeze.json)
remains diagnostic evidence. Its decoder and resource measurements do not
qualify the three-output native node path.

## Network, storage and operations

- [Deployment and observability](v1-deployment.md): validator/miner roles, candidate hardware and private monitoring.
- [Network capacity](v1-network-budget.md): separate proof caps, complete conditional wire accounting, 43-Mbps minimum and 100-Mbps recommendation.
- [Storage and bootstrap](v1-storage-and-sync.md): permanent public records, three-day proof lifecycle, checkpoint trust, backups and recovery.
- [Transport/checkpoint design](v1-network-design.md): proposed authenticated hybrid transport and Dandelion++.
- [Native operational interfaces](node-operations.md) and [RPC boundary](rpc.md): integration status and requirements.
- [Unresolved protocol and qualification questions](11-risks-open-questions.md).

The isolated runtime has explicit engineering commands. Deployment-qualified
service interfaces and public-network artifacts remain pending. There is no privileged main node;
discovery services and the control panel have no consensus authority.

## Legacy implementation and paused V2

The [legacy documentation](legacy/README.md) covers the runnable recursive,
two-output implementation and retained seven-node N=2 classical engineering
testnet. Its full-proof replay and 100-block reorganization bound are not native
V1 rules. V1 requires independent genesis, directories and keys and imports no
retained notes, proofs or wallet state.

[V2 planning](v2/README.md) covers paused recursive aggregation, historical
compression and future uniform in-circuit multisignature authorization. Recursive timings and experimental resource ceilings do not
qualify V1. N=32 is outside the current scope.

## Development and security reporting

- [Regression coverage](testing.md), [engineering requirements](development.md) and [contribution guidance](../CONTRIBUTING.md).
- [Security reporting](../SECURITY.md) and [dependency advisory applicability](dependency-advisories.md).

Published measurements identify source, parameters, hardware and scope.
Engineering freeze, CI success, independent review and activation are distinct.
