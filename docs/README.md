# Technical Documentation

Start with [the technical overview](whitepaper.md), [architecture](architecture.md) and [protocol](protocol.md). [Cryptography](cryptography.md) covers proof binding; [the security model](security-model.md) defines observer and deployment boundaries.

Operational interfaces are in [node operations](node-operations.md) and [RPC and recovery](rpc.md). Validation is in [testing](testing.md), measurement in [benchmarks](benchmarks.md), and implementation invariants in [development](development.md).

Experimental [proof composition](proof-composition.md), local [worker control](worker-control.md) and [memory measurement budgets](memory-budgets.md) describe the implemented boundaries and remaining acceptance work.

The paused V2 [D8/W24 recursive suite](d8-w24-recursion.md) and its
[recursive security scope](proof-security-review.md) are research references,
not the native V1 launch criteria.
[D4 control analysis](d4-security-controls.md) explains why legacy timings do
not qualify the selected suite.

[Conditional D8 parameter screening](d8-parameter-screen.md) lists estimated
shapes and unimplemented grinding requirements. [Linux measurement](linux-proof-measurement.md)
defines the process-tree resource-control method.

The selected [native V1 transaction route](route-a-v1.md) and
[confidential fee settlement](fee-settlement.md) define the implemented native
relations and codecs. The [two-output engineering baseline](../crates/bench-d8/artifacts/v1-native-freeze.json)
remains unchanged. The [multi-asset transaction engineering profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
binds its own parameters, source hashes, public verifier key, actual-instance
security report and qualified three-trial measurements. Native node decoding,
admission and wallet/network integration, independent review and activation
remain separate gates.
The [node and network plan](v1-node-network-plan.md) covers bounded admission,
compact relay, retention, synchronization and hybrid transport.
[Native V1 acceptance](prover-acceptance.md) defines the current release gates;
[deployment and monitoring](v1-deployment.md) separates resource qualification
from isolated benchmarks. The [transport/checkpoint design](v1-network-design.md)
states identity, source-relay and bootstrap trust requirements. Recursive
aggregation is deferred to V2 and its experiments are paused.

- [Current protocol decisions](00-decisions.md)
- [Risks and Open Protocol Questions](11-risks-open-questions.md)
- [Commitment collision accounting](bht-security-accounting.md)
- [D8 dependency patch and review boundary](d8-dependency-patch.md)

- [V1 Multi-Asset Transaction Format](v1-multi-asset.md): three-output relation, issuance and integration gates.
- [V1 Storage, Retention and Bootstrap](v1-storage-and-sync.md): permanent records, three-day proof lifecycle, backup and recovery.

- [Native V1 Network Capacity Budget](v1-network-budget.md): complete bounded wire accounting at the 43-Mbps minimum, with at least 15% unused link capacity and a 100-Mbps recommendation.

- [Native Multi-Asset Proof Measurements](v1-multi-asset-evaluation.md): actual AIR shapes, eight-profile wallet-speed selection, proof-size and memory evidence, and hosted reproduction.
