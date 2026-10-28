# Dependency Advisory Applicability and Remediation

Status: runtime dependency update with targeted development-network regression coverage; the isolated SP1 experiments and their dependency graphs have been removed from the current source tree. Package-version comparisons and feature graphs establish the scope below. They do not establish an exhaustive vulnerability assessment or cryptographic approval.

## Node transport dependencies

The workspace selects `libp2p` 0.57.1 with default features disabled and only Tokio, TCP, DNS, Noise, Yamux, request-response and macros enabled. Its lockfile resolves `libp2p-dns` 0.45.0, `hickory-resolver`/`hickory-proto` 0.26.3, `libp2p-yamux` 0.48.0 and `yamux` 0.14.1. QUIC is not selected by the default node feature graph, although Cargo retains optional transport dependencies in the lockfile; its locked package is `libp2p-quic` 0.14.0.

| Advisory | Affected component and scope | Locked treatment | Applicability and remaining validation |
|---|---|---|---|
| [GHSA-vxx9-2994-q338](https://github.com/advisories/GHSA-vxx9-2994-q338) | Yamux malformed-frame panic; the earlier adapter compiled both 0.12 and 0.13 implementations. | Yamux 0.14.1 replaces both earlier package versions. | Yamux is enabled. Removing the old compiled implementation avoids relying on the adapter's default-configuration choice as a mitigation. |
| [GHSA-6f2x-v7q7-m7m5](https://github.com/advisories/GHSA-6f2x-v7q7-m7m5) | Hickory resolver follows irrelevant CNAME records. | Resolver 0.26.3 is outside the reported affected range ending before 0.26.2. | DNS peer resolution is enabled; resolver behavior is part of the runtime attack surface. |
| [GHSA-5j98-2g5x-46v6](https://github.com/advisories/GHSA-5j98-2g5x-46v6) | Resolver APIs obscure DNSSEC validation failures. | Resolver 0.26.3 is outside the reported affected range ending before 0.26.2. | The inspected default graph has no DNSSEC feature. That narrows current applicability; it does not justify retaining an affected resolver or claiming DNSSEC authentication. |
| [GHSA-q2qq-hmj6-3wpp](https://github.com/advisories/GHSA-q2qq-hmj6-3wpp) | Hickory DNS name-encoding CPU exhaustion. | Protocol 0.26.3 is newer than the reported fix in 0.26.1. | Hickory protocol encoding is included through DNS resolution. No application-specific claim of unreachable hostile inputs is made. |
| [GHSA-3v94-mw7p-v465](https://github.com/advisories/GHSA-3v94-mw7p-v465) | Hickory NSEC3 validation loop. | Protocol 0.26.3 is outside the reported affected 0.25 series. | DNSSEC is not selected in the inspected default graph. Validate the graph again before enabling DNSSEC or changing resolver features. |
| [GHSA-5hq8-qhww-jm7q](https://github.com/advisories/GHSA-5hq8-qhww-jm7q) | QUIC handshake certificate-expiry panic. | Optional lockfile package updated to QUIC 0.14.0, newer than the reported 0.13.1 fix. | QUIC is not enabled by the default node and no QUIC listener is configured. Enabling it requires dedicated transport tests and a renewed advisory review. |

The change preserves the selected Plonky3 package versions, source revisions and checksums. The independent native D8 and multi-asset lockfiles are not updated as part of this networking change. This update does not add the planned post-quantum hybrid handshake: the current transport remains Noise over TCP.

## Removed experimental dependency graphs

The isolated SP1 6.9.0 host, single-slot guest and aggregation guest have been removed, together with all three lockfiles and their Dependabot entries. They were not dependencies of the default node. Their historical dependency graphs contained seven advisory matches across the three families below. Removal does not repair those upstream packages or change earlier commits and tags; historical experiments remain unsupported.

| Advisory | Experimental packages | Disposition |
|---|---|---|
| [GHSA-vj64-rjf3-w3v7](https://github.com/advisories/GHSA-vj64-rjf3-w3v7) | `p3-challenger` 0.4.3-succinct in the removed host and both guest lockfiles. | Removed from the current source tree. Historical fork code is not assumed to contain the upstream fix. |
| [GHSA-3g92-f9ch-qjcm](https://github.com/advisories/GHSA-3g92-f9ch-qjcm) | `p3-symmetric` 0.4.3-succinct in the removed host and both guest lockfiles. | Removed from the current source tree. Historical hashing domains and fixed-length assumptions have not been qualified. |
| [GHSA-rhfx-m35p-ff5j](https://github.com/advisories/GHSA-rhfx-m35p-ff5j) | `lru` 0.12.5 in the removed host lockfile. | Removed from the current source tree. No compatible upstream remediation is claimed for historical builds. |

The current source tree has no SP1 build or CI entry point. The publication manifest rejects the retired subtree. Byte-frozen native D8 sources retain historical comparison comments to preserve their measured source identity; they contain no SP1 dependency or guest implementation. The fixed native proof parameters, verifier artifacts and independent dependency lockfiles are unchanged.

## Validation and update coverage

Reproduce graph inspection with:

```sh
cargo tree --locked -p siworld-node -i hickory-resolver
cargo tree --locked -p siworld-node -e features -i hickory-proto
cargo tree --locked -p siworld-node -i yamux
cargo tree --locked -p siworld-node -i libp2p-quic
```

The inverse QUIC tree is empty for the inspected macOS host and `x86_64-unknown-linux-gnu` graphs. An empty inverse QUIC tree on a tested target establishes that this package is not selected for that build; lockfile presence alone does not establish runtime use. Check every supported release target and feature set before enabling a new transport.

Run the existing loopback protocol and service regressions with development-only test fixtures:

```sh
cargo test --locked -p siworld-node --no-default-features --features development --test network
cargo test --locked -p siworld-node --no-default-features --features development --lib p2p::
cargo test --locked -p siworld-node --no-default-features --features development --lib service::tests
```

The targeted regressions pass: two loopback network tests, four codec tests and five service lifecycle tests. The development feature supplies forgeable test proofs; these commands validate network behavior and do not establish proof-system security. Release/default-feature builds and required CI must pass separately before publication is accepted as validated. Hosting-service advisory status must be checked after the removal reaches the default branch; source removal alone does not establish that the dashboard has refreshed or that all dependencies are free of advisories.

Dependabot monitors the root workspace, Plonky3 benchmark workspace, independent native D8 and multi-asset workspaces, and GitHub Actions. Automated update proposals still require graph inspection, compatibility review and the relevant tests; they must not be merged blindly or change frozen proof dependencies without the parameter/source review required by the protocol specifications.
