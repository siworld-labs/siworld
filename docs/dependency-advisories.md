# Dependency Advisory Applicability and Remediation

Status: runtime dependency update with targeted development-network regression coverage; experimental SP1 advisories remain open. Package-version comparisons and feature graphs establish the scope below. They do not establish an exhaustive vulnerability assessment or cryptographic approval.

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

## Isolated SP1 experiments

`crates/bench-stark/sp1`, its `program` guest and its `aggregate` guest are separate Cargo workspaces. They are excluded from the root and Plonky3 benchmark workspaces and are not dependencies of the default node. Their pinned SP1 6.9.0 stack retains the following advisory matches. Do not use this experimental stack as a deployment dependency or rely on its measurements as evidence of secure proof acceptance.

| Advisory | Experimental packages | Disposition |
|---|---|---|
| [GHSA-vj64-rjf3-w3v7](https://github.com/advisories/GHSA-vj64-rjf3-w3v7) | `p3-challenger` 0.4.3-succinct in the host and both guest lockfiles. | Open. A suffixed fork release is not assumed to contain the upstream 0.4.3 fix. Confirm the fork's transcript/challenger implementation against the fix before selecting an SP1 release. |
| [GHSA-3g92-f9ch-qjcm](https://github.com/advisories/GHSA-3g92-f9ch-qjcm) | `p3-symmetric` 0.4.3-succinct in the host and both guest lockfiles. | Open. Review the SP1 hashing domains, fixed-length assumptions and upstream remediation. Do not substitute an unrelated Plonky3 version into SP1 without native/guest compatibility validation. |
| [GHSA-rhfx-m35p-ff5j](https://github.com/advisories/GHSA-rhfx-m35p-ff5j) | `lru` 0.12.5 in the SP1 host lockfile. | Open. Select an SP1 dependency chain that supports `lru` 0.16.3 or newer, or review and pin an equivalent upstream fix; a forced incompatible transitive override is insufficient. |

Remediation sequence for these experiments:

1. Identify an SP1 release or maintained patch that addresses all three advisory families, including the actual fork source rather than version-string comparison alone.
2. Upgrade the host SDK, build tool and both guest runtimes together. Preserve required upstream license notices and freeze guest artifact identifiers after rebuilding.
3. Regenerate all three lockfiles, check the dependency graph, and execute host/guest proof generation, verification, negative witnesses, and aggregation compatibility tests in the required SP1 toolchain.
4. Review hash input domains and challenger use against each advisory, record any justified non-applicability, and rerun dependency screening. Until those steps pass, retain the open disposition and keep SP1 isolated.

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

The targeted regressions pass: two loopback network tests, four codec tests and five service lifecycle tests. The development feature supplies forgeable test proofs; these commands validate network behavior and do not establish proof-system security. Release/default-feature builds and required CI must pass separately before publication is accepted as validated. No claim of a fully clean repository advisory dashboard follows from this table: the experimental matches above remain deliberately unresolved.

Dependabot monitors the root workspace, Plonky3 benchmark workspace, independent native D8 and multi-asset workspaces, all three SP1 workspaces, and GitHub Actions. Automated update proposals still require graph inspection, compatibility review and the relevant tests; they must not be merged blindly or change frozen proof dependencies without the parameter/source review required by the protocol specifications.
