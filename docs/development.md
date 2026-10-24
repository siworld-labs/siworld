# Engineering Requirements

## Specification consistency

Keep implementation, [protocol](protocol.md), tests and operator interfaces consistent. Proposed mechanisms must not silently become consensus rules or be described as deployed. Protocol changes require explicit compatibility and activation analysis.

## Determinism

Consensus uses integer arithmetic, canonical encoding and explicit ordering. Validate every input and public proof field. Production and validation share one atomic transition. Randomness belongs to witness/key generation and must not change validity for an existing block.

## Dependencies and artifacts

Preserve lockfiles, exact proof versions and pinned recursion revisions. CI actions use immutable revisions. Public verification keys and proof fixtures are required artifacts. Compare regenerated keys independently with the expected relation and parameters. Build output and runtime state stay outside version control.

## Release criteria

There is no production release. A candidate requires reviewed protocol and implementation, explicit active genesis, cryptographic dependency review, a reviewed quantum-sound suite, adversarial resource/network testing, storage and recovery drills, reproducible artifacts and a compatibility policy. Mainnet placeholder fields must not launch a network.

Passing tests or low proving time does not establish readiness. Publish only reproducible measurements and claims supported by the actual configuration.
