# Contributing

## Technical requirements

Protocol behavior is described in [docs/protocol.md](docs/protocol.md). Changes must keep specifications, implementation and regression tests consistent. Unimplemented mechanisms must be identified explicitly; documentation must not imply that a design target is an implemented guarantee.

## Consensus invariants

1. Use integer atoms for amounts and fixed-point arithmetic for ratios. Floating-point arithmetic is prohibited on consensus paths.
2. Derive validation results from explicit inputs. Local clocks, randomness and unordered iteration must not determine consensus validity.
3. Apply each transaction or block atomically. A failed transition must preserve the previous state.
4. Use the same transition for block construction and validation.
5. Validate every input, reject repeated nullifiers and prevent authorization-key reuse where the relation requires it.
6. Write regression tests before changing consensus rules. Retain adversarial tests for earlier counterexamples.

## Privacy invariants

All slots in a container must have the same public structure. Do not publish paid-slot counts, padding counts, individual fees or fee totals. Logs and fixtures must not expose private credentials or link identities, nullifiers and wall-clock activity.

## Validation

Run the commands in [docs/testing.md](docs/testing.md). Changes to proof circuits require native/circuit equivalence checks, negative witnesses, statement-binding tests and verification-key compatibility analysis. Changes to formats require explicit compatibility treatment; silently accepting old and new encodings is prohibited.

## Repository content

Use English and neutral technical language in source comments, documentation, commit subjects and pull requests. Describe observable behavior, interfaces, invariants, measurements and limitations.

Publish only reviewed source code, necessary public test fixtures, specifications and reproducible validation tools. Keep internal discussions, correspondence, transcripts, personal material, working notes, decision drafts, rendered exports, branding and credentials outside version control. Translate engineering requirements into independent specifications without retaining conversational text or attribution to authoring tools.

New documentation requires an index entry and valid relative links. Benchmark claims require a pinned configuration, machine description, sample count and retained measurement evidence. Do not infer production readiness from successful tests or benchmark results.

## Change review

Use a focused pull request with the technical change, rationale, compatibility impact and validation results. Commit subjects must identify the implementation change. Contributions are licensed under GPL-3.0-only. Report suspected vulnerabilities through the [security policy](SECURITY.md).
