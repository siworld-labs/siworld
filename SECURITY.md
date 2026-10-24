# Security Policy

## Supported status

SIWORLD is an unaudited research prototype. No version is supported for production use or real funds. Mock-proof development networks provide no proof security. Real-proof testnets retain the cryptographic, network and operational limitations described in [the security model](docs/security-model.md).

## Vulnerability reporting

Use [private vulnerability reporting](https://github.com/siworld-labs/siworld/security/advisories/new). Include the affected revision and component, impact, prerequisites, reproduction steps and a minimal test case where possible. Exclude personal data, live credentials and actual wallet secrets. Do not disclose an unpatched vulnerability in a public issue.

Relevant areas include consensus divergence, invalid proof acceptance, encoding ambiguity, double spending, privacy leakage, key custody, RPC authorization, storage corruption and unsafe recovery.

## Disclosure

Reports are assessed for reproducibility and impact. Fixes require regression coverage and a documented compatibility analysis. Public advisories should describe affected revisions, mitigations and remaining limitations without disclosing reporter identity unless the reporter requests attribution.
