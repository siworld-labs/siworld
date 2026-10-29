# Protocol Byte Compatibility

SIP is the token denomination; one SIP is 100,000,000 atoms. Renaming display
text and Rust identifiers does not rename an existing encoded format or signed
statement. The byte values below are retained for compatibility. Their presence
does not define a second unit or a conversion between SI and SIP.

## Retained address and storage formats

These formats belong to the retained node and wallet implementation. They are
not evidence that the native V1 wallet has protected persistent storage or a
public address-text format.

| Byte value | Definition | Compatibility boundary |
|---|---|---|
| `si`, `tsi` | [Address prefixes](../crates/node/src/address.rs#L28) | Address decoding and the domain-separated checksum bind the selected prefix. |
| `SIWALLET1:` | [Wallet envelope](../crates/node/src/keystore.rs#L13) | Password-protected wallet text envelope. |
| `SIWFULL1` | [Wallet backup](../crates/node/src/backup.rs#L21) | Encrypted full-wallet backup header. |
| `SIFUND01` | [Fund key store](../crates/node/src/fund_keys.rs#L15) | Encrypted fund custody header. |
| `SIFAPP01` | [Fund approval store](../crates/node/src/fund_approval.rs#L20) | Independent approval-key storage header. |
| `SIFPAY01` | [Fund payment journal](../crates/node/src/fund_payments.rs#L34) | Encrypted fund payment journal header. |
| `SIFULL01` | [Fund backup](../crates/node/src/fund_payments/backup.rs#L5) | Encrypted full-fund backup header. |
| `SIORDER1` | [Order journal](../crates/node/src/orders.rs#L21) | Encrypted payment-order journal header. |
| `SIRKEY01` | [Retention receiver key](../crates/node/src/retention.rs#L21) | Retained archive-receiver key envelope. |

Changing a header requires a separately specified, authenticated format
migration. It must not happen as a token-name substitution.

## Retained signed JSON names

The Rust fields use the SIP denomination, while explicit Serde names preserve
the existing signed serialization:

| Serialized name | Current Rust field | Definitions |
|---|---|---|
| `direct_si` | `direct_sip` | [FundBudget](../crates/node/src/fund_keys.rs#L159), [FundGrant](../crates/node/src/fund_keys.rs#L205) |
| `lock_si` | `lock_sip` | [FundBudget](../crates/node/src/fund_keys.rs#L161), [FundGrant](../crates/node/src/fund_keys.rs#L207) |
| `total_si` | `total_sip` | [FundBudget](../crates/node/src/fund_keys.rs#L163) |
| `max_payout_si` | `max_payout_sip` | [FundBudget](../crates/node/src/fund_keys.rs#L165), [FundGrant](../crates/node/src/fund_keys.rs#L209) |

The approval path hashes or signs these serialized bodies. Tests
`fund_policy_keeps_signed_serialization_bytes` and
`fund_grant_keeps_signed_serialization_bytes` require byte-identical JSON
round trips and reject renamed wire fields; see the
[compatibility tests](../crates/node/src/fund_keys.rs#L288).

## Domain separation and genesis identity

Protocol domain labels containing the project name `siworld` remain unchanged.
That project name is distinct from the token denomination. Examples include
the retained [address checksum domain](../crates/node/src/address.rs#L41),
[genesis identity domain](../crates/node/src/genesis.rs#L356), native
[transaction identity domain](../crates/native-node/src/wire.rs#L90), and
[wallet key-derivation domains](../crates/native-node/src/wallet.rs#L55).
No standalone token-name `SI` domain label is used by the inspected native
transaction, settlement or issuance paths.

The chain identifier remains derived from the original checked genesis data;
see [genesis hashing](../crates/node/src/genesis.rs#L331). Existing network
strings, chain identifiers, key-derivation inputs and published tags are not
renamed. A new native genesis commits its own versioned configuration; the
denomination change alone does not authorize changing these bytes.

## Non-consensus occurrences

The proof measurement JSON keys `reward_asset_constrained_si` and
`si_fee_payment_fixture_only` retain the existing evidence schema in
[native-scan](../crates/bench-multi-asset/src/bin/native-scan.rs#L158) and its
source-bound artifacts. They are measurement field names, not asset IDs,
public note fields or signed payment denominations.

Retained `.si-archive-` temporary-file names and `SI_*` crash-test environment
variables are local storage or fault-injection interfaces. They do not encode
token amounts and must not be confused with consensus byte fields. The
project names SIWORLD and SINETWORK are unaffected.
