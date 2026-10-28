# V2 Shielded Multisignature Authorization

Status: selected V2 research scope; not part of the V1 consensus relation or
proof freeze. The initial target is at most 2-of-3 authorization, with hash-based
signature verification inside the transaction AIR. Algorithms, key formats,
composition and activation remain subject to a separate security review.

## Uniform transaction shape

All transactions in a V2 suite must reserve the same number and shape of
signature/witness slots, including single-owner transfers and miner padding.
Do not expose signature count, policy choice or used-slot masks as a public
transaction classifier. Prove threshold authorization, signer uniqueness,
message binding and policy membership without weakening asset conservation,
lock-height checks, nullifier uniqueness or fee privacy.

Measure the largest supported policy and dummy population before selecting
parameters. Reject missing/duplicate signers, fewer than threshold valid
signatures, cross-network/context replay, modified transaction fields and
incorrect unused-slot witnesses. Versioned activation, policy recovery,
wallet UX and public resource bounds are separate design work.

## V1 compatibility assessment

The native owner field is already an opaque twelve-element digest, encoded as
48 bytes. Keep that width and strict canonical encoding. The V1 relation
currently constrains a single-owner key preimage; it does not accept an arbitrary
policy merely because the field can hold a digest.

A future version can use an explicitly domain-separated authorization-policy
commitment in that field and verify its policy opening in a new AIR. V1 does
not need extra signature slots or fields now. Do not repurpose the note
plaintext's reserved zero bytes or relax their rejection rules: nonzero reserved
bytes remain invalid. Do not silently reinterpret old owner digests as V2
policies. Specify version/domain separation, old-note spending behavior and
migration before adding a new suite.

This preserves room in the data model without claiming unchanged verifier keys
or automatic compatibility. Actual V2 hash-signature circuits, uniform witness
slots and parameters need their own identifiers, source-bound artifacts,
benchmarks and independent review.

## V1 protections remain separate

[V1 threshold seed backups and offline-interface design](../v1-wallet-protection.md)
protect single-key custody; they do not enforce multiple approvals on chain.
No V1 transaction AIR change is introduced solely for this V2 plan. The current
V1 economic revision has its own reopened freeze and must not be conflated with
multisignature implementation.
