# Native V1 Cryptographic Construction

The [economic relations](v1-economics.md) use revision
`native-v1-economics-1`. Actual-AIR screening and 39 reference-host trials
cover the revised transaction, settlement and issuance relations. Public-key
reproduction and complete CI remain release checks; independent review and
network activation remain separate.

Status: implemented isolated native proof relations and selected integration
requirements. **Engineering target ≥80-bit quantum security, pending independent review.**
No independent full-system cryptographic approval is recorded.

## Suite and relations

The native suite is KoalaBear D8, standard Plonky3 Poseidon2 W24 and twelve
canonical base-field elements per digest. Plonky3 and `p3-security` are pinned;
D8 support and modified transcript/grinding behavior are covered by the
[dependency patch boundary](d8-dependency-patch.md).

The [transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
uses log blowup 7, 41 queries, 20-bit query/batch grinding, zero commitment
grinding, binary folding and final-polynomial log length zero. It binds
source/dependency identities, public verifier data and actual-instance security
and resource evidence. Settlement and issuance use separately measured
b8/q36/g20 profiles. The [three-relation engineering manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
records 576 settlement positions and three initial issuance notes with
source-bound public preprocessing keys and complete actual-AIR reports.
Independent key reproduction is required before release. These
fixed scopes do not adopt issuance policy or qualify other capacity keys;
independent approval and activation remain separate. See
[reproduction](native-proof-profiles.md).

The two-input/three-output transaction relation enforces per-asset integer
conservation and SIP-only confidential fees. It checks anchor membership in a
depth-12 recent-root tree, and binds ciphertext bytes, the accepted snapshot
context, input unlock heights and fee commitment. A real input's committed
unlock height cannot exceed the trusted selected snapshot height. Native
issuance constrains hidden minted supply; ML-DSA-65 verifies the declaration
outside its AIR. Native settlement binds fee commitments to all one/five
SIP-only miner reward notes, the public mode and trusted economic context. Node acceptance must
reconstruct all trusted statements rather than accept peer-supplied roots,
keys, subsidies or asset registry decisions.

## Security accounting

Require conjectured classical security ≥128 bits. Johnson Fiat–Shamir query
and enforced-grinding terms must retain ≥80 bits after quantum halving;
challenge-domain terms receive the same floor. Selected Merkle/commitment BHT
collision terms must be ≥80 bits. Evaluate each AIR and protocol composition.
The selected transaction ledger reports approximately 81.692 quantum-halved
Johnson challenge bits, approximately 185 conjectured classical bits and
123.333 BHT commitment-collision bits; these are estimator results for the
fixed instance. The 32-byte application BLAKE3 binding is separate from the
Plonky3 estimator and has a nominal 85.333-bit BHT collision model requiring review.

The [BHT ledger](bht-security-accounting.md) explains model and digest-capacity
conversions. Raw classical estimator values, quantum conversions and
application hashes are separate quantities. A passing screen is not a
full-system post-quantum security proof. Hiding randomness, transcript
consistency, dependency changes, signature/transport authentication and
resource admission require independent review.

## Encryption and fee commitments

ML-KEM-768 and ChaCha20-Poly1305 protect recipient outputs. Change uses a
256-bit ChaCha20-Poly1305 key derived with domain-separated BLAKE3 KDF.
Output commitments are authenticated, and all ciphertext bytes are bound by
the transaction proof. The AIR does not prove encryption correctness.
Wallets must self-check before broadcast and validate AEAD and recovered
commitments on receipt. Padding performs genuine ephemeral-key encryption.

Fee commitments conceal openings on chain. The private sidecar carries the
opening without an extra signature or encryption layer; recipients validate
its transaction binding and recomputed commitment. Planned authenticated
hybrid transport protects sidecar contents on the connection. It does not
hide them from the recipient or hide peer endpoints. Fee sidecars and proving
randomness must not enter public logs or immutable public data.

## Legacy and V2 boundaries

The runnable legacy node uses D4/W16 and recursive aggregation with pinned
root keys; that classical configuration fails the selected native quantum
target. See [legacy cryptography](legacy/cryptography.md) for its set-hash and
multiplicity assumptions. Recursive aggregation and historical compression
are [paused V2 work](v2/README.md). Neither legacy timing nor a recursive
parameter estimate qualifies native V1.
