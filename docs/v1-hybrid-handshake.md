# Native V1 Hybrid TLS Handshake Profile

Status: TLS 1.3 with X25519MLKEM768 and exporter-bound Ed25519 plus ML-DSA-65
authentication is the selected native V1 transport construction. The concrete
provider, certificate policy and authentication encoding are implemented in an
optional engineering adapter. `native-p2p` adds explicit pinned TCP listening,
reconnect and native session admission; default builds do not enable them.
Canonical vectors, dependency/resource qualification, independent composition
review and independent-host acceptance remain gates. The implementation and
test definitions are not evidence that those gates have passed. The identity
module supplies private custody and dual-signed descriptors; it does not
establish a TLS connection by itself.

## Selected transport construction

The dedicated native libp2p connection upgrade uses this TLS construction
with both ephemeral X25519 and ML-KEM-768 contributions and both identity
signatures required.
Noise is not a native V1 upgrade or fallback. A failed TLS or dual-identity
handshake closes the connection without negotiating a weaker transport.
The retained network uses a separate protocol and is unchanged.

## Construction and review boundary

Use a maintained TLS 1.3 implementation with the X25519MLKEM768 group from
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) and the TLS protocol
specified by [RFC 9846](https://www.rfc-editor.org/info/rfc9846/).
Require `TLS_CHACHA20_POLY1305_SHA256` and exactly X25519MLKEM768. The latter
encodes the ML-KEM contribution before X25519: client share 1,216 bytes,
server share 1,120 bytes and combined secret 64 bytes. An all-zero X25519
result must abort. The provider performs the standard TLS key schedule;
SIWORLD must not implement a second hybrid combiner, concatenate traffic keys,
XOR secrets, or derive application keys directly from either component.

The rationale is reuse of a published hybrid exchange with the TLS
HKDF-SHA256 schedule, bidirectional Finished verification and maintained record
protection. The exact security assumptions and error handling still require
review of the selected implementation. TLS authentication with only Ed25519
does not meet the V1 dual-identity requirement. The additional exporter-bound
authentication described below is the selected SIWORLD composition pending
independent review; the TLS RFCs do not approve its authentication encoding,
pin-distribution policy or implementation.

Candidate dependency selection must demonstrate the exact hybrid group, strict
key checks, exporter API, record limits, key erasure and cancellation behavior.
Pin the library, cryptographic provider and all transitive revisions, collect
advisories/licenses and reproduce known-answer vectors before adoption.
A resource or dependency conflict blocks activation until a reviewed profile
revision; it does not permit a custom exchange or classical group.

## TLS restrictions

Use an exclusive libp2p upgrade name `/siworld/native-hybrid/1` and the identical
ALPN value. Require TLS 1.3 on the first connection attempt. Offer no legacy
Noise upgrade, plaintext alternative, older TLS version or classical-only
group. Reject a different selected group, cipher suite, ALPN or version.
The upgrade must not retry under weaker parameters after any failure.

Disable PSKs, session tickets/resumption, 0-RTT, renegotiation and post-handshake
identity authentication. Every connection establishes fresh X25519 and ML-KEM
material. The initiator generates the ephemeral ML-KEM key pair; the responder
encapsulates once. Both generate fresh X25519 keys and independent connection
nonces. ML-KEM decapsulation or TLS Finished failures use one generic wire
failure. Neither branch may continue using just the other shared secret.

Require mutual Ed25519 TLS authentication with one bounded self-signed leaf
certificate per endpoint and no downloaded chain. A dedicated verifier pins
the exact Ed25519 public key from the independently authenticated dual identity;
it verifies TLS CertificateVerify and the required certificate constraints.
It is not an accept-all certificate verifier. Network identity does not depend
on public web PKI names or fetching OCSP/AIA material. The certificate template,
DER bound, validity policy and strict SPKI parsing must be specified and tested
with the selected TLS implementation before enabling this profile.
The current compact pin file stores a fingerprint, not the full public keys;
the provider must also load and verify the corresponding public
descriptor before dialing or accepting. The opt-in runtime enforces that
requirement through independently persisted pins and complete peer descriptors. A pin file alone is insufficient TLS
configuration, and a descriptor supplied by an unauthenticated connection must
not fill that gap.

## Mandatory dual-identity authentication

Only the following authentication messages may cross the protected TLS channel
until both endpoints finish this stage. They are never sent in plaintext.
TLS Finished must already have verified in both directions. Obtain 32 bytes
from the TLS exporter with label `EXPORTER-SIWORLD-native-dual-auth-v1` and
context equal to the canonical 96-byte network/genesis/verifier binding. The
exporter is derived from the completed TLS handshake; do not use an early
exporter or a channel binding supplied by the remote peer.

The operator or an authenticated discovery policy supplies the expected full
descriptor fingerprint for each endpoint. A classical PeerId, DNS name or a
self-signed descriptor received on this connection is not that policy. Reject
unknown or changed pins in this initial profile. A future permissionless peer
discovery and pin-rotation policy requires a separate review.

Every message has this exact 11-byte header: magic `SWHH`, little-endian u16
version 1, u8 message kind and little-endian u32 payload length. No extension,
padding, duplicate or trailing byte is allowed at this layer. TLS itself may
fragment a message. A frame length is checked before any allocation or body
read. Connection initiator/responder roles are separate from a node's mining
or validation role.

Messages must occur in this order:

| Kind | Sender | Payload bytes | Payload |
| --- | --- | ---: | --- |
| 1 | Initiator | 5,532 | Initiator hello |
| 2 | Responder | 5,532 | Responder hello |
| 3 | Initiator | 3,373 | Ed25519 signature then ML-DSA-65 signature |
| 4 | Responder | 3,373 | Ed25519 signature then ML-DSA-65 signature |
| 5 | Initiator | 32 | Transcript hash before this ready message |
| 6 | Responder | 32 | Transcript hash before this ready message |

A hello contains four little-endian u16 values (profile 1, TLS version
`0x0304`, group `0x11ec`, cipher `0x1303`), u8 connection role (1 or 2), a
nonzero 32-byte fresh nonce, the expected remote fingerprint (32 bytes), and
the 5,459-byte descriptor from [the identity format](v1-native-identity.md).
Both descriptors must verify both possession signatures, match the trusted
network/genesis/verifier binding and match the expected local and remote pins.
The two endpoints and the two nonces must be distinct. The negotiated TLS
parameters must match the hello tuple exactly; a peer cannot choose algorithms
by changing these application fields.

Start SHA-256 with the bytes `siworld native hybrid transcript v1`, a zero byte,
the trusted 96-byte binding, initiator fingerprint, responder fingerprint and
the 32-byte local TLS exporter output. Append every exact header and payload
in the stated order. Transport fragmentation does not enter this transcript.
The exporter commits to the TLS handshake context and exchanged ephemeral
material; the application transcript additionally commits to both descriptors,
expected pins, offered/selected fixed suite, connection roles and fresh nonces.

For kind 3 or 4, both signatures cover the bytes
`siworld native hybrid authentication v1`, a zero byte, the u8 sender role and
the SHA-256 transcript hash immediately before that message. ML-DSA uses context
`siworld native hybrid v1`. Strict Ed25519 and ML-DSA-65 verification are both
required against the sender's pinned descriptor. Kind 4 therefore covers kind 3
as well as both hellos. Each signature covers the complete ordered prefix;
neither signs its own bytes. Descriptor possession signatures cannot substitute
for these fresh channel-bound authentication signatures.

Verify a signature message before appending it to the accepted transcript.
After both authentication messages verify, exchange kinds 5 and 6 inside the
TLS channel and compare their exact transcript hashes before appending them.
These acknowledgments, together with bidirectional TLS Finished, confirm the
authenticated endpoint's view of the completed binding. Missing, reordered,
replayed or incorrect acknowledgments close the channel. Only then can the
provider construct the existing crate-private `Authenticated` capability and
open native protocol streams. Neither the parser nor a transcript-shape helper
can create that capability.

## Records, limits and cleanup

The TLS implementation owns record authentication, sequence numbers, nonce
construction and key updates. Application code must not select nonces or reset
record sequence counters. Corrupt records, sequence exhaustion, truncation,
unexpected close and missing `close_notify` produce a failed session; a partial
native frame is never committed as a request. A new connection starts a fresh
handshake. No sidecar or transaction is accepted before authentication.

Proposed operational limits are a TLS plaintext fragment limit of 8 KiB, at
most 8 KiB of TLS handshake wire bytes, at most 16 KiB for an authentication
frame, at most 32 KiB of total pre-admission wire bytes and one five-second
monotonic deadline from accepted/dialed socket to both ready messages. The six
application frames total 17,940 plaintext bytes; the remaining wire budget
must include TLS record headers, tags, certificates, alerts and fragmentation.
The TLS budget is a measured bound, not an assumption that every provider's
default buffering satisfies it. Close on excessive fragmentation or budget
exhaustion before retaining additional bytes.

Keep the existing 16 unfinished-handshake limit and reserve 256 KiB of owned
state per handshake, at most 4 MiB across unfinished handshakes, before reading.
These reservations consume the same shared `Budget` maximum as retained native
payloads; the 4 MiB category cap is not additional capacity. Exhausted or zero
shared capacity rejects admission before reading, and dropping the handshake
guard releases both its shared bytes and category allowance. Reserve TLS-owned
buffers, certificate parsing, descriptors and any queue entries against that
reservation.
Apply bounded global/per-source admission before public-key work and measure
CPU/RSS for both valid and malformed traffic. Use aggregate local failure codes;
do not publish addresses, private keys, individual fees or transaction/time
associations. Local exhaustion and scheduling delays are not peer misconduct.

Request a standard TLS traffic-key update before either direction reaches
`2^20` protected records or 1 GiB of plaintext under one traffic key, whichever
comes first; respect any stricter library limit. Close and establish a new full
hybrid handshake at least hourly, since traffic-key updates alone add no fresh
X25519/ML-KEM entropy. Incomplete update, stalled update, unsupported update or
counter overflow closes the connection. The reviewed provider must bound
in-flight frames and updates and prevent overlapping update storms.

Erase ephemeral private keys, decapsulation keys, component shared secrets,
handshake secrets, exporter buffers, superseded traffic keys and partial secret
buffers on success, timeout, cancellation and every error path. Persist only
the long-lived service identity. Do not log TLS secrets or enable a key-log
callback in public or engineering builds used for wallet traffic.

## Acceptance gates

Before production activation, complete an independent review of this
composition, authenticated pin distribution and dependency revisions; freeze
canonical positive and negative vectors; and demonstrate:

- Different network, genesis, verifier, endpoint pins, roles, nonces, descriptors,
  algorithm tuple or exporter rejects the connection.
- Classical-only negotiation, unknown upgrades and downgraded retry fail closed.
- Both signatures are independently necessary; recording another session's
  descriptor or authentication messages cannot authenticate a new connection.
- Missing/incorrect TLS Finished and either ready message prevent application
  admission; no unauthenticated byte reaches transaction/sidecar processing.
- Decapsulation errors, malformed public keys and signature failures have
  generic wire behavior; cancellation frees all reservations and secret buffers.
- Real listeners enforce wall deadlines, bounded fragmentation, concurrency,
  record limits, updates and reconnect without unbounded retained buffers.
- Independent hosts synchronize and relay compact blocks, recover partitions
  and select/reorganize valid forks using the native consensus path.

The current identity tests and transport-interface tests satisfy none of the
unimplemented cryptographic-provider or independent-host gates by themselves.

## Implemented admission boundary

The transport interface requires an `ExpectedPeer` containing a full verified
descriptor and a matching independently authenticated `PeerPin`, bound to the
local network, genesis and verifier manifest. The caller supplies this trusted
configuration before dialing or accepting. The constructor verifies possession
signatures and pin equality; it cannot establish that the caller obtained the
pin through a trusted channel. Peer discovery and pin distribution remain
separate requirements.

`AdmissionContext` adds an explicit initiator/responder role, cooperative
cancellation and one absolute five-second deadline. The outbound helper starts
that budget before its TCP dial; the inbound helper starts it after accept.
Both pass the original context to the provider and native Hello exchange. A
capability tied to a different role, peer, context, deadline or cancellation
instance cannot be admitted, so constructing a new context does not extend an
existing capability's budget. Handshake reservations are released on rejection,
cancellation, timeout and successful admission.

The crate-private capability constructor compares the provider's observed
descriptor and connection role with that context and rejects parameter metadata
that indicates a different TLS version, group, cipher, ALPN, resumption or early
data. Those comparisons are interface guards. Parameter values supplied by a
provider are assertions, not cryptographic verification, and do not prove a
completed TLS handshake, exporter binding, fresh dual signatures or key
confirmation. These guards alone supply no cryptographic provider. The optional
`native-p2p` adapter obtains the capability only from its completed hybrid TLS
upgrade and dual-authentication exchange.

Cancellation and deadline checks occur at I/O boundaries. The cooperative token
cannot interrupt a blocked socket or listener by itself, and static socket
timeouts do not establish the whole admission wall-clock guarantee. A reviewed
provider and resident listener must supply actual interruption and bounded I/O,
including reads performed internally by TLS. The one-shot blocking listener is
not a cancellation-aware resident service.

## Candidate transcript and lifecycle primitives

The internal identity API has a separate candidate-domain signature primitive
for a future reviewed provider. Both signatures bind the network, genesis,
verifier, sender connection role, ordered endpoint fingerprints, two distinct
nonzero connection nonces, a provider-derived transport binding and the exact
preceding transcript hash. It uses the existing strict Ed25519 and hedged
ML-DSA-65 implementations and a fixed 3,373-byte signature encoding. Descriptor
possession signatures cannot substitute for these signatures. This API neither
generates the nonces nor verifies their freshness, the key exchange, the
provider's hashes or its pin-distribution policy. It cannot create an
`Authenticated` capability. Its separate candidate domain and encoding do not
implement or freeze the six-frame TLS authentication encoding above. A TLS
provider must implement that encoding explicitly and pass its canonical vectors;
relabeling the candidate helper does not establish exporter-bound authentication.

The provider-independent peer scheduler accepts at most 64 configured pinned
fingerprints and retains at most 16 pending attempts and 16 established
sessions, including attempts awaiting actual closure. It uses caller-supplied
monotonic elapsed milliseconds, a five-second admission deadline, an hourly
session lifetime and exponential retry delay capped at 60 seconds with bounded
scheduling jitter. Authenticated protocol misconduct or explicit trusted local
policy disables automatic retry until reconfiguration. Unauthenticated claims
and record-authentication failures cannot quarantine a legitimate configured
pin: they close the attempt and back off under the same fixed transport policy.
Temporary unavailability and local resource exhaustion also retain the same
peer identity and back off. A generation bound to one scheduler instance rejects
stale worker completions. For simultaneous pending connections, the smaller
pinned fingerprint is the preferred initiator. Superseded attempts remain
charged until the driver acknowledges I/O and worker cleanup.

Configured-peer metadata and attempt metadata reserve 256 and 512 logical
bytes respectively from the shared transport `Budget`. These reservations are
in addition to the provider's handshake and payload reservations in that same
budget; they are not a process RSS bound. The scheduler owns no sockets,
cryptographic provider, database or worker threads. Returning cancellation
work does not close a socket or interrupt blocked I/O. A resident driver must
perform those operations, preserve the single consensus owner, and pass actual
listener, reconnect, shutdown and resource-exhaustion tests before activation.

## Dependency compatibility assessment

The following versions were inspected as source candidates. They do not
qualify a provider or establish an enabled connection. The native-node crate
has its own workspace; any candidate integration must pin the TLS library,
cryptographic provider, enabled features and transitive revisions in its exact
native lockfile. Versions in the separate repository workspace lockfile do not
establish the native dependency graph. Keep those integration receipts separate
from the immutable proof-source and proof-parameter profiles.

| Component | Inspected version | Available interface | Required integration or review |
| --- | --- | --- | --- |
| `rustls` | 0.23.46 | Explicit `CryptoProvider` cipher/group lists, TLS 1.3-only builder, X25519MLKEM768, negotiated-group inspection, exporter, traffic-key refresh, custom certificate verifiers and signers | Pin the exact provider, constrain every offered algorithm, implement certificate policy and dual authentication, test receive limits and cancellation |
| `aws-lc-rs` / `aws-lc-sys` | 1.19.0 / 0.47.0 | ML-KEM-768 and X25519 used by the rustls hybrid group; bundled AWS-LC 5.12.0 | Review transitive native code, supported-target build receipts, vectors, secret cleanup, advisories and licenses |
| `libp2p-tls` | 0.7.0 | Asynchronous libp2p connection-upgrade example using rustls and `futures-rustls` | Its stock protocol, identity policy, certificates, fallback groups and key logging do not implement this profile; use a dedicated reviewed native upgrade |
| `futures-rustls` | 0.26.0 | TLS streams compatible with the asynchronous I/O traits used by libp2p upgrades | Prove bounded scheduling and cancellation through the selected stream adapter |
| `tokio-rustls` | 0.26.6 | TLS streams, access to rustls state and initialization hooks for Tokio I/O | Alternative for a direct Tokio socket layer, not directly compatible with the synchronous native `Read + Write` interface or libp2p's futures I/O traits |
| `rcgen` | 0.13.2 | Ed25519 certificate algorithm and `RemoteKeyPair` signing interface | Specify bounded canonical certificate content and use a narrow signer without exporting the identity seed |

In the inspected rustls source, the hybrid implementation checks the exact
share lengths, uses the ML-KEM component first and supports TLS 1.3. Its test
`hybrid_kx_component_share_not_offered_unless_supported_separately` demonstrates
that restricting the provider's groups to X25519MLKEM768 removes a separately
offered X25519 share. Merely enabling `prefer-post-quantum` changes preference;
it does not prohibit classical negotiation. The candidate adapter must configure
an exclusive group list and reject an unexpected negotiated group.

The stock `libp2p-tls` 0.7.0 constructors use ALPN `libp2p`, upgrade name
`/tls/1.0.0`, ephemeral P-256 certificate keys, libp2p identity extensions and
default key-exchange groups. They also install `rustls::KeyLogFile`, which can
write traffic secrets when `SSLKEYLOGFILE` is configured. These are concrete
configuration differences from the selected profile. A native upgrade
must explicitly retain `NoKeyLog` and test that setting `SSLKEYLOGFILE` cannot
create a key-log file. It must require both native identity signatures before
returning an authenticated capability, even after successful TLS authentication.

The inspected rustls `set_buffer_limit` API limits outbound application-data
buffering. `max_fragment_size` controls emitted plaintext records. Neither is
a receive-side certificate, handshake-allocation or total wire-byte limit.
The provider must count incoming and outgoing encrypted bytes, bound read
buffers before handing bytes to TLS, and account for the implementation's
handshake deframing and certificate parsing allocations. The proposed 8 KiB
handshake and 32 KiB admission limits require adversarial measurements of that
adapter; setting the two rustls options alone is insufficient. A nonblocking
driver or an explicitly bounded unbuffered driver must enforce the absolute
deadline while network reads are stalled.

The candidate versions include native C cryptographic code. Linux and macOS
builds need a reviewed C toolchain; the standard non-FIPS aws-lc-rs build does
not require CMake. Windows assembly/toolchain and prebuilt-NASM policies need
separate receipts. No FIPS certification claim follows from these features.
An exact native-workspace lockfile, enabled-feature report, license inventory,
advisory scan and supported-target build matrix remain adoption gates.

## Inactive transport candidate

The optional native-node feature `hybrid-tls-candidate` implements a dedicated
libp2p connection upgrade, mutual pinned Ed25519 certificates, the completed
TLS exporter and the six-message dual-authentication exchange. It uses
`rustls` 0.23.46, `aws-lc-rs` 1.19.0, `aws-lc-sys` 0.47.0,
`futures-rustls` 0.26.0, `libp2p-core` 0.44.0, `rcgen` 0.13.2 and
`x509-parser` 0.18.1. The separate `libp2p-tls` crate is a source reference,
not a native dependency. Its constructors are not used.

Each candidate upgrade reserves its shared handshake allowance before
certificate construction. The resulting opaque connection retains that
allowance until destruction. Both client and server require the exclusive
group, cipher, version and ALPN, disable key logging and resumption, and reject
early data. The raw I/O adapter limits reads to TLS record boundaries and
yields between reads so the TLS driver can finish before prefetched application
data consumes its smaller handshake budget. One absolute admission deadline
and an independently polled cancellation timer bound stalled asynchronous I/O;
timeout drops the owned operation and transport.

The candidate certificate template is a single self-signed Ed25519 v3 leaf,
at most 2,048 DER bytes, with the exact pinned SPKI and a fixed subject/issuer
common name `SIWORLD native peer`. It has no extensions or unique identifiers.
Validity starts 300 seconds before creation and ends 24 hours after creation;
verification uses the TLS provider's current time and rejects longer spans,
malformed or noncanonical DER, additional certificates and OCSP data. A narrow
signer accesses the persisted identity without exporting private seeds or
PKCS#8. Configurations are created per attempt; a future reusable credential
cache must refresh before expiry without rotating the persisted identity.

The TLS authentication signer has its own typed domain and context matching
the six-message format. The earlier generic channel-signature candidate is
unchanged. Completed exporter material is kept locally in a zeroizing buffer;
neither the peer nor an application caller supplies the provider binding.

The candidate output exposes no stream accessor, application I/O, PeerId-only
authentication result or public conversion into an `Authenticated` capability.
The `hybrid-tls-candidate` feature alone remains inactive. The additional
`native-p2p` feature supplies a crate-internal socket adapter that transfers the
verified stream into native session admission; it retains the handshake charge
through native Hello and then accounts established stream buffers separately.
The standalone single-node command does not open peer sockets. Unit
tests exercise actual rustls/AWS-LC hybrid negotiation over fragmented I/O,
both identity signatures, classical-only rejection, malformed records and
authentication frames, pin/context/replay rejection, cancellation and retained
reservation lifetime. Remote execution and exact dependency review are
required; the test definitions alone are not acceptance evidence.

To reproduce candidate checks on an isolated supported host:

```sh
AWS_LC_SYS_USE_SYSTEM=0 cargo test --release --locked \
  --manifest-path crates/native-node/Cargo.toml \
  --features hybrid-tls-candidate --lib p2p::hybrid_tls::
AWS_LC_SYS_USE_SYSTEM=0 cargo test --release --locked \
  --manifest-path crates/native-node/Cargo.toml \
  --features hybrid-tls-candidate --lib identity::tls_
```

Builds must use the locked bundled AWS-LC source and reject environment or
configuration overrides that link an unrecorded system library. Preserve the
dependency license notices in any binary distribution. Existing upstream
rustls audit reports do not cover this integration, the current AWS-LC version
or the SIWORLD authentication composition. The opt-in socket bridge and
resident lifecycle below have actual-listener test definitions; their observed
exact-source execution, adversarial CPU/RSS measurements and independent-host
acceptance remain separate evidence. Established connections use bounded full
reauthentication limits rather than an application traffic-key-update API.

## Opt-in resident runtime integration

`native-p2p` adds `run-network DIRECTORY PEER_CONFIG` and `peer-pin` to the
engineering CLI. The default feature set does not expose these commands.
The [runtime procedure](v1-native-runtime.md#pinned-resident-engineering-service)
specifies exact configuration fields and independently verified pin import.
The service applies libp2p connection-upgrade traits directly to raw TCP;
there is no Swarm, discovery, multiplexing, automatic trust-on-first-use or
public-network activation.

The listener loads an existing independently created identity and full trusted
peer descriptors before traffic. The initiator sends a bounded 36-byte `SWPR`
plus fingerprint routing hint in plaintext so the responder can select a local
pin. That hint is visible service metadata, never authentication. Unknown hints
are dropped and cannot install a pin or penalize an identity as authenticated
misconduct. Full hybrid TLS, both exporter-bound signatures and native Hello
still bind the actual peer and context before commands reach the owner.

Nonblocking TCP plus timer-driven polling interrupts stalled TLS/native I/O.
One original five-second budget covers dial/accept, routing, TLS, dual auth and
Hello. The adapter preserves the handshake reservation through Hello; incomplete
admission and cancellation release it only when the connection is dropped.
Established streams reserve buffers and enforce per-direction encrypted-byte
and record caps plus a 50-minute maximum age. New paired sync cycles require
sufficient remaining wire/record/time allowance; otherwise the connection
closes and fresh full authentication occurs after scheduler backoff. These
limits do not claim measured RSS or application-level TLS key updates.

A single owner controls Node, its redb store, fork choice and production commits.
At most 16 socket workers exchange charged owned commands through a 32-entry
queue. Workers do not acquire the database across I/O. Retained block/proof
reservations follow batch messages through verification and atomic adoption.
The resident driver permits only the smaller pinned fingerprint to initiate
connections, including reconnects, and retains superseded attempt charges
until cleanup. Both endpoints require symmetric trusted peer configurations
and reachable listeners; there is no reverse-dial, NAT traversal or discovery
fallback. A connection still synchronizes both directions. Failed sessions
retry under bounded policy with the same pin and fresh authentication. Missing identity, failed replay or missing
local reward evidence never creates replacement genesis, keys or wallet data.

The resident protocol currently alternates periodic full-proof pull/serve
turns. Compact recovery and transaction/sidecar APIs exist in the library but
are not dispatched by this resident loop. It supplies neither wallet/issuance
RPC ingress nor Dandelion++. Exactly one owned background prover job performs
prover construction, padding preparation or block assembly; a separate worker
performs PoW. Captured state, permits and settings bind results to the original
template, and stale work is discarded. Snapshot/result reservations remain
charged until worker exit. The owner continues polling I/O and control work
during proving, but verifies imported full-proof batches and returned work
serially. Synchronous validation can therefore delay status, admission or
shutdown; measure those latencies and process RSS before deployment.

Shutdown stops admission, cancels connection tasks and stale work, joins owned
workers, then independently replays accepted history and verifies indexed local
reward receipts before reporting a stopped state. Restart retains the existing
identity and canonical state. Current-source execution of these paths remains
required release evidence; source availability alone closes no acceptance gate.

Required resident-service regression tests include:

- Simultaneous inbound/outbound connections, duplicate dial resolution,
  disconnection/reconnect and bounded backoff with no identity replacement.
- Stalled sockets during TLS, each dual-authentication frame, native Hello,
  control messages, sync batches and compact-block proof fetch; one absolute
  deadline, cancellation and complete reservation cleanup in every phase.
- Exhausted handshake, stream, queue, verification and global memory budgets;
  a slow or malformed peer cannot block a healthy peer or status/shutdown work.
- Real-provider negotiation with only the frozen group/cipher/version/ALPN,
  unknown/changed pins, exporter mismatch, signature substitution, key update,
  hourly reconnect, truncation and key-log environment rejection.
- Packet arrivals during local production, stale verification results,
  interrupted atomic commits and restart with the same tip/state fingerprint.
- Independent-host transaction/sidecar admission, compact relay, partition
  recovery, competing forks and reorganization through the common native
  consensus transition, including wallet reward rescan after a reorganization.

Three-day proof pruning, permanent public-data storage and checkpoint restore
remain separate persistence gates. A resident-service test cannot establish
their retention or recovery guarantees.
