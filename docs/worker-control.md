# Miner and Trusted Proof-Worker Control Protocol

Status: implemented, opt-in loopback control listener with bounded handshake,
heartbeat and reconnection. Encrypted remote job transport and independent
security review remain open. This endpoint does not dispatch proof jobs.

## Listener and lifecycle

`siworld-node run --worker-control FILE` loads an owner-only configuration and
passes it to `service::Config.worker`. Without that option the service creates
no worker listener. The listener permits only loopback addresses, 1–8 active
connections and an I/O deadline of at most 10 seconds. Each handshake frame is
at most 4096 bytes. The checked connection accepts only one-byte control
heartbeats; unsupported commands close the connection without buffering a job.

A semaphore reservation spans connection acceptance, the entire handshake and
the authenticated session. Rejection, timeout, EOF and task cancellation release
it. The service owns the listener task and its session tasks; shutdown closes
them before draining any non-preemptible proof kernel. A rejected connection
does not stop the listener or remove another session's reservation.

The configuration contains `listen`, a 64-hex-digit `token_hex`, a 32-byte
`certificate_fingerprint` array, `max_connections` and `io_timeout_ms`. The
proof capacity is derived from genesis, not the configuration file. Private
configuration and credential files must never enter version control.

## Authentication and shape checks

The server sends a fresh 32-byte challenge. The client supplies its own fresh
nonce, a typed handshake and a keyed BLAKE3 transcript authenticator. The reply
has a distinct direction tag and authenticates the same transcript and error
classification. Only the separately pinned 32-byte secret keys these messages;
the public token digest is a selector, not a bearer credential. Neither a token
digest nor a previously accepted transcript proves possession for a new server
challenge. Secret comparisons use the hash library's constant-time equality.

The shared shape validator checks protocol `siworld/worker`, version `1`, role,
trusted-machine assertion, token digest, configured fingerprint and container
size. The fingerprint and trust flag are authenticated configuration claims;
this TCP endpoint does not validate a TLS certificate or attest a machine.
`siworld-worker/1` is reserved as the future encrypted transport's ALPN, not a
claim that raw TCP negotiates TLS or QUIC. Local control authentication supplies
no remote confidentiality or post-quantum peer-identity acceptance.

## Errors and reconnection

Credential and shape mismatches, malformed frames, unsupported commands and
invalid local configuration are permanent failures. The current heartbeat call
stops on its first such failure. Refusal, reset, broken pipe, EOF and I/O timeout
are transient. `WorkerClient` discards the failed stream, reconnects and repeats
the complete challenge handshake within a configured 1–8 attempt limit and a
backoff of at most one second. It never retries a deterministic authentication
failure indefinitely or resubmits a proving job after an ambiguous disconnect.

## Job boundary and validation

The listener grants no wallet-spending, fund-signing, consensus mutation or
block-publication authority. A later encrypted job protocol must add bounded
frame/queue byte reservations, job identities, cancellation and result
verification before carrying private witnesses. A configured digest is not a
substitute for verified encrypted transport identity.

Socket tests cover valid handshakes, each shape mismatch, incorrect secrets,
permanent-error retry suppression, refusal, timeout, oversized frames,
connection teardown/reconnection and reservation release. Service shutdown
must also close its listener and active sessions. These tests establish local
control behavior only; the existing libp2p block protocol remains separate.
