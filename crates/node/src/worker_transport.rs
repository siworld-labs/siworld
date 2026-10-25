//! Bounded loopback worker control transport. No proving jobs or private
//! witnesses are sent over this unencrypted connection. Remote transport
//! requires a separately reviewed encrypted peer-authentication implementation.
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{sleep, timeout},
};
use zeroize::{Zeroize, Zeroizing};

use crate::miner_protocol::{
    retry_class_for_io, validate_handshake, ExpectedPeer, Handshake, HandshakeError, RetryClass,
};

pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct WorkerToken(Zeroizing<[u8; 32]>);

impl WorkerToken {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&*self.0).as_bytes()
    }
}

pub struct WorkerConfig {
    pub listen: SocketAddr,
    pub expected: ExpectedPeer,
    pub token: WorkerToken,
    pub max_connections: usize,
    pub io_timeout: Duration,
}

/// Load an owner-only local control configuration. The genesis determines
/// container size; a configuration file cannot select another proof shape.
pub fn load_config(path: &std::path::Path, container_size: u32) -> Result<WorkerConfig, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FileConfig {
        listen: SocketAddr,
        token_hex: String,
        certificate_fingerprint: [u8; 32],
        max_connections: usize,
        io_timeout_ms: u64,
    }
    let text = crate::secrets::read_secret(path)?;
    let mut value: FileConfig =
        serde_json::from_str(&text).map_err(|_| "invalid worker control configuration")?;
    let token = crate::parse_hex::<32>(&value.token_hex);
    value.token_hex.zeroize();
    let token = WorkerToken::from_bytes(token.ok_or("worker token requires 32 bytes")?);
    local(value.listen).map_err(|_| "worker control transport requires loopback")?;
    Ok(WorkerConfig {
        listen: value.listen,
        expected: ExpectedPeer {
            role: crate::miner_protocol::WorkerRole::ProofWorker,
            token_digest: token.digest(),
            certificate_fingerprint: value.certificate_fingerprint,
            container_size,
        },
        token,
        max_connections: value.max_connections,
        io_timeout: Duration::from_millis(value.io_timeout_ms),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    hello: Handshake,
    nonce: [u8; 32],
    mac: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    error: Option<HandshakeError>,
    mac: [u8; 32],
}

fn error(kind: io::ErrorKind, text: &'static str) -> io::Error {
    io::Error::new(kind, text)
}
fn local(address: SocketAddr) -> io::Result<()> {
    if !address.ip().is_loopback() {
        return Err(error(
            io::ErrorKind::InvalidInput,
            "worker control transport requires loopback",
        ));
    }
    Ok(())
}
fn nonce() -> io::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("worker randomness unavailable"))?;
    Ok(bytes)
}
fn mac(
    token: &WorkerToken,
    direction: &[u8],
    hello: &Handshake,
    server: &[u8; 32],
    client: &[u8; 32],
    failure: Option<HandshakeError>,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(&token.0);
    h.update(b"siworld local worker control v1\0");
    h.update(direction);
    h.update(server);
    h.update(client);
    // The typed serializer has a fixed field order and no untrusted maps.
    h.update(&serde_json::to_vec(&(hello, failure)).expect("fixed handshake fields"));
    *h.finalize().as_bytes()
}
fn same(a: [u8; 32], b: [u8; 32]) -> bool {
    blake3::Hash::from(a) == blake3::Hash::from(b)
}

async fn read_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<T> {
    let n = stream.read_u32_le().await? as usize;
    if n == 0 || n > MAX_FRAME_BYTES {
        return Err(error(
            io::ErrorKind::InvalidData,
            "worker frame limit exceeded",
        ));
    }
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| error(io::ErrorKind::InvalidData, "invalid worker frame"))
}
async fn write_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| error(io::ErrorKind::InvalidData, "invalid worker frame"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(error(
            io::ErrorKind::InvalidData,
            "worker frame limit exceeded",
        ));
    }
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}
async fn deadline<T>(
    duration: Duration,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(duration, future)
        .await
        .map_err(|_| error(io::ErrorKind::TimedOut, "worker I/O deadline exceeded"))?
}

pub struct WorkerSession {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    io_timeout: Duration,
}
impl WorkerSession {
    /// Control frames are one-byte ping/pong only. Unsupported job bytes close
    /// the connection; they are never accumulated in a Vec or queued.
    async fn serve(mut self) -> io::Result<()> {
        loop {
            deadline(self.io_timeout, async {
                if self.stream.read_u8().await? != 0 {
                    return Err(error(
                        io::ErrorKind::InvalidData,
                        "unsupported worker command",
                    ));
                }
                self.stream.write_u8(0).await
            })
            .await?;
        }
    }
}

pub struct WorkerListener {
    listener: TcpListener,
    config: WorkerConfig,
    permits: Arc<Semaphore>,
}
impl WorkerListener {
    pub async fn bind(config: WorkerConfig) -> io::Result<Self> {
        local(config.listen)?;
        if config.max_connections == 0
            || config.max_connections > MAX_CONNECTIONS
            || config.io_timeout.is_zero()
            || config.io_timeout > MAX_IO_TIMEOUT
            || !same(config.expected.token_digest, config.token.digest())
        {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "invalid worker listener limits or credential selector",
            ));
        }
        Ok(Self {
            listener: TcpListener::bind(config.listen).await?,
            permits: Arc::new(Semaphore::new(config.max_connections)),
            config,
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub fn available_connections(&self) -> usize {
        self.permits.available_permits()
    }
    pub async fn accept(&self) -> io::Result<WorkerSession> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("worker listener closed"))?;
        let (mut stream, _) = self.listener.accept().await?;
        deadline(self.config.io_timeout, async {
            let challenge = Challenge { nonce: nonce()? };
            write_frame(&mut stream, &challenge).await?;
            let offer: Offer = read_frame(&mut stream).await?;
            let valid = same(
                offer.mac,
                mac(
                    &self.config.token,
                    b"client",
                    &offer.hello,
                    &challenge.nonce,
                    &offer.nonce,
                    None,
                ),
            );
            let failure = if valid {
                validate_handshake(&offer.hello, &self.config.expected).err()
            } else {
                Some(HandshakeError::Token)
            };
            let reply = Reply {
                error: failure,
                mac: mac(
                    &self.config.token,
                    b"server",
                    &offer.hello,
                    &challenge.nonce,
                    &offer.nonce,
                    failure,
                ),
            };
            write_frame(&mut stream, &reply).await?;
            if failure.is_some() {
                return Err(error(
                    io::ErrorKind::PermissionDenied,
                    "worker authentication or shape mismatch",
                ));
            }
            Ok(())
        })
        .await?;
        Ok(WorkerSession {
            stream,
            _permit: permit,
            io_timeout: self.config.io_timeout,
        })
    }
    /// Owned child tasks are aborted and dropped with this future. Rejected or
    /// timed-out peers release reservations and never close the listener.
    pub async fn serve(self) {
        let mut tasks = JoinSet::new();
        loop {
            while tasks.try_join_next().is_some() {}
            match self.accept().await {
                Ok(session) => {
                    tasks.spawn(session.serve());
                }
                Err(_) => {
                    sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

async fn connect(
    address: SocketAddr,
    hello: &Handshake,
    token: &WorkerToken,
    duration: Duration,
) -> io::Result<TcpStream> {
    local(address)?;
    deadline(duration, async {
        let mut stream = TcpStream::connect(address).await?;
        let challenge: Challenge = read_frame(&mut stream).await?;
        let client_nonce = nonce()?;
        let offer = Offer {
            hello: hello.clone(),
            nonce: client_nonce,
            mac: mac(
                token,
                b"client",
                hello,
                &challenge.nonce,
                &client_nonce,
                None,
            ),
        };
        write_frame(&mut stream, &offer).await?;
        let reply: Reply = read_frame(&mut stream).await?;
        if !same(
            reply.mac,
            mac(
                token,
                b"server",
                hello,
                &challenge.nonce,
                &client_nonce,
                reply.error,
            ),
        ) || reply.error.is_some()
        {
            return Err(error(
                io::ErrorKind::PermissionDenied,
                "worker authentication or shape mismatch",
            ));
        }
        Ok(stream)
    })
    .await
}

#[derive(Clone, Copy)]
pub struct RetryPolicy {
    pub attempts: u8,
    pub delay: Duration,
    pub io_timeout: Duration,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            delay: Duration::from_millis(100),
            io_timeout: MAX_IO_TIMEOUT,
        }
    }
}

/// Reconnects and reauthenticates on a failed heartbeat. Permanent shape or
/// credential failures stop the current call without another dial.
pub struct WorkerClient {
    address: SocketAddr,
    hello: Handshake,
    token: WorkerToken,
    policy: RetryPolicy,
    stream: Option<TcpStream>,
    permanent_failure: Option<io::ErrorKind>,
}
impl WorkerClient {
    pub fn new(
        address: SocketAddr,
        hello: Handshake,
        token: WorkerToken,
        policy: RetryPolicy,
    ) -> io::Result<Self> {
        local(address)?;
        if policy.attempts == 0
            || policy.attempts > 8
            || policy.delay > Duration::from_secs(1)
            || policy.io_timeout.is_zero()
            || policy.io_timeout > MAX_IO_TIMEOUT
        {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "invalid worker retry limits",
            ));
        }
        Ok(Self {
            address,
            hello,
            token,
            policy,
            stream: None,
            permanent_failure: None,
        })
    }
    pub async fn heartbeat(&mut self) -> io::Result<()> {
        if let Some(kind) = self.permanent_failure {
            return Err(error(kind, "worker configuration requires replacement"));
        }
        for attempt in 0..self.policy.attempts {
            let result = async {
                if self.stream.is_none() {
                    self.stream = Some(
                        connect(
                            self.address,
                            &self.hello,
                            &self.token,
                            self.policy.io_timeout,
                        )
                        .await?,
                    );
                }
                deadline(self.policy.io_timeout, async {
                    let stream = self.stream.as_mut().expect("connected stream");
                    stream.write_u8(0).await?;
                    if stream.read_u8().await? != 0 {
                        return Err(error(
                            io::ErrorKind::InvalidData,
                            "invalid worker heartbeat",
                        ));
                    }
                    Ok(())
                })
                .await
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    self.stream = None;
                    if retry_class_for_io(error.kind()) == RetryClass::Permanent {
                        self.permanent_failure = Some(error.kind());
                        return Err(error);
                    }
                    if attempt + 1 == self.policy.attempts {
                        return Err(error);
                    }
                    sleep(self.policy.delay).await;
                }
            }
        }
        unreachable!("positive bounded attempt count")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::miner_protocol::{WorkerRole, PROTOCOL_NAME, PROTOCOL_VERSION};

    #[tokio::test]
    async fn replayed_authenticator_is_rejected_on_a_fresh_challenge() {
        let token = WorkerToken::from_bytes([11; 32]);
        let hello = Handshake {
            protocol: PROTOCOL_NAME.into(),
            version: PROTOCOL_VERSION,
            role: WorkerRole::ProofWorker,
            trusted_machine: true,
            token_digest: token.digest(),
            certificate_fingerprint: [12; 32],
            container_size: 16,
        };
        let listener = WorkerListener::bind(WorkerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            expected: ExpectedPeer {
                role: hello.role,
                token_digest: hello.token_digest,
                certificate_fingerprint: hello.certificate_fingerprint,
                container_size: 16,
            },
            token: token.clone(),
            max_connections: 1,
            io_timeout: Duration::from_millis(200),
        })
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            assert!(listener.accept().await.is_err());
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let challenge: Challenge = read_frame(&mut stream).await.unwrap();
        let client = [13; 32];
        let old = [14; 32];
        assert_ne!(old, challenge.nonce);
        let offer = Offer {
            hello: hello.clone(),
            nonce: client,
            mac: mac(&token, b"client", &hello, &old, &client, None),
        };
        write_frame(&mut stream, &offer).await.unwrap();
        let reply: Reply = read_frame(&mut stream).await.unwrap();
        assert_eq!(reply.error, Some(HandshakeError::Token));
        server.await.unwrap();
    }
}
