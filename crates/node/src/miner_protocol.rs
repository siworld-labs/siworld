//! Versioned authentication contract shared by miners and trusted proof workers.
//!
//! Shared shape checks for the bounded local worker control transport.
//! These fields alone do not authenticate a machine or certificate;
//! `worker_transport` proves possession of a separately pinned secret.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_NAME: &str = "siworld/worker";
pub const PROTOCOL_VERSION: u16 = 1;
pub const ALPN: &str = "siworld-worker/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRole {
    Miner,
    ProofWorker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryClass {
    /// The peer or path may recover without changing credentials or config.
    Transient,
    /// Retry would repeat a deterministic configuration or authentication
    /// failure and must stop until an operator changes the pinned inputs.
    Permanent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handshake {
    pub protocol: String,
    pub version: u16,
    pub role: WorkerRole,
    pub trusted_machine: bool,
    /// Public credential selector; never used as a bearer credential.
    pub token_digest: [u8; 32],
    pub certificate_fingerprint: [u8; 32],
    pub container_size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPeer {
    pub role: WorkerRole,
    pub token_digest: [u8; 32],
    pub certificate_fingerprint: [u8; 32],
    pub container_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeError {
    Protocol,
    Version,
    Role,
    UntrustedMachine,
    Token,
    Certificate,
    ContainerSize,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Protocol => "worker protocol mismatch",
            Self::Version => "worker version mismatch",
            Self::Role => "worker role mismatch",
            Self::UntrustedMachine => "worker machine is not trusted",
            Self::Token => "worker token mismatch",
            Self::Certificate => "worker certificate mismatch",
            Self::ContainerSize => "worker container size mismatch",
        })
    }
}

impl std::error::Error for HandshakeError {}

impl HandshakeError {
    pub const fn retry_class(self) -> RetryClass {
        match self {
            Self::Protocol
            | Self::Version
            | Self::Role
            | Self::UntrustedMachine
            | Self::Token
            | Self::Certificate
            | Self::ContainerSize => RetryClass::Permanent,
        }
    }
}

pub fn validate_handshake(
    offered: &Handshake,
    expected: &ExpectedPeer,
) -> Result<(), HandshakeError> {
    if offered.protocol != PROTOCOL_NAME {
        return Err(HandshakeError::Protocol);
    }
    if offered.version != PROTOCOL_VERSION {
        return Err(HandshakeError::Version);
    }
    if offered.role != expected.role {
        return Err(HandshakeError::Role);
    }
    if !offered.trusted_machine {
        return Err(HandshakeError::UntrustedMachine);
    }
    if offered.token_digest != expected.token_digest {
        return Err(HandshakeError::Token);
    }
    if offered.certificate_fingerprint != expected.certificate_fingerprint {
        return Err(HandshakeError::Certificate);
    }
    if offered.container_size != expected.container_size {
        return Err(HandshakeError::ContainerSize);
    }
    Ok(())
}

pub fn retry_class_for_io(kind: std::io::ErrorKind) -> RetryClass {
    match kind {
        std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::Interrupted
        | std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::AddrNotAvailable
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::UnexpectedEof => RetryClass::Transient,
        std::io::ErrorKind::BrokenPipe => RetryClass::Transient,
        _ => RetryClass::Permanent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> ExpectedPeer {
        ExpectedPeer {
            role: WorkerRole::ProofWorker,
            token_digest: [7; 32],
            certificate_fingerprint: [8; 32],
            container_size: 16,
        }
    }

    fn offered() -> Handshake {
        Handshake {
            protocol: PROTOCOL_NAME.into(),
            version: PROTOCOL_VERSION,
            role: WorkerRole::ProofWorker,
            trusted_machine: true,
            token_digest: [7; 32],
            certificate_fingerprint: [8; 32],
            container_size: 16,
        }
    }

    #[test]
    fn accepts_a_pinned_trusted_worker() {
        assert_eq!(validate_handshake(&offered(), &expected()), Ok(()));
    }

    #[test]
    fn deterministic_auth_and_shape_failures_are_permanent() {
        for change in [
            HandshakeError::Protocol,
            HandshakeError::Version,
            HandshakeError::Role,
            HandshakeError::UntrustedMachine,
            HandshakeError::Token,
            HandshakeError::Certificate,
            HandshakeError::ContainerSize,
        ] {
            let mut peer = offered();
            match change {
                HandshakeError::Protocol => peer.protocol = "other".into(),
                HandshakeError::Version => peer.version += 1,
                HandshakeError::Role => peer.role = WorkerRole::Miner,
                HandshakeError::UntrustedMachine => peer.trusted_machine = false,
                HandshakeError::Token => peer.token_digest = [1; 32],
                HandshakeError::Certificate => peer.certificate_fingerprint = [1; 32],
                HandshakeError::ContainerSize => peer.container_size = 32,
            }
            assert_eq!(validate_handshake(&peer, &expected()), Err(change));
            assert_eq!(change.retry_class(), RetryClass::Permanent);
        }
    }

    #[test]
    fn only_transport_failures_are_retryable() {
        assert_eq!(
            retry_class_for_io(std::io::ErrorKind::TimedOut),
            RetryClass::Transient
        );
        assert_eq!(
            retry_class_for_io(std::io::ErrorKind::ConnectionReset),
            RetryClass::Transient
        );
        assert_eq!(
            retry_class_for_io(std::io::ErrorKind::PermissionDenied),
            RetryClass::Permanent
        );
        assert_eq!(
            retry_class_for_io(std::io::ErrorKind::ConnectionRefused),
            RetryClass::Transient
        );
    }
}
