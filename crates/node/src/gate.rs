//! Connection limits and peer bans.
//!
//! The gate caps pending and established inbound connections, inbound
//! connections per remote IP and connections per peer, and refuses peers it
//! has banned. A peer is banned for [`BAN_DURATION`] when it sends an invalid
//! block or message, or when the invalid transactions it sends add up to
//! [`BAN_SCORE`]; scores halve on every tick. A ban covers the peer's identity
//! and, since an identity is free to replace, the IP addresses it connected
//! from, so a banned IP is refused before the handshake. Loopback addresses
//! are exempt from per-IP limits and IP bans, so that several local nodes can
//! run side by side.
//!
//! Nothing here is logged: addresses and identities stay in memory.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::core::transport::PortUse;
use libp2p::core::{multiaddr::Protocol, ConnectedPoint, Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionEstablished, ListenFailure};
use libp2p::swarm::{
    dummy, ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;

/// Most inbound connections still in their handshake.
pub const MAX_PENDING_INBOUND: usize = 32;
/// Most established inbound connections.
pub const MAX_INBOUND: usize = 16;
/// Most established inbound connections from one non-loopback IP address.
pub const MAX_INBOUND_PER_IP: usize = 4;
/// Most established connections with one peer, inbound and outbound.
pub const MAX_PER_PEER: usize = 2;
/// How long a ban lasts.
pub const BAN_DURATION: Duration = Duration::from_secs(3600);
/// Misbehaviour score at which a peer is banned.
pub const BAN_SCORE: u32 = 100;
/// Score added for an invalid transaction.
pub const INVALID_TX_SCORE: u32 = 10;

#[derive(Debug)]
struct Refused(&'static str);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

fn deny(reason: &'static str) -> ConnectionDenied {
    ConnectionDenied::new(Refused(reason))
}

/// The IP address in a multiaddr, unless it is a loopback address.
fn remote_ip(address: &Multiaddr) -> Option<IpAddr> {
    let ip = match address.iter().next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    (!ip.is_loopback()).then_some(ip)
}

struct Connection {
    peer: PeerId,
    /// The remote IP of an inbound connection, unless it is loopback.
    inbound_ip: Option<IpAddr>,
    inbound: bool,
}

#[derive(Default)]
pub struct Gate {
    pending_inbound: usize,
    connections: HashMap<ConnectionId, Connection>,
    scores: HashMap<PeerId, u32>,
    banned_peers: HashMap<PeerId, Instant>,
    banned_ips: HashMap<IpAddr, Instant>,
}

impl Gate {
    /// Whether `peer` is banned at `now`.
    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.banned_peers
            .get(peer)
            .is_some_and(|until| *until > now)
    }

    fn ip_banned(&self, ip: Option<IpAddr>, now: Instant) -> bool {
        ip.and_then(|ip| self.banned_ips.get(&ip))
            .is_some_and(|until| *until > now)
    }

    /// Bans `peer` and the IP addresses of its inbound connections.
    pub fn ban(&mut self, peer: PeerId, now: Instant) {
        let until = now + BAN_DURATION;
        self.banned_peers.insert(peer, until);
        self.scores.remove(&peer);
        for c in self.connections.values().filter(|c| c.peer == peer) {
            if let Some(ip) = c.inbound_ip {
                self.banned_ips.insert(ip, until);
            }
        }
    }

    /// Adds `score` to `peer`'s misbehaviour score and bans it once the score
    /// reaches [`BAN_SCORE`]. Returns whether the peer is now banned.
    pub fn penalize(&mut self, peer: PeerId, score: u32, now: Instant) -> bool {
        let total = self.scores.entry(peer).or_default();
        *total = total.saturating_add(score);
        if *total >= BAN_SCORE {
            self.ban(peer, now);
            return true;
        }
        false
    }

    /// Halves every score and forgets expired bans.
    pub fn decay(&mut self, now: Instant) {
        self.scores.retain(|_, s| {
            *s /= 2;
            *s > 0
        });
        self.banned_peers.retain(|_, until| *until > now);
        self.banned_ips.retain(|_, until| *until > now);
    }

    fn admit_pending(&mut self, remote: &Multiaddr, now: Instant) -> Result<(), ConnectionDenied> {
        if self.ip_banned(remote_ip(remote), now) {
            return Err(deny("banned address"));
        }
        if self.pending_inbound >= MAX_PENDING_INBOUND {
            return Err(deny("too many pending inbound connections"));
        }
        self.pending_inbound += 1;
        Ok(())
    }

    fn admit(
        &self,
        peer: PeerId,
        inbound_ip: Option<IpAddr>,
        inbound: bool,
        now: Instant,
    ) -> Result<(), ConnectionDenied> {
        if self.is_banned(&peer, now) || self.ip_banned(inbound_ip, now) {
            return Err(deny("banned peer"));
        }
        let open = self.connections.values();
        if open.clone().filter(|c| c.peer == peer).count() >= MAX_PER_PEER {
            return Err(deny("too many connections with the peer"));
        }
        if inbound {
            if open.clone().filter(|c| c.inbound).count() >= MAX_INBOUND {
                return Err(deny("too many inbound connections"));
            }
            if inbound_ip.is_some()
                && open.filter(|c| c.inbound_ip == inbound_ip).count() >= MAX_INBOUND_PER_IP
            {
                return Err(deny("too many inbound connections from the address"));
            }
        }
        Ok(())
    }
}

impl NetworkBehaviour for Gate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.admit_pending(remote, Instant::now())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.pending_inbound = self.pending_inbound.saturating_sub(1);
        self.admit(peer, remote_ip(remote), true, Instant::now())?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.admit(peer, None, false, Instant::now())?;
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            }) => {
                let (inbound, inbound_ip) = match endpoint {
                    ConnectedPoint::Listener { send_back_addr, .. } => {
                        (true, remote_ip(send_back_addr))
                    }
                    ConnectedPoint::Dialer { .. } => (false, None),
                };
                self.connections.insert(
                    connection_id,
                    Connection {
                        peer: peer_id,
                        inbound_ip,
                        inbound,
                    },
                );
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => {
                self.connections.remove(&connection_id);
            }
            FromSwarm::ListenFailure(ListenFailure { .. }) => {
                self.pending_inbound = self.pending_inbound.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(ip: &str) -> Multiaddr {
        format!("/ip4/{ip}/tcp/4000").parse().unwrap()
    }

    fn listener(ip: &str) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: address("0.0.0.0"),
            send_back_addr: address(ip),
        }
    }

    /// Admits and records an inbound connection the way the swarm would.
    fn connect(gate: &mut Gate, id: usize, peer: PeerId, ip: &str) -> Result<(), ConnectionDenied> {
        let id = ConnectionId::new_unchecked(id);
        let remote = address(ip);
        gate.handle_pending_inbound_connection(id, &address("0.0.0.0"), &remote)?;
        gate.handle_established_inbound_connection(id, peer, &address("0.0.0.0"), &remote)?;
        gate.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &listener(ip),
            failed_addresses: &[],
            other_established: 0,
        }));
        Ok(())
    }

    fn close(gate: &mut Gate, id: usize, peer: PeerId, ip: &str) {
        gate.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: ConnectionId::new_unchecked(id),
            endpoint: &listener(ip),
            cause: None,
            remaining_established: 0,
        }));
    }

    #[test]
    fn inbound_connections_are_capped() {
        let mut gate = Gate::default();
        for i in 0..MAX_INBOUND {
            connect(&mut gate, i, PeerId::random(), &format!("198.51.100.{i}")).unwrap();
        }
        assert!(connect(&mut gate, 99, PeerId::random(), "203.0.113.1").is_err());
        close(&mut gate, 0, PeerId::random(), "198.51.100.0");
        connect(&mut gate, 100, PeerId::random(), "203.0.113.1").unwrap();
        assert_eq!(gate.pending_inbound, 0);
    }

    #[test]
    fn connections_per_address_and_peer_are_capped() {
        let mut gate = Gate::default();
        for i in 0..MAX_INBOUND_PER_IP {
            connect(&mut gate, i, PeerId::random(), "198.51.100.1").unwrap();
        }
        assert!(connect(&mut gate, 10, PeerId::random(), "198.51.100.1").is_err());
        // Loopback has no per-address limit.
        for i in 0..MAX_INBOUND_PER_IP + 1 {
            connect(&mut gate, 20 + i, PeerId::random(), "127.0.0.1").unwrap();
        }
        let peer = PeerId::random();
        for i in 0..MAX_PER_PEER {
            connect(&mut gate, 40 + i, peer, &format!("203.0.113.{i}")).unwrap();
        }
        assert!(connect(&mut gate, 50, peer, "203.0.113.9").is_err());
    }

    #[test]
    fn a_banned_peer_and_its_address_are_refused_until_the_ban_ends() {
        let mut gate = Gate::default();
        let now = Instant::now();
        let peer = PeerId::random();
        connect(&mut gate, 1, peer, "198.51.100.7").unwrap();
        gate.ban(peer, now);
        close(&mut gate, 1, peer, "198.51.100.7");
        assert!(gate.is_banned(&peer, now));
        // A new identity from the same address is refused before its handshake.
        assert!(gate.admit_pending(&address("198.51.100.7"), now).is_err());
        assert!(gate.admit(peer, None, false, now).is_err());
        assert!(gate.admit_pending(&address("198.51.100.8"), now).is_ok());

        let later = now + BAN_DURATION + Duration::from_secs(1);
        gate.decay(later);
        assert!(!gate.is_banned(&peer, later));
        assert!(gate.admit_pending(&address("198.51.100.7"), later).is_ok());
    }

    #[test]
    fn loopback_bans_cover_the_identity_only() {
        let mut gate = Gate::default();
        let now = Instant::now();
        let peer = PeerId::random();
        connect(&mut gate, 1, peer, "127.0.0.1").unwrap();
        gate.ban(peer, now);
        assert!(gate.admit_pending(&address("127.0.0.1"), now).is_ok());
        assert!(gate.admit(peer, None, true, now).is_err());
        assert!(gate.admit(PeerId::random(), None, true, now).is_ok());
    }

    #[test]
    fn invalid_transactions_add_up_to_a_ban_and_scores_decay() {
        let mut gate = Gate::default();
        let now = Instant::now();
        let peer = PeerId::random();
        let per_ban = BAN_SCORE.div_ceil(INVALID_TX_SCORE);
        for _ in 1..per_ban {
            assert!(!gate.penalize(peer, INVALID_TX_SCORE, now));
        }
        gate.decay(now);
        assert!(!gate.penalize(peer, INVALID_TX_SCORE, now));
        for _ in 1..per_ban {
            gate.penalize(peer, INVALID_TX_SCORE, now);
        }
        assert!(gate.is_banned(&peer, now));
    }
}
