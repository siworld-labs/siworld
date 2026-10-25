//! Testnet node and single-machine development network.
//!
//! The testnet supports real proofs; the opt-in development network uses
//! mock proofs. Both are unaudited: **do not use with real funds.** [`node::Node`] is
//! the testnet node core (one key, a genesis file, a block store); the
//! network layer drives it. The `development` feature runs a chain with test
//! wallets on one machine. Either way, blocks are built with the consensus
//! builder and accepted through [`siworld_consensus::Chain::accept`], the same
//! `transition` path every node uses to validate blocks.

pub mod address;
pub mod amount;
pub mod backup;
pub mod devfund;
#[cfg(feature = "development")]
pub mod devnet;
pub mod fund_approval;
pub mod fund_keys;
pub mod fund_payments;
pub mod gate;
pub mod genesis;
pub mod keystore;
pub mod mempool;
pub mod miner_protocol;
pub mod node;
pub mod orders;
pub mod p2p;
pub mod payments;
pub mod retention;
pub mod rpc_auth;
pub mod secrets;
pub mod service;
pub mod wallet;
pub mod wire;
pub mod worker_transport;

pub use devfund::{DevFundSigner, PayoutRefused};
#[cfg(feature = "development")]
pub use devnet::{BlockInfo, Config, Devnet, NodeError, WALLET_NAMES};
pub use mempool::{Mempool, MempoolError, TxPow};
pub use wallet::{PayError, Wallets};

use siworld_core::Digest;

/// Full hexadecimal form of a 32-byte digest (`Digest`'s `Debug` prints only
/// the first 6 bytes).
pub fn hex(d: &Digest) -> String {
    d.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses exactly 2·N hexadecimal digits into N bytes.
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parses 64 hexadecimal digits into a digest.
pub fn parse_hex32(s: &str) -> Option<Digest> {
    parse_hex(s).map(Digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let d = Digest([0xa5; 32]);
        assert_eq!(parse_hex32(&hex(&d)), Some(d));
        assert_eq!(parse_hex32("00"), None);
        assert_eq!(parse_hex32(&"zz".repeat(32)), None);
    }
}
