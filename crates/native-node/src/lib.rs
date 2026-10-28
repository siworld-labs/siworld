//! Native V1 engineering chain and network interfaces, separate from the retained node.
#![forbid(unsafe_code)]

pub mod fund_spend;
pub mod local;
pub mod mining;
pub mod pool;
pub mod producer;
pub mod proof_codec;
pub mod proofs;
pub mod service;
pub mod state;
pub mod store;
pub mod wire;

pub mod admission;
pub mod audit;
pub mod chain;
pub mod p2p;
pub mod runtime;
pub mod sync;
pub mod wallet;
pub(crate) mod wallet_crypto;

#[cfg(test)]
mod fixtures;
