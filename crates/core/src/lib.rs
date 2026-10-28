//! siworld consensus foundations: types, constants, and issuance rules.
//!
//! Consensus paths use integers only and never depend on local clocks,
//! randomness, or hash-map iteration order.

pub mod codec;
pub mod issuance;
pub mod params;
pub mod pow;
pub mod types;
pub mod v1_economics;

pub use types::*;
