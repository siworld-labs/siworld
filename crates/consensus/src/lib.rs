//! Block validity and block production.
//!
//! The producer and the validator share [`transition::transition`] and
//! [`transition::check_proof`]: `builder` calls them to compute the roots and
//! check the proof after building a block, and `chain` calls them to validate a
//! block, so the two paths cannot diverge. The header does not commit to the
//! container proof, so the state transition takes none.

pub mod builder;
pub mod chain;
pub mod pow;
pub mod transition;

pub use builder::{
    assemble_body, build_block, build_unsealed, build_unsealed_with_header, BuildError, Miner,
    PendingTx,
};
pub use chain::{Accepted, Chain, TipChange};
pub use pow::{
    asert_target, beyond_future_limit, block_work, check_timestamp, check_work, check_work_after,
    median_time_past, meets_target, mine, mine_some, next_target, pow_hash,
};
pub use primitive_types::U512;
pub use transition::{check_proof, transition, BlockError, PayoutError};

/// Current block version.
pub const BLOCK_VERSION: u32 = 0;
