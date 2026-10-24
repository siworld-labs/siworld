//! Public statement of the container proof: the root statement of
//! docs/protocol.md ("the merge statement"), which the Plonky3 aggregation in
//! `crates/bench-stark` proves. The verifier recomputes ΣE from the block's
//! slots and checks the proof against these values.

use siworld_core::params::COINBASE_MATURITY;
use siworld_core::{Commitment, ContainerProof, Digest, Height};
use siworld_crypto::{to_field, SetSum, SET_LEN};
use siworld_poseidon2::{felt_from_canonical, limbs, PrimeCharacteristicRing, DIGEST, F, LIMBS};

/// The root decomposes the height and the miner package's unlock height
/// (height + [`COINBASE_MATURITY`]) into this many bits, so both must stay
/// below 2^HEIGHT_BITS. A prototype bound, open in docs/security-model.md.
pub const HEIGHT_BITS: u32 = 30;

/// Offsets of the root public values:
/// [ΣE, 𝒜 root, height, cm_miner, miner share (4 limbs), count].
pub const ROOT_SET: usize = 0;
pub const ROOT_ANCHORS: usize = ROOT_SET + SET_LEN;
pub const ROOT_HEIGHT: usize = ROOT_ANCHORS + DIGEST;
pub const ROOT_CM_MINER: usize = ROOT_HEIGHT + 1;
pub const ROOT_SHARE: usize = ROOT_CM_MINER + DIGEST;
pub const ROOT_COUNT: usize = ROOT_SHARE + LIMBS;
pub const NUM_ROOT_PUBLIC: usize = ROOT_COUNT + 1;

/// Public inputs of the container proof.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ContainerPublic {
    /// ΣE over the block's slots.
    pub set_sum: SetSum,
    /// The 𝒜 root the proof used.
    pub anchors_root: Digest,
    pub height: Height,
    /// Commitment of the block's miner package, which the root derives from
    /// the fee total it accumulated plus `miner_share`.
    pub miner_note_cm: Commitment,
    /// The miner's public reward share (docs/protocol.md: the remainder of the 90/5/5
    /// split, plus any slashing bounty), as four 16-bit limbs in the circuit.
    pub miner_share: u64,
    /// Number of slots, N.
    pub count: u32,
}

impl ContainerPublic {
    /// The root public values in circuit order, or `None` if a value has no
    /// representation the circuit accepts: a non-canonical digest, a height
    /// whose unlock height reaches 2^HEIGHT_BITS, or a count that is not a
    /// canonical field element. No proof exists for such a statement.
    pub fn public_values(&self) -> Option<[F; NUM_ROOT_PUBLIC]> {
        let unlock = self.height.checked_add(COINBASE_MATURITY)?;
        if unlock >= 1 << HEIGHT_BITS {
            return None;
        }
        let mut v = [F::ZERO; NUM_ROOT_PUBLIC];
        v[ROOT_SET..ROOT_ANCHORS].copy_from_slice(&self.set_sum.0);
        v[ROOT_ANCHORS..ROOT_HEIGHT].copy_from_slice(&to_field(&self.anchors_root)?);
        v[ROOT_HEIGHT] = F::from_u64(self.height);
        v[ROOT_CM_MINER..ROOT_SHARE].copy_from_slice(&to_field(&self.miner_note_cm.0)?);
        v[ROOT_SHARE..ROOT_COUNT].copy_from_slice(&limbs(self.miner_share));
        v[ROOT_COUNT] = felt_from_canonical(self.count)?;
        Some(v)
    }
}

/// The verifier sees only the public inputs and the proof.
pub trait ContainerVerifier {
    fn verify(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool;
}
