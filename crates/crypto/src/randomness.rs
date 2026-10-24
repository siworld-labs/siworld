//! Secret randomness for block producers and wallets.
//!
//! Empty packages, the miner package, and wallet outputs draw their randomness
//! from a [`SecretSeed`]. Anyone who can reproduce it can recompute every empty
//! package (exposing which slots are padding) and brute-force the fee total in
//! `miner_note_cm` (exposing the real-transaction count), so production code can
//! only obtain one from the operating system's random number generator.

use siworld_core::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::expand;

/// 256 bits of secret randomness. Values are derived from it with
/// [`SecretSeed::derive`] and independent sub-seeds with [`SecretSeed::child`].
///
/// Production code obtains one only through [`SecretSeed::from_os_rng`]; the
/// deterministic constructor exists only with the `insecure-deterministic`
/// feature, for tests and the devnet. The type is neither `Copy` nor `Clone`,
/// `Debug` does not print it, and its owned storage is zeroized on drop.
pub struct SecretSeed(Digest);

impl SecretSeed {
    /// Draws a fresh seed from the operating system.
    pub fn from_os_rng() -> Result<Self, getrandom::Error> {
        let mut seed = Self(Digest::ZERO);
        getrandom::fill(&mut seed.0 .0)?;
        Ok(seed)
    }

    /// **Insecure.** A seed fixed by `seed`, for reproducible tests and devnet
    /// runs. Anyone who knows `seed` can tell padding from real transactions and
    /// recover fee totals.
    #[cfg(feature = "insecure-deterministic")]
    pub fn insecure_deterministic(seed: Digest) -> Self {
        Self(seed)
    }

    /// A pseudorandom value for `label` and `index`.
    pub fn derive(&self, label: &str, index: u64) -> Digest {
        expand(&self.0, label, index)
    }

    /// An independent seed for `label` and `index`, as secret as this one.
    pub fn child(&self, label: &str, index: u64) -> SecretSeed {
        SecretSeed(expand(&self.0, label, index))
    }
}

impl Zeroize for SecretSeed {
    fn zeroize(&mut self) {
        self.0 .0.zeroize();
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretSeed {}

impl core::fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretSeed(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_seeds_are_fresh() {
        let a = SecretSeed::from_os_rng().unwrap();
        let b = SecretSeed::from_os_rng().unwrap();
        assert_ne!(a.derive("x", 0), b.derive("x", 0));
    }

    #[test]
    fn derive_and_child_separate_labels_and_indices() {
        let s = SecretSeed::from_os_rng().unwrap();
        assert_ne!(s.derive("x", 0), s.derive("x", 1));
        assert_ne!(s.derive("x", 0), s.derive("y", 0));
        assert_eq!(s.derive("x", 0), s.derive("x", 0));
        let c = s.child("x", 0);
        assert_ne!(c.derive("x", 0), s.derive("x", 0));
        assert_eq!(c.derive("x", 0), s.child("x", 0).derive("x", 0));
    }

    #[test]
    fn debug_hides_the_seed() {
        let s = SecretSeed::from_os_rng().unwrap();
        assert_eq!(format!("{s:?}"), "SecretSeed(..)");
    }

    #[test]
    fn seed_storage_can_be_erased_and_is_erased_on_drop() {
        fn requires_drop_erasure<T: ZeroizeOnDrop>() {}
        requires_drop_erasure::<SecretSeed>();
        let mut seed = SecretSeed::from_os_rng().unwrap();
        seed.zeroize();
        assert_eq!(seed.0, Digest::ZERO);
    }

    #[cfg(feature = "insecure-deterministic")]
    #[test]
    fn deterministic_seed_is_reproducible() {
        let a = SecretSeed::insecure_deterministic(Digest([1; 32]));
        let b = SecretSeed::insecure_deterministic(Digest([1; 32]));
        assert_eq!(a.derive("x", 3), b.derive("x", 3));
    }
}
