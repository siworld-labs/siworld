//! Nullifier set.
//!
//! Placeholder implementation: an ordered set plus a root that rolls forward in
//! insertion order. Replacing it with midstate's sparse Merkle tree will make the
//! root independent of insertion order and support non-membership proofs.

use std::collections::BTreeSet;

use siworld_core::{Digest, Nullifier};
use siworld_crypto::domain_hash;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlreadySpent(pub Nullifier);

#[derive(Clone, Debug, Default)]
pub struct NullifierSet {
    set: BTreeSet<Nullifier>,
    root: Digest,
}

impl NullifierSet {
    pub fn contains(&self, nf: &Nullifier) -> bool {
        self.set.contains(nf)
    }

    /// Inserts a nullifier. A duplicate is rejected without changing state.
    pub fn insert(&mut self, nf: Nullifier) -> Result<(), AlreadySpent> {
        if !self.set.insert(nf) {
            return Err(AlreadySpent(nf));
        }
        self.root = roll(&self.root, &nf);
        Ok(())
    }

    /// The root after inserting `nfs` in order, without changing the set. The
    /// caller checks that none is already present.
    pub fn root_after(&self, nfs: &[Nullifier]) -> Digest {
        nfs.iter().fold(self.root, |root, nf| roll(&root, nf))
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn root(&self) -> Digest {
        self.root
    }
}

fn roll(root: &Digest, nf: &Nullifier) -> Digest {
    domain_hash(
        "siworld v0 placeholder nullifier root",
        &[root.as_bytes(), nf.0.as_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_is_rejected_without_change() {
        let nf = Nullifier(Digest([5; 32]));
        let mut s = NullifierSet::default();
        s.insert(nf).unwrap();
        let root = s.root();
        assert_eq!(s.insert(nf), Err(AlreadySpent(nf)));
        assert_eq!(s.root(), root);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn root_after_matches_inserting() {
        let nf = |i: u8| Nullifier(Digest([i; 32]));
        let mut s = NullifierSet::default();
        s.insert(nf(1)).unwrap();
        let new = [nf(2), nf(3)];
        let predicted = s.root_after(&new);
        for n in new {
            s.insert(n).unwrap();
        }
        assert_eq!(predicted, s.root());
    }
}
