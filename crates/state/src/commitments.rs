//! Append-only commitment tree with fixed depth D. Each append costs O(D) hashes.

use std::collections::BTreeMap;

use siworld_core::{Commitment, Digest};
use siworld_crypto::{empty_leaf, merkle_node};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeFull;

#[derive(Clone, Debug)]
pub struct CommitmentTree {
    depth: u8,
    /// `zeros[l]`: root of an empty subtree of height l.
    zeros: Vec<Digest>,
    /// `levels[l]`: existing nodes at level l (leaves are level 0); nodes not yet
    /// present on the right count as empty subtrees.
    levels: Vec<Vec<Digest>>,
}

impl CommitmentTree {
    pub fn new(depth: u8) -> Self {
        assert!((1..64).contains(&depth), "tree depth out of range");
        let mut zeros = vec![empty_leaf()];
        for l in 0..usize::from(depth) {
            let z = zeros[l];
            zeros.push(merkle_node(&z, &z));
        }
        Self {
            depth,
            zeros,
            levels: vec![Vec::new(); usize::from(depth) + 1],
        }
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn len(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    pub fn leaf(&self, index: u64) -> Option<Commitment> {
        self.levels[0].get(index as usize).map(|d| Commitment(*d))
    }

    fn node(&self, level: usize, index: usize) -> Digest {
        self.levels[level]
            .get(index)
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// Appends a commitment and returns its position. When the tree is full, rejects
    /// without changing state.
    pub fn append(&mut self, cm: Commitment) -> Result<u64, TreeFull> {
        let index = self.len();
        self.append_all(&[cm])?;
        Ok(index)
    }

    /// Appends commitments in order. If they do not all fit, rejects without
    /// changing state.
    pub fn append_all(&mut self, cms: &[Commitment]) -> Result<(), TreeFull> {
        // Ascending (level, index): each level's new nodes extend it or overwrite
        // its last node.
        for ((level, index), value) in self.updates(cms)? {
            let nodes = &mut self.levels[level];
            if index < nodes.len() {
                nodes[index] = value;
            } else {
                nodes.push(value);
            }
        }
        Ok(())
    }

    /// The root after appending `cms`, without changing the tree.
    pub fn root_after(&self, cms: &[Commitment]) -> Result<Digest, TreeFull> {
        let depth = usize::from(self.depth);
        Ok(self
            .updates(cms)?
            .get(&(depth, 0))
            .copied()
            .unwrap_or_else(|| self.root()))
    }

    /// Every node that appending `cms` writes, keyed by (level, index). O(D)
    /// hashes per commitment.
    fn updates(&self, cms: &[Commitment]) -> Result<BTreeMap<(usize, usize), Digest>, TreeFull> {
        let start = self.len();
        if cms.len() as u64 > self.capacity() - start {
            return Err(TreeFull);
        }
        let mut written = BTreeMap::new();
        for (k, cm) in cms.iter().enumerate() {
            let mut idx = (start + k as u64) as usize;
            written.insert((0, idx), cm.0);
            for level in 0..usize::from(self.depth) {
                let parent = idx / 2;
                let node = |i: usize| {
                    written
                        .get(&(level, i))
                        .copied()
                        .unwrap_or_else(|| self.node(level, i))
                };
                let value = merkle_node(&node(parent * 2), &node(parent * 2 + 1));
                written.insert((level + 1, parent), value);
                idx = parent;
            }
        }
        Ok(written)
    }

    pub fn root(&self) -> Digest {
        self.node(usize::from(self.depth), 0)
    }

    pub fn path(&self, index: u64) -> Option<MerklePath> {
        if index >= self.len() {
            return None;
        }
        let mut idx = index as usize;
        let mut siblings = Vec::with_capacity(usize::from(self.depth));
        for level in 0..usize::from(self.depth) {
            siblings.push(self.node(level, idx ^ 1));
            idx /= 2;
        }
        Some(MerklePath { index, siblings })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerklePath {
    pub index: u64,
    pub siblings: Vec<Digest>,
}

impl MerklePath {
    pub fn root(&self, leaf: &Commitment) -> Digest {
        let mut acc = leaf.0;
        let mut idx = self.index;
        for sib in &self.siblings {
            acc = if idx & 1 == 0 {
                merkle_node(&acc, sib)
            } else {
                merkle_node(sib, &acc)
            };
            idx >>= 1;
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cm(i: u8) -> Commitment {
        Commitment(Digest([i; 32]))
    }

    #[test]
    fn paths_verify_against_root() {
        let mut t = CommitmentTree::new(8);
        for i in 0..13 {
            t.append(cm(i)).unwrap();
        }
        for i in 0..13u8 {
            let p = t.path(u64::from(i)).unwrap();
            assert_eq!(p.root(&cm(i)), t.root());
            assert_ne!(p.root(&cm(i + 100)), t.root());
        }
    }

    #[test]
    fn empty_root_is_zero_subtree() {
        let t = CommitmentTree::new(4);
        assert!(t.is_empty());
        assert_eq!(t.root(), t.zeros[4]);
    }

    #[test]
    fn full_tree_rejects_without_change() {
        let mut t = CommitmentTree::new(2);
        for i in 0..4 {
            t.append(cm(i)).unwrap();
        }
        let root = t.root();
        assert_eq!(t.append(cm(9)), Err(TreeFull));
        assert_eq!(t.len(), 4);
        assert_eq!(t.root(), root);
    }

    #[test]
    fn root_after_and_append_all_match_appending_one_by_one() {
        for start in 0..6u8 {
            for k in 0..6u8 {
                let mut t = CommitmentTree::new(4);
                for i in 0..start {
                    t.append(cm(i)).unwrap();
                }
                let new: Vec<_> = (0..k).map(|i| cm(100 + i)).collect();
                let mut one_by_one = t.clone();
                for c in &new {
                    one_by_one.append(*c).unwrap();
                }
                assert_eq!(t.root_after(&new), Ok(one_by_one.root()));
                t.append_all(&new).unwrap();
                assert_eq!(t.root(), one_by_one.root());
                assert_eq!(t.len(), one_by_one.len());
                for i in 0..t.len() {
                    assert_eq!(t.path(i), one_by_one.path(i));
                }
            }
        }
    }

    #[test]
    fn batch_that_overflows_is_rejected_without_change() {
        let mut t = CommitmentTree::new(2);
        for i in 0..3 {
            t.append(cm(i)).unwrap();
        }
        let root = t.root();
        assert_eq!(t.root_after(&[cm(7), cm(8)]), Err(TreeFull));
        assert_eq!(t.append_all(&[cm(7), cm(8)]), Err(TreeFull));
        assert_eq!(t.len(), 3);
        assert_eq!(t.root(), root);
        assert!(t.root_after(&[cm(7)]).is_ok());
    }
}
