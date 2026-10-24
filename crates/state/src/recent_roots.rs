//! Recent-roots accumulator 𝒜 (docs/protocol.md): a Poseidon2 Merkle tree
//! over a ring buffer of the last W blocks. Position `h mod W` holds block h's
//! entry `Poseidon2(TAG_ANCHOR; r_h, h ‖ base_fee(h))`, where `r_h` is the
//! commitment-tree root after block h; unfilled positions are the zero digest.
//! A transaction proves membership against one of these roots without
//! revealing which.

use std::collections::VecDeque;

use siworld_core::issuance::{epoch_of, fee_base};
use siworld_core::{Digest, Height};
use siworld_crypto::{anchor_entry, empty_leaf, merkle_node};

#[derive(Clone, Debug)]
pub struct RecentRoots {
    window: u32,
    /// Ascending by height.
    entries: VecDeque<(Digest, Height)>,
    /// The tree in heap order: `nodes[1]` is the root, the children of node i
    /// are 2i and 2i + 1, and position p's leaf is `nodes[W + p]`. `nodes[0]`
    /// is unused.
    nodes: Vec<Digest>,
}

/// The standard fee tier of h's epoch, as the 𝒜 entry commits to it.
pub fn base_fee(height: Height) -> u64 {
    fee_base(epoch_of(height))
}

impl RecentRoots {
    /// An empty window of W positions.
    ///
    /// # Panics
    ///
    /// If W is not a power of two.
    pub fn new(window: u32) -> Self {
        assert!(
            window.is_power_of_two(),
            "anchor window must be a power of two"
        );
        let w = window as usize;
        let mut nodes = vec![empty_leaf(); 2 * w];
        for i in (1..w).rev() {
            nodes[i] = merkle_node(&nodes[2 * i], &nodes[2 * i + 1]);
        }
        Self {
            window,
            entries: VecDeque::new(),
            nodes,
        }
    }

    /// Tree depth: log₂ W.
    pub fn depth(&self) -> u32 {
        self.window.trailing_zeros()
    }

    /// Records the commitment-tree root after block `height`, which must
    /// follow the latest recorded height.
    pub fn push(&mut self, root: Digest, height: Height) {
        if let Some((_, last)) = self.latest() {
            assert_eq!(height, last + 1, "𝒜 records consecutive heights");
        }
        self.entries.push_back((root, height));
        while self.entries.len() > self.window as usize {
            self.entries.pop_front();
        }
        let mut idx = self.leaf_index(height);
        self.nodes[idx] = anchor_entry(&root, height, base_fee(height));
        while idx > 1 {
            idx /= 2;
            self.nodes[idx] = merkle_node(&self.nodes[2 * idx], &self.nodes[2 * idx + 1]);
        }
    }

    fn leaf_index(&self, height: Height) -> usize {
        self.window as usize + (height % u64::from(self.window)) as usize
    }

    /// If the root is in the window, returns its height (the highest one if the
    /// same root appears more than once).
    pub fn height_of(&self, root: &Digest) -> Option<Height> {
        self.entries
            .iter()
            .rev()
            .find(|(r, _)| r == root)
            .map(|(_, h)| *h)
    }

    pub fn latest(&self) -> Option<(Digest, Height)> {
        self.entries.back().copied()
    }

    /// The 𝒜 root; written into the state root and used as a public input of
    /// the container proof.
    pub fn accumulator_root(&self) -> Digest {
        self.nodes[1]
    }

    /// The root after [`Self::push`], without changing the window.
    pub fn accumulator_root_after_push(&self, root: &Digest, height: Height) -> Digest {
        let mut idx = self.leaf_index(height);
        let mut acc = anchor_entry(root, height, base_fee(height));
        while idx > 1 {
            let sibling = &self.nodes[idx ^ 1];
            acc = if idx & 1 == 0 {
                merkle_node(&acc, sibling)
            } else {
                merkle_node(sibling, &acc)
            };
            idx /= 2;
        }
        acc
    }

    /// Siblings from block h's entry up to the root, least significant level
    /// first, while h is in the window.
    pub fn path(&self, height: Height) -> Option<Vec<Digest>> {
        self.entries.iter().any(|(_, h)| *h == height).then(|| {
            let mut idx = self.leaf_index(height);
            let mut siblings = Vec::with_capacity(self.depth() as usize);
            while idx > 1 {
                siblings.push(self.nodes[idx ^ 1]);
                idx /= 2;
            }
            siblings
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(h: u8) -> Digest {
        Digest([h; 32])
    }

    #[test]
    fn old_roots_fall_out_of_window() {
        let mut a = RecentRoots::new(4);
        for h in 0..6u8 {
            a.push(root(h), u64::from(h));
        }
        assert_eq!(a.height_of(&root(1)), None);
        assert_eq!(a.height_of(&root(2)), Some(2));
        assert_eq!(a.height_of(&root(5)), Some(5));
        assert_eq!(a.path(1), None);
        assert!(a.path(2).is_some());
    }

    #[test]
    fn root_after_push_matches_pushing() {
        for n in 0..10u8 {
            let mut a = RecentRoots::new(4);
            for h in 0..n {
                a.push(root(h), u64::from(h));
            }
            let h = u64::from(n);
            let predicted = a.accumulator_root_after_push(&root(99), h);
            a.push(root(99), h);
            assert_eq!(predicted, a.accumulator_root());
        }
    }

    /// The root is the Merkle tree over `h mod W`, with zero digests where no
    /// block has been recorded yet, and paths are least significant first.
    #[test]
    fn root_is_the_ring_tree_of_anchor_entries() {
        let mut a = RecentRoots::new(4);
        for h in 0..6u8 {
            a.push(root(h), u64::from(h));
        }
        // Positions 0..3 hold heights 4, 5, 2, 3.
        let leaf = |h: u8| anchor_entry(&root(h), u64::from(h), base_fee(u64::from(h)));
        let left = merkle_node(&leaf(4), &leaf(5));
        let right = merkle_node(&leaf(2), &leaf(3));
        assert_eq!(a.accumulator_root(), merkle_node(&left, &right));
        assert_eq!(a.path(5), Some(vec![leaf(4), right]));
        assert_eq!(a.path(2), Some(vec![leaf(3), left]));

        let mut b = RecentRoots::new(4);
        b.push(root(0), 0);
        let z = Digest::ZERO;
        assert_eq!(
            b.accumulator_root(),
            merkle_node(&merkle_node(&leaf(0), &z), &merkle_node(&z, &z))
        );
    }

    #[test]
    fn entry_commits_to_the_base_fee_of_its_epoch() {
        let h = siworld_core::params::EPOCH_BLOCKS * 30;
        assert_ne!(base_fee(h), base_fee(0));
        assert_eq!(base_fee(h), fee_base(30));
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn window_must_be_a_power_of_two() {
        RecentRoots::new(100);
    }
}
