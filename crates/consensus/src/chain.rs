//! Block tree with fork choice by cumulative work.
//!
//! The node keeps the blocks it accepts with the cumulative work of their
//! branch, and its state is the state at the tip of the heaviest branch
//! (whitepaper §5): most work, not most blocks, so a branch of cheap blocks
//! cannot outweigh one of hard blocks. On equal work the branch seen first
//! stays.
//!
//! Reorganizations are at most [`MAX_REORG_DEPTH`] blocks deep: once the tip
//! has reached height T, the main-chain block at T − MAX_REORG_DEPTH is final
//! and a block whose branch leaves the main chain below it is rejected, before
//! its work is checked. ASERT is anchored at genesis, so a branch from far
//! below the tip is far behind schedule and would cost about one hash per
//! block; within the limit a fork block costs at least about 72 % of a block
//! on the tip (docs/protocol.md). Side blocks that can no longer become
//! the main chain are forgotten.
//!
//! A block on another branch is checked against that branch's state, rebuilt
//! by replaying the branch from a checkpoint at or below the final block, or
//! taken from the state of the side block accepted last when it extends that
//! one; undo data or snapshots replace the replay once state is persisted.

use std::collections::{BTreeMap, BTreeSet};

use primitive_types::U512;
use siworld_circuits::ContainerVerifier;
use siworld_core::params::{ChainParams, MAX_REORG_DEPTH};
use siworld_core::{Block, Digest, Header, Height, Roots};
use siworld_state::{BlockDelta, ChainState};

use crate::pow::{block_work, check_work_after};
use crate::transition::{check_proof, transition, BlockError};
use crate::BLOCK_VERSION;

pub struct Chain<V> {
    pub params: ChainParams,
    /// State at the tip of the heaviest branch.
    pub state: ChainState,
    pub verifier: V,
    /// Height of the state the node started from, the base.
    base_height: Height,
    /// The state after a main-chain block at or below the final height.
    /// Every kept branch passes through it, so branches are replayed from it.
    checkpoint: ChainState,
    /// The main chain up to this height is final: the highest tip height the
    /// node has had, less [`MAX_REORG_DEPTH`], and never below the base.
    final_height: Height,
    /// Accepted blocks that can still be on the main chain, and the base, by
    /// header hash.
    index: BTreeMap<Digest, Entry>,
    /// Hashes of the tip's branch from the base up, by height above the base.
    main: Vec<Digest>,
    /// The blocks in `index` that are not on the main chain.
    side: BTreeSet<Digest>,
    /// The state after a block in `index` other than the tip, kept so that a
    /// branch received in order costs one transition per block.
    side_state: Option<ChainState>,
}

/// How accepting a block moved the tip.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TipChange {
    /// The block is on another branch that does not outweigh the tip's.
    None,
    /// The block extends the tip.
    Extended,
    /// The tip moved to the block's branch: the blocks above height `fork`
    /// left the main chain and the branch's replaced them.
    Reorg { fork: Height },
}

/// An accepted block: the roots after it and how the tip moved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Accepted {
    pub roots: Roots,
    pub tip: TipChange,
}

/// Blocks a locator lists one by one below the tip before it starts skipping.
const LOCATOR_DENSE: u64 = 10;

struct Entry {
    /// `None` for the base.
    block: Option<Block>,
    height: Height,
    /// Timestamps after this block, as [`ChainState::timestamps`] holds them.
    timestamps: Vec<u64>,
    /// Sum of [`block_work`] from the base through this block.
    work: U512,
}

impl<V: ContainerVerifier> Chain<V> {
    pub fn new(params: ChainParams, state: ChainState, verifier: V) -> Self {
        let mut index = BTreeMap::new();
        index.insert(
            state.tip,
            Entry {
                block: None,
                height: state.height,
                timestamps: state.timestamps.clone(),
                work: U512::zero(),
            },
        );
        Self {
            params,
            main: vec![state.tip],
            base_height: state.height,
            final_height: state.height,
            checkpoint: state.clone(),
            state,
            verifier,
            index,
            side: BTreeSet::new(),
            side_state: None,
        }
    }

    /// The block with this header hash, if accepted. The base has none.
    pub fn block(&self, hash: &Digest) -> Option<&Block> {
        self.index.get(hash)?.block.as_ref()
    }

    pub fn contains(&self, hash: &Digest) -> bool {
        self.index.contains_key(hash)
    }

    /// The hash of the main chain's block at `height` (the base's at its own
    /// height).
    pub fn main_hash(&self, height: Height) -> Option<Digest> {
        let i = height.checked_sub(self.base_height)?;
        self.main.get(usize::try_from(i).ok()?).copied()
    }

    /// Main-chain hashes that tell a peer where this node is: the tip and the
    /// blocks just below it, then exponentially sparser ones, then the base.
    pub fn locator(&self) -> Vec<Digest> {
        let mut out = Vec::new();
        let mut back = 0u64;
        let mut step = 1u64;
        let top = self.main.len() as u64 - 1;
        while back < top {
            out.push(self.main[(top - back) as usize]);
            if out.len() as u64 >= LOCATOR_DENSE {
                step *= 2;
            }
            back += step;
        }
        out.push(self.main[0]);
        out
    }

    /// Up to `max` main-chain blocks after the highest locator entry on the
    /// main chain, or after the base if none is.
    pub fn blocks_after(&self, locator: &[Digest], max: usize) -> Vec<&Block> {
        let start = locator
            .iter()
            .find_map(|hash| {
                let entry = self.index.get(hash)?;
                (self.main_hash(entry.height) == Some(*hash)).then_some(entry.height)
            })
            .unwrap_or(self.base_height);
        (start + 1..)
            .map_while(|h| self.main_hash(h))
            .take(max)
            .map(|hash| self.block(&hash).expect("main chain blocks are stored"))
            .collect()
    }

    /// Cumulative work of the current tip's branch since the base state.
    pub fn tip_work(&self) -> U512 {
        self.index[&self.state.tip].work
    }

    /// Height of the final block: no block whose branch leaves the main chain
    /// below it is accepted.
    pub fn final_height(&self) -> Height {
        self.final_height
    }

    /// [`Self::accept`], returning only the roots after the block.
    pub fn apply_block(&mut self, block: &Block) -> Result<Roots, BlockError> {
        self.accept(block).map(|a| a.roots)
    }

    /// Validates a block on its parent's branch and accepts it, moving the tip
    /// to it when its branch has more work than the current tip's. On failure
    /// the chain is unchanged; only the replay checkpoint may move forward.
    ///
    /// [`BlockError::BadProof`] rejects only this copy: the header is not
    /// invalid, and the same header with a valid proof is still accepted.
    pub fn accept(&mut self, block: &Block) -> Result<Accepted, BlockError> {
        let h = &block.header;
        if h.version != BLOCK_VERSION {
            return Err(BlockError::BadVersion);
        }
        let hash = h.hash();
        if self.index.contains_key(&hash) {
            return Err(BlockError::AlreadyKnown);
        }
        let parent = self.index.get(&h.parent).ok_or(BlockError::BadParent)?;
        if !self.descends_from_final(h.parent) {
            return Err(BlockError::ReorgTooDeep);
        }
        if h.container_size != self.params.container_size {
            return Err(BlockError::BadContainerSize);
        }
        // Timestamp, ASERT target and work come before the body and before any
        // branch is rebuilt, so a header without work costs one hash chain.
        check_work_after(parent.height, &parent.timestamps, &self.params, h)?;
        if h.body_root != block.body.hash() {
            return Err(BlockError::BadBodyRoot);
        }
        let work = parent.work + block_work(&h.target);

        let on_tip = h.parent == self.state.tip;
        let mut branch = (!on_tip).then(|| self.branch_state(h.parent));
        let parent_state = branch.as_ref().unwrap_or(&self.state);
        let (delta, roots) = match check_body(parent_state, block, &self.params, &self.verifier) {
            Ok(checked) => checked,
            Err(e) => {
                if branch.is_some() {
                    self.side_state = branch;
                }
                return Err(e);
            }
        };

        // Every check has passed; from here nothing can fail.
        let tip_work = self.tip_work();
        let child = branch.as_mut().unwrap_or(&mut self.state);
        extend(child, delta, h);
        debug_assert_eq!(child.roots(), roots);
        let timestamps = child.timestamps.clone();
        self.index.insert(
            hash,
            Entry {
                block: Some(block.clone()),
                height: h.height,
                timestamps,
                work,
            },
        );
        let tip = match branch {
            None => {
                debug_assert!(work > tip_work, "every block adds work");
                self.main.push(hash);
                TipChange::Extended
            }
            Some(state) if work > tip_work => {
                self.side_state = Some(std::mem::replace(&mut self.state, state));
                let fork = self.rewrite_main(hash);
                debug_assert!(fork >= self.final_height);
                TipChange::Reorg { fork }
            }
            Some(state) => {
                self.side.insert(hash);
                self.side_state = Some(state);
                TipChange::None
            }
        };
        if tip != TipChange::None {
            self.finalize();
        }
        Ok(Accepted { roots, tip })
    }

    /// Whether the accepted block `at` is the final block or descends from it.
    fn descends_from_final(&self, mut at: Digest) -> bool {
        loop {
            let entry = &self.index[&at];
            if entry.height < self.final_height {
                return false;
            }
            if self.main_hash(entry.height) == Some(at) {
                return true;
            }
            at = entry
                .block
                .as_ref()
                .expect("the base is on the main chain")
                .header
                .parent;
        }
    }

    /// Moves the final height up after the tip moved, and forgets the side
    /// blocks that no longer descend from the final block.
    fn finalize(&mut self) {
        let height = self
            .state
            .height
            .saturating_sub(MAX_REORG_DEPTH)
            .max(self.final_height);
        if height == self.final_height {
            return;
        }
        self.final_height = height;
        let dead: Vec<Digest> = self
            .side
            .iter()
            .copied()
            .filter(|hash| !self.descends_from_final(*hash))
            .collect();
        for hash in &dead {
            self.side.remove(hash);
            self.index.remove(hash);
        }
        if let Some(state) = &self.side_state {
            if !self.index.contains_key(&state.tip) {
                self.side_state = None;
            }
        }
    }

    /// Makes `tip`'s branch the main chain; returns the height of the last
    /// block it shares with the old one.
    fn rewrite_main(&mut self, tip: Digest) -> Height {
        let mut new = Vec::new();
        let mut at = tip;
        loop {
            let height = self.index[&at].height;
            if self.main_hash(height) == Some(at) {
                let keep = (height - self.base_height) as usize + 1;
                self.side.extend(self.main.drain(keep..));
                for hash in &new {
                    self.side.remove(hash);
                }
                self.main.extend(new.into_iter().rev());
                return height;
            }
            new.push(at);
            at = self.index[&at]
                .block
                .as_ref()
                .expect("the base is on every branch")
                .header
                .parent;
        }
    }

    /// The state after the accepted block `tip`, other than the tip itself.
    fn branch_state(&mut self, tip: Digest) -> ChainState {
        match self.side_state.take() {
            Some(state) if state.tip == tip => state,
            other => {
                self.side_state = other;
                self.state_at(tip)
            }
        }
    }

    /// The state after an accepted block, replayed from the checkpoint once
    /// the checkpoint has moved up to the final block.
    fn state_at(&mut self, tip: Digest) -> ChainState {
        while self.checkpoint.height < self.final_height {
            let hash = self
                .main_hash(self.checkpoint.height + 1)
                .expect("the final block is on the main chain");
            let block = self.index[&hash]
                .block
                .as_ref()
                .expect("only the base has no block");
            replay(&mut self.checkpoint, block, &self.params);
        }
        let mut branch = Vec::new();
        let mut at = tip;
        while at != self.checkpoint.tip {
            let block = self.index[&at]
                .block
                .as_ref()
                .expect("every kept block descends from the checkpoint");
            branch.push(block);
            at = block.header.parent;
        }
        let mut state = self.checkpoint.clone();
        for block in branch.into_iter().rev() {
            replay(&mut state, block, &self.params);
        }
        state
    }
}

/// Checks a block's body, roots and proof against its parent's state; returns
/// the state changes and the roots after them.
fn check_body<V: ContainerVerifier>(
    parent: &ChainState,
    block: &Block,
    params: &ChainParams,
    verifier: &V,
) -> Result<(BlockDelta, Roots), BlockError> {
    let h = &block.header;
    let (delta, roots) = transition(parent, &block.body, h.height, params)?;
    if h.state_root != roots.state_root
        || h.commitment_root != roots.commitment_root
        || h.nullifier_root != roots.nullifier_root
    {
        return Err(BlockError::RootMismatch);
    }
    check_proof(&block.proof, parent, &block.body, h.height, verifier)?;
    Ok((delta, roots))
}

/// Moves `state` past an accepted block whose parent it is the state after.
fn replay(state: &mut ChainState, block: &Block, params: &ChainParams) {
    let (delta, _) = transition(state, &block.body, block.header.height, params)
        .expect("an accepted block replays on its parent");
    extend(state, delta, &block.header);
}

/// Moves `state` past a block whose changes `delta` holds; the one path for
/// both the tip and replayed branches.
fn extend(state: &mut ChainState, delta: BlockDelta, header: &Header) {
    state.apply(delta);
    state.tip = header.hash();
    state.record_timestamp(header.timestamp);
}
