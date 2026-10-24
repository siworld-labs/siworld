//! Chain state: commitment tree, recent-roots window, nullifier set, the
//! pending-reward queue and the development-fund accounts.
//!
//! In-memory implementation for the devnet and tests. redb persistence and the
//! port of midstate's sparse Merkle tree come later.

mod commitments;
mod devfund;
mod nullifiers;
mod recent_roots;

pub use commitments::{CommitmentTree, MerklePath, TreeFull};
pub use devfund::{deposit, DevFund};
pub use nullifiers::{AlreadySpent, NullifierSet};
pub use recent_roots::{base_fee, RecentRoots};

use std::collections::{BTreeSet, VecDeque};

use siworld_core::params::{ChainParams, COINBASE_MATURITY, MEDIAN_TIME_PAST_WINDOW};
use siworld_core::{Commitment, DevAccount, Digest, Height, Nullifier, Roots};
use siworld_crypto::domain_hash;

/// Why a block's state changes cannot be applied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeltaError {
    /// Spent in an earlier block, or twice in this one (the first repeat in order).
    AlreadySpent(Nullifier),
    /// The new commitments do not fit in the tree.
    TreeFull,
    /// The block's payouts from this account exceed what it can spend.
    Overdraft(DevAccount),
}

/// A development-fund payout as the state sees it: the account debited, the
/// amount, and the recipient package's commitment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PayoutDelta {
    pub account: DevAccount,
    pub amount: u64,
    pub cm: Commitment,
}

/// A block's validated state changes, produced by [`ChainState::prepare`] and
/// consumed by [`ChainState::apply`] on the same parent state.
#[derive(Clone, Debug)]
pub struct BlockDelta {
    parent: Roots,
    height: Height,
    nullifiers: Vec<Nullifier>,
    /// In tree order: the slots' outputs, the matured miner package, then the
    /// payouts' packages.
    commitments: Vec<Commitment>,
    /// This block's miner package, queued until it matures.
    miner_cm: Commitment,
    /// The development-fund accounts after this block.
    fund: DevFund,
}

#[derive(Clone, Debug)]
pub struct ChainState {
    pub height: Height,
    pub tip: Digest,
    pub commitments: CommitmentTree,
    pub anchors: RecentRoots,
    /// 𝒜 root as of the block before the tip; `None` at genesis. With
    /// `anchors.accumulator_root()` these are the only roots the next block's
    /// proof may use (ACC_ROOT_LAG, docs/protocol.md). Determined by the parent state, so
    /// it is not part of the state root.
    pub prev_anchors_root: Option<Digest>,
    pub nullifiers: NullifierSet,
    /// The pending-reward queue (docs/protocol.md, Economics): the miner packages of
    /// the last `COINBASE_MATURITY` blocks, oldest first. The block at height
    /// h appends the package of block h − COINBASE_MATURITY to the commitment
    /// tree, or the zero digest when there is none. Part of the state root.
    pub pending_rewards: VecDeque<Commitment>,
    /// The development-fund accounts (docs/protocol.md, Economics). Part of the state root.
    pub dev_fund: DevFund,
    /// Target block time in seconds: the protocol time one block adds.
    pub block_time: u64,
    /// Timestamps of the last blocks up to MEDIAN_TIME_PAST_WINDOW, oldest first;
    /// the last is the tip's. Fixed by the headers, so not part of the state root.
    pub timestamps: Vec<u64>,
}

impl ChainState {
    /// Genesis state at height 0: an empty commitment tree, no premine.
    pub fn genesis(params: &ChainParams) -> Self {
        let commitments = CommitmentTree::new(params.commitment_tree_depth);
        let mut anchors = RecentRoots::new(params.anchor_window);
        anchors.push(commitments.root(), 0);
        Self {
            height: 0,
            tip: Digest::ZERO,
            commitments,
            anchors,
            prev_anchors_root: None,
            nullifiers: NullifierSet::default(),
            pending_rewards: VecDeque::new(),
            dev_fund: DevFund::default(),
            block_time: params.target_block_time,
            timestamps: vec![params.genesis_timestamp],
        }
    }

    /// Test-only: inserts commitments directly at genesis, skipping the 100-block
    /// maturity period. Not available on mainnet.
    #[cfg(feature = "test-utils")]
    pub fn genesis_with_commitments(
        params: &ChainParams,
        cms: &[siworld_core::Commitment],
    ) -> Self {
        let mut commitments = CommitmentTree::new(params.commitment_tree_depth);
        for cm in cms {
            commitments.append(*cm).expect("test genesis fits in tree");
        }
        let mut anchors = RecentRoots::new(params.anchor_window);
        anchors.push(commitments.root(), 0);
        Self {
            height: 0,
            tip: Digest::ZERO,
            commitments,
            anchors,
            prev_anchors_root: None,
            nullifiers: NullifierSet::default(),
            pending_rewards: VecDeque::new(),
            dev_fund: DevFund::default(),
            block_time: params.target_block_time,
            timestamps: vec![params.genesis_timestamp],
        }
    }

    /// The tip's timestamp.
    pub fn timestamp(&self) -> u64 {
        *self
            .timestamps
            .last()
            .expect("genesis records its timestamp")
    }

    /// Records the timestamp of a newly applied block.
    pub fn record_timestamp(&mut self, timestamp: u64) {
        self.timestamps.push(timestamp);
        if self.timestamps.len() > MEDIAN_TIME_PAST_WINDOW {
            self.timestamps.remove(0);
        }
    }

    pub fn roots(&self) -> Roots {
        roots(
            self.commitments.root(),
            self.nullifiers.root(),
            self.anchors.accumulator_root(),
            self.height,
            transparent_root(self.pending_rewards.iter(), &self.dev_fund),
        )
    }

    /// The miner package the next block appends after its slot outputs: the
    /// one queued `COINBASE_MATURITY` blocks before it, or the zero digest
    /// while the queue is not full yet.
    pub fn maturing_reward(&self) -> Commitment {
        if self.pending_rewards.len() >= COINBASE_MATURITY as usize {
            self.pending_rewards[0]
        } else {
            Commitment(Digest::ZERO)
        }
    }

    /// Checks a block's state changes against this state and computes the roots
    /// after them, without changing anything: no nullifier may already be spent
    /// or repeat, the payouts of each account must fit its spendable balance,
    /// and the slots' output commitments (in tree order), the maturing miner
    /// package and the payouts' packages must fit in the tree. `miner_cm` is
    /// the block's own miner package, which joins the queue.
    pub fn prepare(
        &self,
        height: Height,
        nullifiers: Vec<Nullifier>,
        mut commitments: Vec<Commitment>,
        miner_cm: Commitment,
        payouts: &[PayoutDelta],
    ) -> Result<(BlockDelta, Roots), DeltaError> {
        let mut seen = BTreeSet::new();
        for nf in &nullifiers {
            if self.nullifiers.contains(nf) || !seen.insert(*nf) {
                return Err(DeltaError::AlreadySpent(*nf));
            }
        }
        for account in [DevAccount::Direct, DevAccount::Lock] {
            let total = payouts
                .iter()
                .filter(|p| p.account == account)
                .try_fold(0u64, |acc, p| acc.checked_add(p.amount));
            if total.is_none_or(|t| t > self.dev_fund.spendable(account)) {
                return Err(DeltaError::Overdraft(account));
            }
        }
        commitments.push(self.maturing_reward());
        commitments.extend(payouts.iter().map(|p| p.cm));
        let payouts: Vec<(DevAccount, u64)> =
            payouts.iter().map(|p| (p.account, p.amount)).collect();
        let mut dev_fund = self.dev_fund;
        advance_fund(&mut dev_fund, height, self.block_time, &payouts);
        let commitment_root = self
            .commitments
            .root_after(&commitments)
            .map_err(|TreeFull| DeltaError::TreeFull)?;
        // The queue after this block: the oldest entry leaves once the queue is
        // full (it is the package appended above), and this block's joins.
        let full = self.pending_rewards.len() >= COINBASE_MATURITY as usize;
        let queue_after = self
            .pending_rewards
            .iter()
            .skip(usize::from(full))
            .chain(std::iter::once(&miner_cm));
        let after = roots(
            commitment_root,
            self.nullifiers.root_after(&nullifiers),
            self.anchors
                .accumulator_root_after_push(&commitment_root, height),
            height,
            transparent_root(queue_after, &dev_fund),
        );
        let delta = BlockDelta {
            parent: self.roots(),
            height,
            nullifiers,
            commitments,
            miner_cm,
            fund: dev_fund,
        };
        Ok((delta, after))
    }

    /// Applies a delta from [`Self::prepare`] on this same state. Panics, before
    /// changing anything, if the state has moved since.
    pub fn apply(&mut self, delta: BlockDelta) {
        assert!(
            self.roots() == delta.parent,
            "delta was prepared on a different state"
        );
        self.prev_anchors_root = Some(delta.parent.anchors_root);
        for nf in delta.nullifiers {
            self.nullifiers.insert(nf).expect("checked by prepare");
        }
        self.commitments
            .append_all(&delta.commitments)
            .expect("checked by prepare");
        if self.pending_rewards.len() >= COINBASE_MATURITY as usize {
            self.pending_rewards.pop_front();
        }
        self.pending_rewards.push_back(delta.miner_cm);
        self.dev_fund = delta.fund;
        self.height = delta.height;
        self.anchors.push(self.commitments.root(), delta.height);
    }
}

/// The development fund after block `height`: its accounting, then the
/// block's payouts (checked against the balance before the block).
fn advance_fund(
    fund: &mut DevFund,
    height: Height,
    block_time: u64,
    payouts: &[(DevAccount, u64)],
) {
    fund.advance(height, block_time);
    for &(account, amount) in payouts {
        fund.pay(account, amount);
    }
}

/// Root of the transparent state: the pending-reward queue, oldest first, and
/// the development-fund accounts.
fn transparent_root<'a>(queue: impl Iterator<Item = &'a Commitment>, fund: &DevFund) -> Digest {
    let bytes: Vec<u8> = queue.flat_map(|cm| cm.0 .0).collect();
    domain_hash("siworld v0 transparent state", &[&bytes, &fund.encode()])
}

fn roots(
    commitment_root: Digest,
    nullifier_root: Digest,
    anchors_root: Digest,
    height: Height,
    transparent_root: Digest,
) -> Roots {
    let state_root = domain_hash(
        "siworld v0 state root",
        &[
            commitment_root.as_bytes(),
            nullifier_root.as_bytes(),
            anchors_root.as_bytes(),
            &height.to_le_bytes(),
            transparent_root.as_bytes(),
        ],
    );
    Roots {
        commitment_root,
        nullifier_root,
        anchors_root,
        state_root,
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;

    fn nf(i: u8) -> Nullifier {
        Nullifier(Digest([i; 32]))
    }

    fn cm(i: u8) -> Commitment {
        Commitment(Digest([i; 32]))
    }

    fn params() -> ChainParams {
        ChainParams {
            anchor_window: 2,
            commitment_tree_depth: 4,
            ..ChainParams::devnet()
        }
    }

    const ZERO: Commitment = Commitment(Digest::ZERO);

    #[test]
    fn prepared_roots_are_the_roots_after_apply() {
        let mut s = ChainState::genesis(&params());
        // Past the anchor window, so the window drops its oldest root.
        for h in 1..=4u8 {
            let (delta, roots) = s
                .prepare(
                    u64::from(h),
                    vec![nf(2 * h), nf(2 * h + 1)],
                    vec![cm(h), cm(h + 50)],
                    cm(h + 100),
                    &[],
                )
                .unwrap();
            let parent_anchors = s.anchors.accumulator_root();
            s.apply(delta);
            assert_eq!(s.roots(), roots);
            assert_eq!(s.height, u64::from(h));
            assert_eq!(s.prev_anchors_root, Some(parent_anchors));
            // Two outputs and the (still zero) matured reward per block.
            assert_eq!(s.commitments.len(), 3 * u64::from(h));
            assert_eq!(s.commitments.leaf(3 * u64::from(h) - 1), Some(ZERO));
            assert_eq!(s.nullifiers.len(), 2 * usize::from(h));
            assert_eq!(s.pending_rewards.len(), usize::from(h));
        }
    }

    /// The miner package of block h enters the tree with block
    /// h + COINBASE_MATURITY, right after that block's own outputs, and the
    /// queue holds exactly the packages that have not matured.
    #[test]
    fn miner_packages_mature_one_hundred_blocks_later() {
        let p = ChainParams {
            commitment_tree_depth: 12,
            ..params()
        };
        let mut s = ChainState::genesis(&p);
        let reward = |h: u64| Commitment(Digest([h as u8; 32]));
        for h in 1..=COINBASE_MATURITY + 2 {
            assert_eq!(
                s.maturing_reward(),
                if h > COINBASE_MATURITY {
                    reward(h - COINBASE_MATURITY)
                } else {
                    ZERO
                }
            );
            let (delta, roots) = s.prepare(h, vec![], vec![], reward(h), &[]).unwrap();
            s.apply(delta);
            assert_eq!(s.roots(), roots);
            assert_eq!(s.commitments.len(), h);
            assert_eq!(
                s.commitments.leaf(h - 1),
                Some(if h > COINBASE_MATURITY {
                    reward(h - COINBASE_MATURITY)
                } else {
                    ZERO
                })
            );
            assert_eq!(s.pending_rewards.len() as u64, h.min(COINBASE_MATURITY));
            assert_eq!(s.pending_rewards.back(), Some(&reward(h)));
        }
        // No package was ever appended by its own block.
        for h in 1..=2 {
            assert_eq!(s.commitments.leaf(h - 1), Some(ZERO));
        }
    }

    /// Two states that differ only in a queued (not yet appended) package have
    /// different state roots, so a validator cannot diverge silently on it.
    #[test]
    fn the_pending_reward_queue_is_part_of_the_state_root() {
        let a = ChainState::genesis(&params());
        let (da, ra) = a.prepare(1, vec![], vec![], cm(1), &[]).unwrap();
        let (db, rb) = a.prepare(1, vec![], vec![], cm(2), &[]).unwrap();
        assert_eq!(ra.commitment_root, rb.commitment_root);
        assert_ne!(ra.state_root, rb.state_root);
        let mut sa = a.clone();
        sa.apply(da);
        let mut sb = a;
        sb.apply(db);
        assert_eq!(sa.roots(), ra);
        assert_eq!(sb.roots(), rb);
    }

    /// A payout spends what the account could spend after the previous
    /// block, the fund's accounting is part of the state root, and payouts
    /// beyond the balance (singly or together) are refused.
    #[test]
    fn payouts_are_bounded_by_the_balance_and_change_the_state_root() {
        let p = ChainParams {
            commitment_tree_depth: 12,
            ..params()
        };
        let mut s = ChainState::genesis(&p);
        for h in 1..=COINBASE_MATURITY + 1 {
            let (delta, _) = s.prepare(h, vec![], vec![], ZERO, &[]).unwrap();
            s.apply(delta);
        }
        let direct = s.dev_fund.spendable(DevAccount::Direct);
        assert_eq!(direct, deposit(1));
        assert!(s.dev_fund.spendable(DevAccount::Lock) > 0);
        let h = COINBASE_MATURITY + 2;
        // Canonical commitments: every byte below 0x7f encodes a field element.
        let payout = |account, amount, i: u8| PayoutDelta {
            account,
            amount,
            cm: cm(100 + i),
        };

        assert_eq!(
            s.prepare(
                h,
                vec![],
                vec![],
                ZERO,
                &[payout(DevAccount::Direct, direct + 1, 0)]
            )
            .unwrap_err(),
            DeltaError::Overdraft(DevAccount::Direct)
        );
        assert_eq!(
            s.prepare(
                h,
                vec![],
                vec![],
                ZERO,
                &[
                    payout(DevAccount::Direct, direct, 0),
                    payout(DevAccount::Direct, 1, 1)
                ]
            )
            .unwrap_err(),
            DeltaError::Overdraft(DevAccount::Direct)
        );
        let lock = s.dev_fund.spendable(DevAccount::Lock);
        assert_eq!(
            s.prepare(
                h,
                vec![],
                vec![],
                ZERO,
                &[payout(DevAccount::Lock, lock + 1, 0)]
            )
            .unwrap_err(),
            DeltaError::Overdraft(DevAccount::Lock)
        );

        let (none, roots_none) = s.prepare(h, vec![], vec![], ZERO, &[]).unwrap();
        let (delta, roots) = s
            .prepare(
                h,
                vec![],
                vec![],
                ZERO,
                &[
                    payout(DevAccount::Direct, direct, 0),
                    payout(DevAccount::Lock, lock, 1),
                ],
            )
            .unwrap();
        assert_ne!(roots.state_root, roots_none.state_root);
        drop(none);
        s.apply(delta);
        assert_eq!(s.roots(), roots);
        // The payouts' packages follow the matured package in the tree.
        let n = s.commitments.len();
        assert_eq!(s.commitments.leaf(n - 3), Some(ZERO));
        assert_eq!(s.commitments.leaf(n - 2), Some(cm(100)));
        assert_eq!(s.commitments.leaf(n - 1), Some(cm(101)));
        // Only this block's credit is left; the lock released a little more.
        assert_eq!(s.dev_fund.spendable(DevAccount::Direct), deposit(2));
        assert_eq!(s.dev_fund.payouts(DevAccount::Direct), 1);
        assert_eq!(s.dev_fund.payouts(DevAccount::Lock), 1);
        assert_eq!(s.dev_fund.paid(DevAccount::Lock), lock);
    }

    #[test]
    fn prepare_rejects_a_nullifier_spent_before_or_twice_in_the_block() {
        let mut s = ChainState::genesis(&params());
        let (delta, _) = s.prepare(1, vec![nf(1)], vec![], ZERO, &[]).unwrap();
        s.apply(delta);
        assert_eq!(
            s.prepare(2, vec![nf(2), nf(1)], vec![], ZERO, &[])
                .unwrap_err(),
            DeltaError::AlreadySpent(nf(1))
        );
        assert_eq!(
            s.prepare(2, vec![nf(5), nf(5)], vec![], ZERO, &[])
                .unwrap_err(),
            DeltaError::AlreadySpent(nf(5))
        );
    }

    #[test]
    fn prepare_rejects_a_batch_that_overflows_the_tree() {
        let s = ChainState::genesis(&params());
        // 16 leaves: 15 outputs plus the matured reward fit, 16 do not.
        let cms: Vec<_> = (0..15).map(cm).collect();
        assert!(s.prepare(1, vec![], cms, ZERO, &[]).is_ok());
        let cms: Vec<_> = (0..16).map(cm).collect();
        assert_eq!(
            s.prepare(1, vec![], cms, ZERO, &[]).unwrap_err(),
            DeltaError::TreeFull
        );
    }

    #[test]
    fn delta_prepared_on_another_state_is_refused_before_any_change() {
        let mut a = ChainState::genesis(&params());
        let (delta, _) = a.prepare(1, vec![nf(1)], vec![cm(1)], ZERO, &[]).unwrap();
        a.apply(delta.clone());
        let before = a.roots();
        let mut stale = a.clone();
        assert!(catch_unwind(AssertUnwindSafe(|| stale.apply(delta))).is_err());
        assert_eq!(stale.roots(), before);
        assert_eq!(stale.nullifiers.len(), 1);
    }
}
