//! The development-fund accounts (docs/protocol.md, Economics).
//!
//! Every block deposits ⌊reward/20⌋ into each of the two accounts. The direct
//! account's credits mature after `COINBASE_MATURITY` blocks. The lock
//! account releases each deposit linearly over `DEV_LOCK_SECONDS` of protocol
//! time (the sum of target block times): the amount released by height H is
//! ⌊Σ_h L_h · min(age(h, H), T) / T⌋. Both are functions of the issuance
//! schedule, so the state holds a few running sums and no record per block.
//! Payouts are public entries of a block body; a payout in block H may spend
//! what was spendable after block H − 1.

use siworld_core::issuance::{block_reward, epoch_of, reward_split};
use siworld_core::params::{COINBASE_MATURITY, DEV_LOCK_SECONDS};
use siworld_core::{DevAccount, Height};

/// The deposit block `height` makes into each account: ⌊reward/20⌋.
pub fn deposit(height: Height) -> u64 {
    reward_split(block_reward(epoch_of(height))).1
}

/// Account balances and the lock's release state after some block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DevFund {
    /// Direct account: credits that have matured, and what has been paid out.
    direct_credited: u64,
    direct_paid: u64,
    direct_payouts: u64,
    /// Lock account. `active` is the sum of the deposits still being released,
    /// `weighted` their sum weighted by age in protocol seconds, `released`
    /// the sum of the deposits released in full.
    lock_active: u64,
    lock_weighted: u128,
    lock_released: u64,
    lock_paid: u64,
    lock_payouts: u64,
}

impl DevFund {
    /// How many payouts `account` has made.
    pub fn payouts(&self, account: DevAccount) -> u64 {
        match account {
            DevAccount::Direct => self.direct_payouts,
            DevAccount::Lock => self.lock_payouts,
        }
    }

    /// What `account` has paid out in total.
    pub fn paid(&self, account: DevAccount) -> u64 {
        match account {
            DevAccount::Direct => self.direct_paid,
            DevAccount::Lock => self.lock_paid,
        }
    }

    /// The lock's deposits released so far, paid out or not.
    pub fn released(&self) -> u64 {
        let partial = self.lock_weighted / u128::from(DEV_LOCK_SECONDS);
        self.lock_released + u64::try_from(partial).expect("released at most the deposits")
    }

    /// What a payout from `account` may take now.
    pub fn spendable(&self, account: DevAccount) -> u64 {
        match account {
            DevAccount::Direct => self.direct_credited - self.direct_paid,
            DevAccount::Lock => self.released() - self.lock_paid,
        }
    }

    /// The accounting of block `height`, whose target block time is
    /// `block_time` seconds: every deposit being released ages by one block,
    /// the deposit that reaches the lock period is released in full, the
    /// direct credit of `COINBASE_MATURITY` blocks ago matures, and this
    /// block's deposits join.
    pub fn advance(&mut self, height: Height, block_time: u64) {
        let dt = u128::from(block_time);
        self.lock_weighted += u128::from(self.lock_active) * dt;
        // A deposit made `lock_blocks` blocks ago has aged lock_blocks · dt ≥
        // DEV_LOCK_SECONDS seconds, and one block younger has not.
        let lock_blocks = DEV_LOCK_SECONDS.div_ceil(block_time);
        if let Some(h) = height.checked_sub(lock_blocks).filter(|h| *h >= 1) {
            let l = deposit(h);
            self.lock_weighted -= u128::from(l) * u128::from(lock_blocks) * dt;
            self.lock_active -= l;
            self.lock_released += l;
        }
        if let Some(h) = height.checked_sub(COINBASE_MATURITY).filter(|h| *h >= 1) {
            self.direct_credited += deposit(h);
        }
        self.lock_active += deposit(height);
    }

    /// Records a payout the caller has checked against [`Self::spendable`].
    pub fn pay(&mut self, account: DevAccount, amount: u64) {
        match account {
            DevAccount::Direct => {
                self.direct_paid += amount;
                self.direct_payouts += 1;
            }
            DevAccount::Lock => {
                self.lock_paid += amount;
                self.lock_payouts += 1;
            }
        }
    }

    /// Every field, for the state root.
    pub fn encode(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        let fields = [
            self.direct_credited,
            self.direct_paid,
            self.direct_payouts,
            self.lock_active,
            self.lock_released,
            self.lock_paid,
            self.lock_payouts,
        ];
        for (i, x) in fields.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
        }
        out[56..72].copy_from_slice(&self.lock_weighted.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The release formula of docs/protocol.md computed from scratch, deposit by
    /// deposit, for a constant block time.
    fn released_by_formula(height: Height, block_time: u64) -> u64 {
        let t = u128::from(DEV_LOCK_SECONDS);
        let sum: u128 = (1..=height)
            .map(|h| {
                let age = u128::from(height - h) * u128::from(block_time);
                u128::from(deposit(h)) * age.min(t)
            })
            .sum();
        u64::try_from(sum / t).unwrap()
    }

    #[test]
    fn the_running_sums_match_the_release_formula() {
        // Block times that make the lock 10 blocks (exact) and 11 blocks
        // (rounded up), so deposits age, cap and retire within the test.
        for block_time in [DEV_LOCK_SECONDS / 10, 15_000_000, 60] {
            let mut fund = DevFund::default();
            for h in 1..=40 {
                fund.advance(h, block_time);
                assert_eq!(
                    fund.released(),
                    released_by_formula(h, block_time),
                    "block time {block_time}, height {h}"
                );
            }
        }
    }

    #[test]
    fn a_lock_deposit_is_released_linearly_and_in_full() {
        // Ten blocks per lock period.
        let block_time = DEV_LOCK_SECONDS / 10;
        let mut fund = DevFund::default();
        fund.advance(1, block_time);
        let l = deposit(1);
        assert_eq!(fund.released(), 0);
        for h in 2..=11 {
            fund.advance(h, block_time);
            // Block 1's deposit has aged h − 1 tenths; the later deposits
            // contribute their own tenths too.
            let tenths: u64 = (1..h).map(|d| h - d).sum();
            assert_eq!(fund.released(), l * tenths / 10);
        }
        // At block 11 block 1's deposit reached the lock period and was
        // released in full; block 2's follows one block later.
        assert_eq!(fund.lock_released, l);
        fund.advance(12, block_time);
        assert_eq!(fund.lock_released, 2 * l);
        assert_eq!(fund.released(), released_at(12, l));

        fn released_at(h: u64, l: u64) -> u64 {
            l * (1..h).map(|d| (h - d).min(10)).sum::<u64>() / 10
        }
    }

    #[test]
    fn direct_credits_mature_after_one_hundred_blocks() {
        let mut fund = DevFund::default();
        for h in 1..=COINBASE_MATURITY {
            fund.advance(h, 60);
            assert_eq!(fund.spendable(DevAccount::Direct), 0);
        }
        fund.advance(COINBASE_MATURITY + 1, 60);
        assert_eq!(fund.spendable(DevAccount::Direct), deposit(1));
        fund.advance(COINBASE_MATURITY + 2, 60);
        assert_eq!(fund.spendable(DevAccount::Direct), deposit(1) + deposit(2));
    }

    #[test]
    fn payouts_reduce_the_balance_and_count() {
        let mut fund = DevFund::default();
        for h in 1..=COINBASE_MATURITY + 1 {
            fund.advance(h, 60);
        }
        let before = fund.spendable(DevAccount::Direct);
        fund.pay(DevAccount::Direct, 7);
        assert_eq!(fund.spendable(DevAccount::Direct), before - 7);
        assert_eq!(fund.payouts(DevAccount::Direct), 1);
        assert_eq!(fund.paid(DevAccount::Direct), 7);
        assert_eq!(fund.payouts(DevAccount::Lock), 0);
    }

    #[test]
    fn the_encoding_covers_every_field() {
        let mut a = DevFund::default();
        a.advance(1, 60);
        a.advance(2, 60);
        let mut b = a;
        b.pay(DevAccount::Lock, 0);
        assert_ne!(a.encode(), b.encode());
        let mut c = a;
        c.advance(3, 60);
        assert_ne!(a.encode(), c.encode());
        assert_eq!(a.encode(), a.encode());
    }
}
