//! The development fund's side of payouts (docs/protocol.md, Economics): the signer
//! that holds the two account keys, and the queue of payouts a node that
//! holds them includes in the blocks it mines.
//!
//! Payouts are not relayed: the fund's own node mines them, so it must run
//! with `--mine`. Anyone can verify them in the blocks, and every node's
//! `info` shows the accounts' balances.

use zeroize::Zeroize;

use siworld_core::params::{DevFundKeys, MAX_PAYOUTS_PER_BLOCK, MIN_PACKAGE_DEPOSIT};
use siworld_core::{DevAccount, Digest, Payout};
use siworld_crypto::{expand, sign_payout, SigningKey};
use siworld_state::DevFund;

/// The fund's two signing keys, derived from one secret seed.
pub struct DevFundSigner {
    keys: [SigningKey; 2],
}

impl DevFundSigner {
    /// Deterministic in `seed`: the same seed always gives the same keys, so
    /// the seed is what a key file holds and what a backup needs.
    pub fn from_seed(seed: &Digest) -> Self {
        let keys = [DevAccount::Direct, DevAccount::Lock].map(|a| {
            let mut derived = expand(seed, "dev fund key", u64::from(a.to_byte()));
            let key = SigningKey::generate(&derived);
            derived.0.zeroize();
            key
        });
        Self { keys }
    }

    /// The verifying keys, as a genesis file carries them.
    pub fn verifying_keys(&self) -> DevFundKeys {
        DevFundKeys {
            direct: self.keys[0].verifying_key().0,
            lock: self.keys[1].verifying_key().0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        &self,
        chain: &Digest,
        account: DevAccount,
        counter: u64,
        amount: u64,
        owner: Digest,
        rseed: Digest,
        hedge: &Digest,
    ) -> Payout {
        sign_payout(
            self.key(account),
            chain,
            account,
            counter,
            amount,
            owner,
            rseed,
            hedge,
        )
    }

    fn key(&self, account: DevAccount) -> &SigningKey {
        &self.keys[usize::from(account.to_byte())]
    }
}

/// Why a payout cannot be queued.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayoutRefused {
    /// No signing/commitment randomness was obtained; nothing was queued.
    Randomness,
    Capacity,
    JournalRequired,
    Journal,
    IdConflict,
    UnknownId,
    RecoveryRequired,
    /// This node holds no development-fund keys.
    NoKeys,
    /// The encrypted fund signer is locked or its grant expired.
    Locked,
    /// Recipient, account allowance or single-payout cap is not authorized.
    Authorization,
    /// The devnet knows no wallet by that name.
    UnknownWallet,
    BelowMinimum,
    /// The account cannot spend this much on top of the payouts already queued.
    Insufficient {
        spendable: u64,
    },
    /// The next block already carries MAX_PAYOUTS_PER_BLOCK payouts.
    BlockFull,
}

impl std::fmt::Display for PayoutRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity => write!(f, "fund journal capacity reached; retain all history"),
            Self::JournalRequired => write!(f, "initialized durable fund journal required"),
            Self::Journal => write!(
                f,
                "fund journal unavailable; stop and recover original history"
            ),
            Self::IdConflict => write!(f, "payout ID already binds different parameters"),
            Self::UnknownId => write!(f, "unknown payout ID; absence does not authorize a new ID"),
            Self::RecoveryRequired => write!(
                f,
                "fund chain synchronization or conflict reconciliation required"
            ),
            Self::Randomness => write!(f, "OS randomness unavailable; no payout was queued"),
            Self::NoKeys => write!(f, "this node holds no development-fund key"),
            Self::Locked => write!(f, "development-fund key is locked"),
            Self::Authorization => write!(f, "payout exceeds the fund authorization"),
            Self::UnknownWallet => write!(f, "unknown wallet"),
            Self::BelowMinimum => write!(f, "the amount is below the minimum package"),
            Self::Insufficient { spendable } => write!(
                f,
                "the account can pay out at most {} atom more right now",
                spendable
            ),
            Self::BlockFull => write!(f, "the next block already carries the maximum of payouts"),
        }
    }
}

impl std::error::Error for PayoutRefused {}

/// Payouts signed and waiting for the next block this node mines.
#[derive(Default)]
pub struct PayoutQueue {
    queued: Vec<Payout>,
}

impl PayoutQueue {
    /// Signs a payout of `amount` from `account` to `owner` on the chain
    /// `chain_id`, against the fund state `fund` and what is already queued,
    /// and queues it. `rseed` is the package's commitment randomness, `hedge`
    /// the signature's.
    #[allow(clippy::too_many_arguments)]
    pub fn queue(
        &mut self,
        signer: &DevFundSigner,
        chain_id: &Digest,
        fund: &DevFund,
        account: DevAccount,
        owner: Digest,
        amount: u64,
        rseed: Digest,
        hedge: &Digest,
    ) -> Result<Payout, PayoutRefused> {
        if amount < MIN_PACKAGE_DEPOSIT {
            return Err(PayoutRefused::BelowMinimum);
        }
        if self.queued.len() >= MAX_PAYOUTS_PER_BLOCK {
            return Err(PayoutRefused::BlockFull);
        }
        let same: Vec<&Payout> = self
            .queued
            .iter()
            .filter(|p| p.account == account)
            .collect();
        // Saturating: a reorg may have lowered the balance below what is
        // queued until `prune` runs.
        let spendable = fund
            .spendable(account)
            .saturating_sub(same.iter().map(|p| p.amount).sum::<u64>());
        if amount > spendable {
            return Err(PayoutRefused::Insufficient { spendable });
        }
        let counter = fund.payouts(account) + same.len() as u64;
        let payout = sign_payout(
            signer.key(account),
            chain_id,
            account,
            counter,
            amount,
            owner,
            rseed,
            hedge,
        );
        self.queued.push(payout);
        Ok(payout)
    }

    /// The payouts for the next block, in order.
    pub(crate) fn push_signed(&mut self, payout: Payout) {
        self.queued.push(payout);
    }

    pub fn pending(&self) -> &[Payout] {
        &self.queued
    }

    /// Brings the queue in line with the fund state after the tip moved:
    /// keeps, per account and in order, the payouts whose counters continue
    /// the account's count and whose amounts the account can still cover,
    /// and drops the rest (included in a block, left stale by a reorg, or
    /// no longer affordable). Returns what was dropped, for the operator.
    pub fn prune(&mut self, fund: &DevFund) -> Vec<Payout> {
        let mut next = [DevAccount::Direct, DevAccount::Lock].map(|a| fund.payouts(a));
        let mut left = [DevAccount::Direct, DevAccount::Lock].map(|a| fund.spendable(a));
        let mut dropped = Vec::new();
        self.queued.retain(|p| {
            let i = usize::from(p.account.to_byte());
            let keep = p.counter == next[i] && p.amount <= left[i];
            if keep {
                next[i] += 1;
                left[i] -= p.amount;
            } else {
                dropped.push(*p);
            }
            keep
        });
        dropped
    }

    pub fn clear(&mut self) {
        self.queued.clear();
    }

    pub fn len(&self) -> usize {
        self.queued.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use siworld_core::params::COINBASE_MATURITY;
    use siworld_state::deposit;

    use super::*;

    fn fund_after(blocks: u64) -> DevFund {
        let mut fund = DevFund::default();
        for h in 1..=blocks {
            fund.advance(h, 60);
        }
        fund
    }

    fn queue_two(signer: &DevFundSigner, fund: &DevFund) -> (PayoutQueue, Payout, Payout) {
        let chain = Digest([1; 32]);
        let mut q = PayoutQueue::default();
        let half = fund.spendable(DevAccount::Direct) / 2;
        let a = q
            .queue(
                signer,
                &chain,
                fund,
                DevAccount::Direct,
                Digest([2; 32]),
                half,
                Digest([3; 32]),
                &Digest([4; 32]),
            )
            .unwrap();
        let b = q
            .queue(
                signer,
                &chain,
                fund,
                DevAccount::Direct,
                Digest([2; 32]),
                half,
                Digest([5; 32]),
                &Digest([6; 32]),
            )
            .unwrap();
        (q, a, b)
    }

    #[test]
    fn queued_payouts_take_consecutive_counters_and_share_the_balance() {
        let signer = DevFundSigner::from_seed(&Digest([9; 32]));
        let fund = fund_after(COINBASE_MATURITY + 1);
        let (mut q, a, b) = queue_two(&signer, &fund);
        assert_eq!((a.counter, b.counter), (0, 1));
        assert_eq!(
            a.amount + b.amount,
            fund.spendable(DevAccount::Direct) - fund.spendable(DevAccount::Direct) % 2
        );
        assert_eq!(
            q.queue(
                &signer,
                &Digest([1; 32]),
                &fund,
                DevAccount::Direct,
                Digest([2; 32]),
                10_000,
                Digest([7; 32]),
                &Digest([8; 32])
            ),
            Err(PayoutRefused::Insufficient {
                spendable: fund.spendable(DevAccount::Direct) % 2
            })
        );
        assert_eq!(q.len(), 2);
    }

    /// After the first payout is in a block, the second continues the count
    /// and stays; a payout whose counter the chain has passed, or that the
    /// balance no longer covers, is dropped and reported.
    #[test]
    fn prune_keeps_only_the_payouts_the_chain_still_expects() {
        let signer = DevFundSigner::from_seed(&Digest([9; 32]));
        let fund = fund_after(COINBASE_MATURITY + 1);
        let (mut q, a, b) = queue_two(&signer, &fund);

        let mut after_a = fund;
        after_a.advance(COINBASE_MATURITY + 2, 60);
        after_a.pay(DevAccount::Direct, a.amount);
        assert_eq!(q.prune(&after_a), vec![a]);
        assert_eq!(q.pending(), &[b]);

        // A reorg then undoes the block with `a`: the account's count is back
        // to 0, `b`'s counter 1 no longer follows it, so `b` goes too rather
        // than making every later template fail.
        assert_eq!(q.prune(&fund), vec![b]);
        assert!(q.is_empty());

        // The balance shrank below what is queued: the later payout goes.
        let (mut q, a, b) = queue_two(&signer, &fund);
        let poorer = fund_after(COINBASE_MATURITY);
        assert_eq!(poorer.spendable(DevAccount::Direct), 0);
        assert_eq!(q.prune(&poorer), vec![a, b]);
        assert!(deposit(1) > 0);
    }
}
