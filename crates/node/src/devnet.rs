//! Devnet node: one chain, one mempool, a set of test wallets.

use std::sync::Arc;

use siworld_circuits::{MockProver, ProofSystem};
use siworld_consensus::{build_block, BlockError, BuildError, Chain, Miner, PendingTx};
use siworld_core::params::{ChainParams, ATOMS_PER_SIP};
use siworld_core::{Block, DevAccount, Digest, Height, Payout};
use siworld_crypto::{expand, SecretSeed, SpendKey};
use siworld_state::ChainState;

use crate::devfund::{DevFundSigner, PayoutQueue, PayoutRefused};
use crate::mempool::{admissible, Mempool, TxPow, DEFAULT_CAPACITY, DEFAULT_PER_PEER};
use crate::wallet::{PayError, Wallets};

/// Devnet test wallets.
pub const WALLET_NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];

/// Default devnet seed. The test wallet keys and the miner key are derived from
/// it, so they are public; block padding and payment randomness are not (see
/// [`Config::randomness`]).
pub const DEFAULT_SEED: Digest = Digest([0xde; 32]);

pub struct Config {
    /// Public seed for the test wallet keys and the miner key.
    pub seed: Digest,
    /// Secret randomness for block padding, the miner package, and wallet
    /// payments. Defaults to the operating system's generator; use
    /// [`SecretSeed::insecure_deterministic`] only to replay a run.
    pub randomness: SecretSeed,
    /// Genesis block timestamp (Unix seconds); ASERT schedules blocks from it.
    pub genesis_timestamp: u64,
    /// Genesis funds: (wallet name, amount in atoms), one package per entry.
    pub genesis: Vec<(&'static str, u64)>,
}

impl Default for Config {
    /// alice, bob, and carol get two 50 SIP packages each; dave gets none.
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails.
    fn default() -> Self {
        let fifty = 50 * ATOMS_PER_SIP;
        Self {
            seed: DEFAULT_SEED,
            randomness: SecretSeed::from_os_rng().expect("OS random number generator"),
            genesis_timestamp: 0,
            genesis: ["alice", "bob", "carol"]
                .iter()
                .flat_map(|n| [(*n, fifty), (*n, fifty)])
                .collect(),
        }
    }
}

/// Everything printed about a block. Excludes the real-transaction count, fees,
/// and the empty-package count (privacy invariants in CONTRIBUTING.md).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockInfo {
    pub height: Height,
    pub hash: Digest,
    pub state_root: Digest,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NodeError {
    Build(BuildError),
    Apply(BlockError),
}

pub struct Devnet {
    pub chain: Chain<Arc<dyn ProofSystem>>,
    pub wallets: Wallets,
    mempool: Mempool,
    /// Root of the per-block producer seeds.
    blocks: SecretSeed,
    miner: Miner,
    /// The development fund's signing keys, derived from the public seed like
    /// the test wallet keys, and the payouts queued for the next block.
    dev_fund: DevFundSigner,
    payouts: PayoutQueue,
    /// Payouts signed so far, for their randomness.
    payouts_signed: u64,
}

impl Devnet {
    pub fn new(config: Config) -> Self {
        Self::with_mempool_capacity(config, DEFAULT_CAPACITY)
    }

    /// A devnet whose mempool holds at most `capacity` transactions.
    pub fn with_mempool_capacity(config: Config, capacity: usize) -> Self {
        let dev_fund = DevFundSigner::from_seed(&expand(&config.seed, "devnet dev fund", 0));
        let params = ChainParams {
            genesis_timestamp: config.genesis_timestamp,
            dev_fund_keys: Some(dev_fund.verifying_keys()),
            ..ChainParams::devnet()
        };
        let mut wallets = Wallets::new(
            expand(&config.seed, "devnet wallets", 0),
            config.randomness.child("devnet wallets", 0),
            &WALLET_NAMES,
        );
        let specs: Vec<(usize, u64)> = config
            .genesis
            .iter()
            .map(|(name, value)| {
                let w = wallets
                    .index_of(name)
                    .unwrap_or_else(|| panic!("unknown genesis wallet {name}"));
                (w, *value)
            })
            .collect();
        let cms = wallets.genesis_notes(&specs);
        let state = ChainState::genesis_with_commitments(&params, &cms);
        let miner = Miner {
            address: SpendKey::from_digest(expand(&config.seed, "devnet miner key", 0)).address(),
            committee_key: expand(&config.seed, "devnet committee key", 0),
        };
        let tx_pow = TxPow::for_params(&params);
        let system: Arc<dyn ProofSystem> = Arc::new(MockProver);
        Self {
            chain: Chain::new(params, state, system.clone()),
            wallets,
            mempool: Mempool::new(capacity, DEFAULT_PER_PEER, tx_pow, system),
            blocks: config.randomness.child("devnet blocks", 0),
            miner,
            dev_fund,
            payouts: PayoutQueue::default(),
            payouts_signed: 0,
        }
    }

    /// Queues a development-fund payout of `amount` atoms from `account` to
    /// the test wallet `to` for the next block, signed with the devnet's fund
    /// key. The counter and the balance account for payouts already queued.
    pub fn payout(
        &mut self,
        account: DevAccount,
        to: &str,
        amount: u64,
    ) -> Result<(), PayoutRefused> {
        let w = self
            .wallets
            .index_of(to)
            .ok_or(PayoutRefused::UnknownWallet)?;
        self.payouts_signed += 1;
        let n = self.payouts_signed;
        self.payouts.queue(
            &self.dev_fund,
            &self.chain.params.chain_id,
            &self.chain.state.dev_fund,
            account,
            self.wallets.address(w).owner(),
            amount,
            self.blocks.derive("devnet payout rseed", n),
            &self.blocks.derive("devnet payout hedge", n),
        )?;
        Ok(())
    }

    /// The anti-spam work the devnet's mempool requires.
    pub fn tx_pow(&self) -> TxPow {
        self.mempool.tx_pow()
    }

    /// The proof system the devnet proves and verifies with.
    pub fn system(&self) -> Arc<dyn ProofSystem> {
        self.mempool.system().clone()
    }

    pub fn state(&self) -> &ChainState {
        &self.chain.state
    }

    pub fn height(&self) -> Height {
        self.chain.state.height
    }

    pub fn balance(&self, name: &str) -> Option<u64> {
        self.wallets.index_of(name).map(|w| self.wallets.balance(w))
    }

    /// Builds a payment and submits it to the mempool, where it waits by fee tier.
    /// A lower-tier payment it evicts from a full pool has its inputs released.
    pub fn pay(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
        priority: bool,
    ) -> Result<(), PayError> {
        let from = self.wallets.index_of(from).ok_or(PayError::UnknownWallet)?;
        let to = self.wallets.index_of(to).ok_or(PayError::UnknownWallet)?;
        let to = self.wallets.address(to);
        let tx = self.wallets.build_payment(
            &self.chain.state,
            &self.chain.params,
            &self.mempool.tx_pow(),
            self.chain.verifier.as_ref(),
            from,
            &to,
            amount,
            priority,
        )?;
        let slot = tx.slot;
        match self.mempool.submit(&self.chain.state, tx, None) {
            Ok(evicted) => {
                if let Some(old) = evicted {
                    self.wallets.release(&old.slot);
                }
                Ok(())
            }
            Err(e) => {
                self.wallets.release(&slot);
                Err(PayError::Mempool(e))
            }
        }
    }

    /// Produces one block: take transactions from the mempool → `build_block` →
    /// self-validate with `apply_block` → wallet scan.
    ///
    /// `timestamp` is raised to one second past the tip's when it is not
    /// already later, so a stalled clock or several blocks per second stay
    /// valid: with one producer, timestamps only increase, so the tip's is the
    /// latest and one past it exceeds the median-time-past floor.
    pub fn mine(&mut self, timestamp: u64) -> Result<BlockInfo, NodeError> {
        let timestamp = timestamp.max(self.chain.state.timestamp() + 1);
        let n = self.chain.params.container_size as usize;
        let mut txs = Vec::new();
        for tx in self.mempool.take(n) {
            match admissible(
                &self.chain.state,
                &self.mempool.tx_pow(),
                self.chain.verifier.as_ref(),
                &tx,
            ) {
                Ok(_) => txs.push(tx),
                Err(_) => self.wallets.release(&tx.slot),
            }
        }
        let height = self.chain.state.height + 1;
        let seed = self.blocks.child("devnet block seed", height);
        let payouts: Vec<Payout> = self.payouts.pending().to_vec();
        self.payouts.clear();
        let block = match self.build(&txs, &payouts, &seed, timestamp) {
            Ok(b) => b,
            Err(_) if !txs.is_empty() || !payouts.is_empty() => {
                // A transaction or payout made block building fail: drop this
                // batch and produce a block of empty packages only.
                for tx in &txs {
                    self.wallets.release(&tx.slot);
                }
                self.build(&[], &[], &seed, timestamp)
                    .map_err(NodeError::Build)?
            }
            Err(e) => return Err(NodeError::Build(e)),
        };
        let roots = self.chain.apply_block(&block).map_err(NodeError::Apply)?;
        self.wallets.scan(block.header.height, &block.body);
        Ok(BlockInfo {
            height: block.header.height,
            hash: self.chain.state.tip,
            state_root: roots.state_root,
        })
    }

    fn build(
        &self,
        txs: &[PendingTx],
        payouts: &[Payout],
        seed: &SecretSeed,
        timestamp: u64,
    ) -> Result<Block, BuildError> {
        build_block(
            &self.chain.state,
            &self.chain.state.anchors,
            &self.chain.params,
            self.chain.verifier.as_ref(),
            &self.miner,
            txs,
            payouts,
            seed,
            timestamp,
        )
    }
}
