//! Testnet node core: one chain, one wallet, a mempool, and the block store,
//! without the network. The peer-to-peer layer hands it blocks and
//! transactions and relays what it produces.
//!
//! Every block, whether mined here or received, goes through [`Node::accept`]:
//! the chain validates it with the same transition a producer used, the store
//! saves it, and the wallet and mempool follow the tip. A reorg rolls the
//! wallet back to the fork and scans the new branch; transactions of the
//! abandoned branch are not returned to the mempool (docs/security-model.md).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::keystore::Keystore;

use siworld_circuits::ProofSystem;
use siworld_consensus::{
    build_unsealed, build_unsealed_with_header, median_time_past, BlockError, BuildError, Chain,
    Miner, PendingTx, TipChange,
};
use siworld_core::{params::ChainParams, Block, Digest, Header, Height, Payout};
use siworld_crypto::{domain_hash, Address, SecretSeed, SpendKey};
use siworld_state::{ChainState, DevFund, RecentRoots};
use siworld_storage::{BlockStore, StoreError};

use crate::devfund::{DevFundSigner, PayoutQueue};
use crate::genesis::Genesis;
use crate::mempool::{Mempool, MempoolError, TxPow, DEFAULT_CAPACITY, DEFAULT_PER_PEER};
use crate::wallet::{PayError, Wallets};

/// The node's wallet in [`Wallets`].
const WALLET: usize = 0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Balance {
    /// Every unspent package, including immature miner packages (in the tree
    /// or still queued) and inputs of pending payments.
    pub total: u64,
    /// What a payment can use now.
    pub spendable: u64,
    /// What becomes spendable without further action: the change of payments
    /// not yet in a block, and immature miner packages.
    pub pending: u64,
}

#[derive(Debug)]
pub enum AcceptError {
    Block(BlockError),
    /// The chain accepted the block but the store failed to save it; the
    /// node should stop, since a restart would not see the block.
    Store(StoreError),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(e) => write!(f, "invalid block: {e:?}"),
            Self::Store(e) => write!(f, "cannot save block: {e}"),
        }
    }
}

impl std::error::Error for AcceptError {}

#[derive(Debug)]
pub enum OpenError {
    Store(StoreError),
    /// Stored block `seq` no longer validates.
    Replay {
        seq: u64,
        error: BlockError,
    },
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Replay { seq, error } => {
                write!(f, "stored block {seq} does not validate: {error:?}")
            }
        }
    }
}

impl std::error::Error for OpenError {}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TemplateError {
    /// No candidate was built or pending work changed.
    Randomness,
    Build(BuildError),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Randomness => f.write_str("OS randomness unavailable; no candidate was built"),
            Self::Build(error) => write!(f, "cannot build candidate: {error:?}"),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Owned work for the background producer. No wallet or signing keys, live
/// queues, store, or mutable chain handle cross the worker boundary.
pub(crate) struct TemplateWork {
    state: ChainState,
    params: ChainParams,
    system: Arc<dyn ProofSystem>,
    miner: Miner,
    txs: Vec<PendingTx>,
    payouts: Vec<Payout>,
    timestamp: u64,
    cache: Arc<Mutex<ProducerCache>>,
}

#[derive(Default)]
struct ProducerCache {
    /// Only locally generated zero-fee padding, never a wallet witness/seed.
    padding: Vec<PendingTx>,
    anchors: Option<RecentRoots>,
}

impl TemplateWork {
    pub(crate) fn build_with_header(
        self,
        on_header: impl FnOnce(Header),
    ) -> Result<Block, TemplateError> {
        let seed = SecretSeed::from_os_rng().map_err(|_| TemplateError::Randomness)?;
        let mut cache = self.cache.lock().map_err(|_| {
            TemplateError::Build(BuildError::Aggregate(
                siworld_circuits::AggregateError::Prover("producer cache poisoned".into()),
            ))
        })?;
        let anchors = cache
            .anchors
            .as_ref()
            .filter(|a| {
                let root = a.accumulator_root();
                (root == self.state.anchors.accumulator_root()
                    || Some(root) == self.state.prev_anchors_root)
                    && self
                        .txs
                        .iter()
                        .all(|t| a.height_of(&t.proof.anchor).is_some())
            })
            .unwrap_or(&self.state.anchors)
            .clone();
        cache.padding.retain(|t| {
            anchors.height_of(&t.proof.anchor).is_some()
                && t.slot.nf.iter().all(|nf| {
                    !self.state.nullifiers.contains(nf)
                        && !self.txs.iter().any(|tx| tx.slot.nf.contains(nf))
                })
        });
        let capacity = self.params.container_size as usize;
        cache.padding.truncate(capacity);
        let missing = capacity.saturating_sub(self.txs.len());
        let (anchor, _) = anchors
            .latest()
            .ok_or(TemplateError::Build(BuildError::NoAnchor))?;
        let ctx = siworld_circuits::RelationContext {
            anchors: &anchors,
            tree_depth: self.params.commitment_tree_depth,
        };
        while cache.padding.len() < missing {
            let (slot, proof, fee) = siworld_circuits::dummy::dummy_slot(
                self.system.as_ref(),
                &ctx,
                anchor,
                &seed.derive("candidate padding", 0),
                cache.padding.len() as u64,
            );
            cache.padding.push(PendingTx {
                slot,
                proof,
                fee,
                nonce: 0,
            });
        }
        let mut entries = self.txs;
        entries.extend(cache.padding.iter().take(missing).cloned());
        cache.anchors = Some(anchors.clone());
        build_unsealed_with_header(
            &self.state,
            &anchors,
            &self.params,
            self.system.as_ref(),
            &self.miner,
            &entries,
            &self.payouts,
            &seed,
            self.timestamp,
            on_header,
        )
        .map_err(TemplateError::Build)
    }
}

struct WalletProtection {
    store: Keystore,
    deadline: Option<Instant>,
}
pub(crate) struct FundProtection {
    pub(crate) store: crate::fund_keys::FundKeystore,
    pub(crate) authorization: Option<crate::fund_keys::Authorization>,
}

pub struct Node {
    pub genesis: Genesis,
    pub chain: Chain<Arc<dyn ProofSystem>>,
    /// Makes and checks every proof of this chain.
    pub system: Arc<dyn ProofSystem>,
    pub wallets: Wallets,
    wallet_protection: Option<WalletProtection>,
    pub(crate) payments: Option<crate::payments::PaymentJournal>,
    pub mempool: Mempool,
    store: Option<BlockStore>,
    /// Whom the node's blocks pay.
    miner: Miner,
    /// The development fund's keys, when this node is the fund's, and the
    /// payouts waiting for the next block it mines.
    pub(crate) dev_fund: Option<DevFundSigner>,
    pub(crate) fund_protection: Option<FundProtection>,
    pub(crate) fund_journal: Option<crate::fund_payments::FundJournal>,
    pub(crate) payouts: PayoutQueue,
    producer_cache: Arc<Mutex<ProducerCache>>,
}

impl Node {
    /// Starts from `genesis` with the spend key `key` and the proof system
    /// `system`, then replays the blocks in `store`, if any. `randomness` must
    /// be secret: it initializes wallet derivation state. Each network-wallet
    /// payment, block candidate and fund payout refreshes from OS randomness;
    /// the wallet also discards the previous derivation state after each draw.
    pub fn open(
        genesis: Genesis,
        key: SpendKey,
        randomness: SecretSeed,
        store: Option<BlockStore>,
        system: Arc<dyn ProofSystem>,
    ) -> Result<Self, OpenError> {
        let committee_key = domain_hash("siworld testnet committee key", &[key.expose_secret()]);
        let mut wallets =
            Wallets::from_keys(vec![("node".into(), key)], randomness.child("wallet", 0));
        wallets.genesis(&genesis.notes());
        // Until the node holds a pre-confirmation key, the committee key hash
        // is derived from the secret spend key, so it cannot be linked to the
        // address by anyone who does not hold the key.
        let miner = Miner {
            address: wallets.address(WALLET),
            committee_key,
        };
        let chain = Chain::new(genesis.params.clone(), genesis.state(), system.clone());
        let stored = match &store {
            Some(s) => s.blocks().map_err(OpenError::Store)?,
            None => Vec::new(),
        };
        let tx_pow = TxPow::for_params(&genesis.params);
        let mut node = Self {
            genesis,
            chain,
            mempool: Mempool::new(DEFAULT_CAPACITY, DEFAULT_PER_PEER, tx_pow, system.clone()),
            system,
            wallets,
            wallet_protection: None,
            payments: None,
            store,
            miner,
            dev_fund: None,
            fund_protection: None,
            fund_journal: None,
            payouts: PayoutQueue::default(),
            producer_cache: Arc::new(Mutex::new(ProducerCache::default())),
        };
        for (seq, block) in stored.iter().enumerate() {
            let accepted = node
                .chain
                .accept(block)
                .map_err(|error| OpenError::Replay {
                    seq: seq as u64,
                    error,
                })?;
            node.follow(accepted.tip);
        }
        Ok(node)
    }

    /// A protected wallet starts locked. No password is retained. The caller
    /// must supply the same authenticated keystore used to open this node.
    pub fn protect_wallet(&mut self, store: Keystore) -> Result<(), String> {
        if self.wallet_protection.is_some() {
            return Err("wallet already protected".into());
        }
        self.wallet_protection = Some(WalletProtection {
            store,
            deadline: None,
        });
        self.lock_wallet();
        Ok(())
    }

    pub fn wallet_is_locked(&self) -> bool {
        self.wallets.is_locked()
    }
    pub fn wallet_is_protected(&self) -> bool {
        self.wallet_protection.is_some()
    }
    pub fn wallet_unlock_deadline(&self) -> Option<Instant> {
        self.wallet_protection.as_ref().and_then(|p| p.deadline)
    }
    pub fn lock_wallet(&mut self) {
        self.wallets.lock();
        if let Some(j) = &mut self.payments {
            j.lock();
        }
        if let Some(p) = &mut self.wallet_protection {
            p.deadline = None;
        }
    }
    pub fn expire_wallet(&mut self, now: Instant) {
        if self.wallet_unlock_deadline().is_some_and(|d| now >= d) {
            self.lock_wallet();
        }
    }
    pub fn unlock_wallet(&mut self, password: &str, seconds: u64) -> Result<(), String> {
        self.expire_wallet(Instant::now());
        if !(1..=3600).contains(&seconds) {
            return Err("unlock timeout must be 1 to 3600 seconds".into());
        }
        let key = self
            .wallet_protection
            .as_ref()
            .ok_or("wallet has no encrypted keystore")?
            .store
            .open(password)?;
        if key.address() != self.address() {
            return Err("keystore does not match this wallet".into());
        }
        // Reconstruct only while locked, preserving live pending reservations.
        if self.wallet_is_locked() {
            self.wallets.unlock(key)?;
            let result = (|| {
                if let Some(j) = &mut self.payments {
                    j.unlock(
                        self.wallets
                            .journal_key(&self.genesis.id)
                            .map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                }
                self.wallets.genesis(&self.genesis.notes());
                self.refresh_payments(true).map_err(|e| e.to_string())
            })();
            if let Err(e) = result {
                self.lock_wallet();
                return Err(e);
            }
            self.follow(TipChange::Extended);
        }
        self.wallet_protection
            .as_mut()
            .expect("protected wallet")
            .deadline = Some(Instant::now() + Duration::from_secs(seconds));
        Ok(())
    }

    /// Authenticate custody and genesis identity, then retain only ciphertext.
    pub fn protect_dev_fund(
        &mut self,
        store: crate::fund_keys::FundKeystore,
        password: &str,
        journal_directory: &std::path::Path,
    ) -> Result<(), String> {
        self.protect_dev_fund_inner(store, password, journal_directory, None)
    }
    pub fn protect_dev_fund_witnessed(
        &mut self,
        store: crate::fund_keys::FundKeystore,
        password: &str,
        journal_directory: &std::path::Path,
        witness_directory: &std::path::Path,
    ) -> Result<(), String> {
        self.protect_dev_fund_inner(store, password, journal_directory, Some(witness_directory))
    }
    fn protect_dev_fund_inner(
        &mut self,
        store: crate::fund_keys::FundKeystore,
        password: &str,
        journal_directory: &std::path::Path,
        witness_directory: Option<&std::path::Path>,
    ) -> Result<(), String> {
        if self.fund_protection.is_some() {
            return Err("fund already configured".into());
        }
        let signer = store.open(password)?;
        if self.genesis.params.dev_fund_keys != Some(signer.verifying_keys()) {
            return Err("fund key does not match this genesis".into());
        }
        let mut journal = crate::fund_payments::FundJournal::open_with_witness(
            journal_directory,
            store.journal_key(password, &self.genesis.id)?,
            &self.genesis,
            witness_directory,
        )
        .map_err(|e| e.to_string())?;
        journal.lock();
        self.fund_journal = Some(journal);
        self.fund_protection = Some(FundProtection {
            store,
            authorization: None,
        });
        self.refresh_fund_payouts();
        Ok(())
    }
    pub fn fund_unlock_deadline(&self) -> Option<Instant> {
        self.fund_protection
            .as_ref()
            .and_then(|p| p.authorization.as_ref())
            .map(|a| a.deadline)
    }
    pub fn lock_fund(&mut self) {
        self.dev_fund = None;
        if let Some(j) = &mut self.fund_journal {
            j.lock();
        }
        if let Some(p) = &mut self.fund_protection {
            p.authorization = None;
        }
    }
    pub fn expire_fund(&mut self, now: Instant) {
        if self.fund_unlock_deadline().is_some_and(|d| now >= d) {
            self.lock_fund();
        }
    }
    pub fn unlock_fund(
        &mut self,
        password: &str,
        grant: &crate::fund_keys::FundGrant,
    ) -> Result<(), String> {
        self.expire_fund(Instant::now());
        if self.dev_fund.is_some() {
            return Err("fund already unlocked; lock before authorizing a new budget".into());
        }
        let p = self
            .fund_protection
            .as_mut()
            .ok_or("no encrypted fund keystore configured")?;
        let signer = p.store.open(password)?;
        let authorization = grant.validate(&self.genesis.id)?;
        if self.genesis.params.dev_fund_keys != Some(signer.verifying_keys()) {
            return Err("fund key does not match this genesis".into());
        }
        self.fund_journal
            .as_mut()
            .ok_or("fund journal required")?
            .unlock(
                p.store.journal_key(password, &self.genesis.id)?,
                &self.genesis,
            )
            .map_err(|e| e.to_string())?;
        if !self.fund_chain_ready() {
            self.fund_journal.as_mut().expect("journal").lock();
            return Err("fund chain synchronization required".into());
        }
        // Persist policy enrollment and a single-use approval before exposing a signer.
        // Any ambiguous write leaves this instance locked and requires recovery.
        if let Err(e) = self.record_fund_approval(grant) {
            self.lock_fund();
            return Err(e);
        }
        self.fund_protection
            .as_mut()
            .expect("protected")
            .authorization = Some(authorization);
        self.dev_fund = Some(signer);
        Ok(())
    }
    pub fn fund_status(&mut self) -> crate::fund_keys::FundStatus {
        self.expire_fund(Instant::now());
        let a = self
            .fund_protection
            .as_ref()
            .and_then(|p| p.authorization.as_ref());
        crate::fund_keys::FundStatus {
            configured: self.fund_protection.is_some(),
            locked: self.dev_fund.is_none(),
            direct_remaining: a.map_or(0, |a| a.remaining[0]),
            lock_remaining: a.map_or(0, |a| a.remaining[1]),
            max_payout: a.map_or(0, |a| a.max),
        }
    }

    /// The development-fund accounts after the tip.
    pub fn dev_fund(&self) -> &DevFund {
        &self.chain.state.dev_fund
    }

    pub fn height(&self) -> Height {
        self.chain.state.height
    }

    pub fn tip(&self) -> Digest {
        self.chain.state.tip
    }

    pub fn address(&self) -> Address {
        self.miner.address.clone()
    }

    pub fn balance(&self) -> Result<Balance, PayError> {
        if self.wallet_is_locked()
            || self
                .wallet_unlock_deadline()
                .is_some_and(|d| Instant::now() >= d)
        {
            return Err(PayError::Locked);
        }
        Ok(Balance {
            total: self.wallets.balance(WALLET),
            spendable: self.wallets.spendable(WALLET, self.height()),
            pending: self.wallets.pending(WALLET, self.height()),
        })
    }

    /// Validates, stores and follows a block, mined here or received.
    pub fn accept(&mut self, block: &Block) -> Result<TipChange, AcceptError> {
        let accepted = self.chain.accept(block).map_err(AcceptError::Block)?;
        if let Some(store) = &mut self.store {
            store.append(block).map_err(AcceptError::Store)?;
        }
        self.follow(accepted.tip);
        Ok(accepted.tip)
    }

    /// Brings the wallet and the mempool to the chain's tip.
    fn follow(&mut self, tip: TipChange) {
        if tip == TipChange::None {
            return;
        }
        if let TipChange::Reorg { fork } = tip {
            self.wallets.rollback(fork);
        }
        let from = if self.wallet_is_locked() {
            self.chain.state.height.saturating_add(1)
        } else {
            self.wallets.height().map_or(0, |h| h + 1)
        };
        for height in from..=self.chain.state.height {
            let hash = self.chain.main_hash(height).expect("main chain");
            let block = self
                .chain
                .block(&hash)
                .expect("main chain blocks are stored");
            self.wallets.scan(height, &block.body);
        }
        for tx in self.mempool.prune(&self.chain.state) {
            self.wallets.release(&tx.slot);
        }
        if self
            .refresh_payments(matches!(tip, TipChange::Reorg { .. }))
            .is_err()
        {
            // Fail closed without emitting private payment identifiers or details.
            eprintln!("payment journal unavailable; spending disabled until restart");
        }
        self.refresh_fund_payouts();
        let dropped = self.payouts.prune(&self.chain.state.dev_fund);
        if !dropped.is_empty() {
            // Amounts and counters only: the fund's payouts are public anyway.
            eprintln!(
                "dropped {} queued payout(s) the chain no longer expects",
                dropped.len()
            );
        }
    }

    /// Admits a transaction to the mempool, from the peer `source` or from
    /// this node (`None`).
    pub fn submit_tx(&mut self, tx: PendingTx, source: Option<Digest>) -> Result<(), MempoolError> {
        if let Some(evicted) = self.mempool.submit(&self.chain.state, tx, source)? {
            self.wallets.release(&evicted.slot);
        }
        Ok(())
    }

    /// Builds a payment, admits it to the mempool, and returns it for relay.
    pub fn pay(
        &mut self,
        to: &Address,
        amount: u64,
        priority: bool,
    ) -> Result<PendingTx, PayError> {
        if self.payments.is_some() {
            return Err(PayError::DurablePaymentRequired);
        }
        self.expire_wallet(Instant::now());
        if self.wallet_is_locked() {
            return Err(PayError::Locked);
        }
        let tx = self.wallets.build_payment(
            &self.chain.state,
            &self.chain.params,
            &self.mempool.tx_pow(),
            self.system.as_ref(),
            WALLET,
            to,
            amount,
            priority,
        )?;
        match self.submit_tx(tx.clone(), None) {
            Ok(()) => Ok(tx),
            Err(e) => {
                self.wallets.release(&tx.slot);
                Err(PayError::Mempool(e))
            }
        }
    }

    /// Capture only when the single candidate worker is free. Cloning the
    /// in-memory state is still synchronous; persistent snapshots are W4 work.
    pub(crate) fn template_work(&self, now: u64) -> TemplateWork {
        TemplateWork {
            state: self.chain.state.clone(),
            params: self.chain.params.clone(),
            system: self.system.clone(),
            miner: self.miner.clone(),
            txs: self.mempool.peek(self.chain.params.container_size as usize),
            payouts: self.payouts.pending().to_vec(),
            timestamp: now.max(median_time_past(&self.chain.state) + 1),
            cache: self.producer_cache.clone(),
        }
    }

    /// A block on the tip with the best pending transactions, its nonce still
    /// to be searched. The timestamp is `now`, raised past the median time
    /// past when the clock lags it. If the transactions make building fail,
    /// they are dropped from the mempool and the block carries empty packages
    /// only. Each candidate draws independent OS entropy; its seed's owned
    /// storage is erased when construction returns, including on failure.
    pub fn template(&mut self, now: u64) -> Result<Block, TemplateError> {
        self.template_with_rng(now, || {
            SecretSeed::from_os_rng().map_err(|_| TemplateError::Randomness)
        })
    }

    fn template_with_rng(
        &mut self,
        now: u64,
        rng: impl FnOnce() -> Result<SecretSeed, TemplateError>,
    ) -> Result<Block, TemplateError> {
        // Obtain entropy before inspecting or mutating pending work. A failed
        // RNG must not fall back to a retained or deterministic seed.
        let seed = rng()?;
        let timestamp = now.max(median_time_past(&self.chain.state) + 1);
        let txs = self.mempool.peek(self.chain.params.container_size as usize);
        let payouts = self.payouts.pending().to_vec();
        match self.build(&txs, &payouts, &seed, timestamp) {
            Err(_) if !txs.is_empty() || !payouts.is_empty() => {
                // Find which side is at fault and drop only that one.
                if !payouts.is_empty() {
                    if let Ok(block) = self.build(&txs, &[], &seed, timestamp) {
                        eprintln!(
                            "dropped {} queued payout(s) a block cannot carry",
                            payouts.len()
                        );
                        self.refresh_fund_payouts();
                        return Ok(block);
                    }
                }
                for tx in &txs {
                    self.mempool.remove_slot(&tx.slot.id());
                    self.wallets.release(&tx.slot);
                }
                match self.build(&[], &payouts, &seed, timestamp) {
                    Ok(block) => Ok(block),
                    Err(_) => {
                        self.refresh_fund_payouts();
                        self.build(&[], &[], &seed, timestamp)
                    }
                }
            }
            result => result,
        }
        .map_err(TemplateError::Build)
    }

    fn build(
        &self,
        txs: &[PendingTx],
        payouts: &[Payout],
        seed: &SecretSeed,
        timestamp: u64,
    ) -> Result<Block, BuildError> {
        build_unsealed(
            &self.chain.state,
            &self.chain.state.anchors,
            &self.chain.params,
            self.system.as_ref(),
            &self.miner,
            txs,
            payouts,
            seed,
            timestamp,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_circuits::MockProver;
    use siworld_core::params::ATOMS_PER_SI;

    use crate::genesis::{AllocationFile, GenesisFile, ProofsFile};
    use crate::hex;

    #[test]
    fn unused_padding_is_reused_but_included_nullifiers_are_never_recycled() {
        let key = SpendKey::from_digest(Digest([1; 32]));
        let genesis = Genesis::from_file(&GenesisFile {
            network: "padding-cache".into(),
            timestamp: 1_000,
            block_time: 60,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 4,
            proofs: ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![],
        })
        .unwrap();
        let mut node = Node::open(
            genesis,
            key,
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        let mut first = node.template_work(1_001).build_with_header(|_| {}).unwrap();
        let second = node.template_work(1_002).build_with_header(|_| {}).unwrap();
        assert_eq!(
            first.body.slots, second.body.slots,
            "retain unused leaf proofs across same-tip candidates"
        );
        assert_ne!(
            first.body.coinbase.miner_note_cm, second.body.coinbase.miner_note_cm,
            "fresh miner witness for every candidate"
        );
        assert!(siworld_consensus::mine(&mut first.header, 1));
        node.accept(&first).unwrap();
        let third = node.template_work(1_003).build_with_header(|_| {}).unwrap();
        assert!(third.body.slots.iter().all(|s| !first
            .body
            .slots
            .iter()
            .any(|old| old.id() == s.id())));
        assert_eq!(node.producer_cache.lock().unwrap().padding.len(), 4);
    }

    #[test]
    fn retained_anchor_is_used_only_while_parent_or_grandparent_allows_it() {
        let genesis = Genesis::from_file(&GenesisFile {
            network: "anchor-cache".into(),
            timestamp: 1_000,
            block_time: 60,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 2,
            proofs: ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![],
        })
        .unwrap();
        let make_node = |byte| {
            Node::open(
                genesis.clone(),
                SpendKey::from_digest(Digest([byte; 32])),
                SecretSeed::from_os_rng().unwrap(),
                None,
                Arc::new(MockProver),
            )
            .unwrap()
        };
        let mut node = make_node(1);
        let mut peer = make_node(2);
        let first = node.template_work(1_001).build_with_header(|_| {}).unwrap();
        let initial_root = node.chain.state.anchors.accumulator_root();
        for height in 1..=2 {
            let mut remote = peer.template(1_000 + height).unwrap();
            assert!(siworld_consensus::mine(&mut remote.header, 1));
            peer.accept(&remote).unwrap();
            node.accept(&remote).unwrap();
            let candidate = node
                .template_work(1_001 + height)
                .build_with_header(|_| {})
                .unwrap();
            assert_eq!(
                candidate.body.slots, first.body.slots,
                "unspent padding leaves stay reusable"
            );
            siworld_consensus::check_proof(
                &candidate.proof,
                &node.chain.state,
                &candidate.body,
                height + 1,
                node.system.as_ref(),
            )
            .unwrap();
            let used = node
                .producer_cache
                .lock()
                .unwrap()
                .anchors
                .as_ref()
                .unwrap()
                .accumulator_root();
            assert_eq!(
                used,
                if height == 1 {
                    initial_root
                } else {
                    node.chain.state.anchors.accumulator_root()
                }
            );
        }
    }

    #[test]
    fn entropy_failure_preserves_pending_payment_and_state() {
        let key = SpendKey::from_digest(Digest([1; 32]));
        let genesis = Genesis::from_file(&GenesisFile {
            network: "rng-failure".into(),
            timestamp: 1_000,
            block_time: 1,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 4,
            proofs: ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![AllocationFile {
                owner: hex(&key.owner()),
                amount: "100".into(),
            }],
        })
        .unwrap();
        let mut node = Node::open(
            genesis,
            key,
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        let to = SpendKey::from_digest(Digest([2; 32])).address();
        let tx = node.pay(&to, ATOMS_PER_SI, false).unwrap();
        let before = node.balance().unwrap();
        let roots = node.chain.state.roots();
        assert!(matches!(
            node.template_with_rng(1_001, || Err(TemplateError::Randomness)),
            Err(TemplateError::Randomness)
        ));
        assert_eq!(node.balance().unwrap(), before);
        assert_eq!(node.chain.state.roots(), roots);
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.mempool.peek(1)[0].slot.id(), tx.slot.id());
        assert_eq!(node.template(1_001).unwrap().body.slots.len(), 4);
    }
}
