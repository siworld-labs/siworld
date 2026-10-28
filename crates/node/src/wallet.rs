//! Wallets: a set of named spend keys that track their packages and build
//! payments. The devnet derives its test keys from a public seed; a node holds
//! one key drawn from the operating system.
//!
//! Wallets find incoming packages the way real wallets do (docs/node-operations.md): for each
//! main-chain block, each wallet trial-decrypts every new package with its view
//! key, using the view tag to skip most of them. Value-zero packages (empty
//! packages, zero change) are not tracked. Each package records the height
//! that created it and the height that spent it, so a reorg rolls the wallets
//! back to the fork point and the new branch is scanned forward again.
//!
//! A miner package is decrypted from the coinbase of the block that pays it,
//! but it enters the commitment tree only `COINBASE_MATURITY` blocks later
//! (the pending-reward queue, docs/protocol.md), so it is tracked as a pending reward
//! until the block that appends it gives it a tree position.

use std::collections::{BTreeMap, BTreeSet};

use siworld_circuits::{
    encrypt_outputs, output_rhos, InputWitness, ProofSystem, ProveError, RelationContext,
    SlotWitness,
};
use siworld_consensus::PendingTx;
use siworld_core::issuance::{epoch_of, fee_base, fee_priority};
use siworld_core::params::{ChainParams, COINBASE_MATURITY, MAX_REORG_DEPTH, MIN_PACKAGE_DEPOSIT};
use siworld_core::{BlockBody, Commitment, Condition, Digest, Height, Note, Nullifier, Slot};
use siworld_crypto::{
    expand, note_commitment, nullifier, payout_note, Address, SecretSeed, SpendKey, ViewKey,
};
use siworld_state::ChainState;

use crate::amount::format_sip;
use crate::mempool::{MempoolError, TxPow};

/// An on-chain package, its position in the commitment tree, and the height
/// of the block that created it.
#[derive(Clone, Copy)]
pub struct Owned {
    pub note: Note,
    pub index: u64,
    pub found: Height,
}

impl core::fmt::Debug for Owned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Owned(REDACTED)")
    }
}

pub struct Wallet {
    pub name: String,
    keys: Option<WalletSecrets>,
    address: Address,
    /// Unspent packages.
    notes: Vec<Owned>,
    /// Spent packages and the height that spent them, kept for a reorg.
    spent: Vec<(Owned, Height)>,
    /// Inputs already used by pending transactions, so one package is not used by
    /// two payments at once.
    reserved: BTreeSet<Nullifier>,
    /// The change of each pending payment, by the nullifier of its first input,
    /// until the payment is on chain or dropped.
    change: BTreeMap<Nullifier, u64>,
    durable_reserved: BTreeSet<Nullifier>,
    durable_change: BTreeMap<Nullifier, u64>,
    /// Miner packages paid to this wallet, with the height of the block that
    /// paid each. One matures (joins `notes`) when the block
    /// `COINBASE_MATURITY` later appends it; it is kept here for
    /// `MAX_REORG_DEPTH` more blocks so a rollback can make it pending again.
    rewards: Vec<(Note, Height)>,
}

struct WalletSecrets {
    sk: SpendKey,
    vk: ViewKey,
}

fn erase_note(note: &mut Note) {
    use zeroize::Zeroize;
    note.owner.0.zeroize();
    note.value.zeroize();
    note.cond.unlock_height.zeroize();
    note.rho.0.zeroize();
    note.rseed.0.zeroize();
}

impl Wallet {
    fn key(&self) -> &SpendKey {
        &self.keys.as_ref().expect("wallet is unlocked").sk
    }

    fn erase_notes(&mut self) {
        for o in &mut self.notes {
            erase_note(&mut o.note);
        }
        for (o, _) in &mut self.spent {
            erase_note(&mut o.note);
        }
        for (note, _) in &mut self.rewards {
            erase_note(note);
        }
        self.notes.clear();
        self.spent.clear();
        self.rewards.clear();
    }

    fn nf(&self, note: &Note) -> Nullifier {
        nullifier(&self.key().nullifier_key(), &note.rho)
    }

    pub fn address(&self) -> Address {
        self.address.clone()
    }

    /// Unspent packages.
    pub fn notes(&self) -> &[Owned] {
        &self.notes
    }

    pub fn nullifier_of(&self, o: &Owned) -> Nullifier {
        self.nf(&o.note)
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.erase_notes();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PayError {
    Locked,
    DurablePaymentRequired,
    UnknownWallet,
    /// Fresh OS randomness was unavailable; inputs were not reserved.
    Randomness,
    /// The amount is below the minimum deposit MIN_PACKAGE_DEPOSIT.
    AmountTooSmall,
    /// At most two packages cannot cover the amount plus the fee, even once
    /// pending payments confirm and immature packages mature.
    InsufficientFunds,
    /// The spendable packages cannot cover the amount plus the fee, but they
    /// will once `pending` (the change of payments not yet on chain and
    /// immature packages) becomes spendable.
    FundsPending {
        pending: u64,
    },
    /// The change is non-zero but below the minimum deposit.
    ChangeTooSmall,
    /// The proof system refused to prove the payment.
    Prove(ProveError),
    Mempool(MempoolError),
}

impl std::fmt::Display for PayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownWallet => write!(f, "unknown wallet"),
            Self::DurablePaymentRequired => write!(f, "a durable payment ID is required"),
            Self::Locked => write!(f, "wallet is locked"),
            Self::Randomness => write!(f, "OS randomness unavailable; no payment was built"),
            Self::AmountTooSmall => write!(
                f,
                "the amount is below the minimum package of {} SIP",
                format_sip(MIN_PACKAGE_DEPOSIT)
            ),
            Self::InsufficientFunds => write!(
                f,
                "insufficient funds: at most two packages pay for one payment and its fee"
            ),
            Self::FundsPending { pending } => write!(
                f,
                "{} SIP is not spendable yet; wait for the previous payment to confirm, then send again",
                format_sip(*pending)
            ),
            Self::ChangeTooSmall => write!(
                f,
                "the change would be below the minimum package of {} SIP; send a slightly different amount",
                format_sip(MIN_PACKAGE_DEPOSIT)
            ),
            Self::Prove(e) => write!(f, "cannot build the payment: {e}"),
            Self::Mempool(e) => write!(f, "the mempool rejected the payment: {e:?}"),
        }
    }
}

impl std::error::Error for PayError {}

/// Whether at most two of `values` sum to at least `need`.
fn covers(values: &[u64], need: u64) -> bool {
    let mut top = [0u64; 2];
    for &v in values {
        if v > top[0] {
            top = [v, top[0]];
        } else if v > top[1] {
            top[1] = v;
        }
    }
    top[0].checked_add(top[1]).is_none_or(|sum| sum >= need)
}

pub(crate) struct PaymentPlan {
    inputs: Vec<Owned>,
    pub nfs: Vec<Nullifier>,
    anchor: Digest,
    pub anchor_height: u64,
    fee: u64,
    pub change: u64,
}
impl Drop for PaymentPlan {
    fn drop(&mut self) {
        for input in &mut self.inputs {
            erase_note(&mut input.note);
        }
    }
}

pub struct Wallets {
    wallets: Vec<Wallet>,
    /// Secret randomness for output `rseed`s, encryption, fee blinds, and dummy
    /// inputs; each draw uses the next counter value.
    randomness: SecretSeed,
    counter: u64,
    /// Network wallets refresh before each payment; the opt-in devnet can replay.
    os_payment_entropy: bool,
    /// Commitment-tree leaves after each scanned block, by height from 0.
    leaves: Vec<u64>,
}

impl Wallets {
    /// Derives one spend key per name from `seed`. The keys are test keys: anyone
    /// who knows `seed` can spend and view their packages. Payment randomness
    /// comes from `randomness` instead, so it stays secret either way.
    pub fn new(seed: Digest, randomness: SecretSeed, names: &[&str]) -> Self {
        let keys = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let sk = SpendKey::from_digest(expand(&seed, "devnet wallet key", i as u64));
                ((*name).to_string(), sk)
            })
            .collect();
        let mut wallets = Self::from_keys(keys, randomness);
        wallets.os_payment_entropy = false;
        wallets
    }

    /// Wallets for the given named spend keys.
    pub fn from_keys(keys: Vec<(String, SpendKey)>, randomness: SecretSeed) -> Self {
        let wallets = keys
            .into_iter()
            .map(|(name, sk)| {
                let vk = sk.view_key();
                Wallet {
                    name,
                    address: vk.address(),
                    keys: Some(WalletSecrets { sk, vk }),
                    notes: Vec::new(),
                    spent: Vec::new(),
                    reserved: BTreeSet::new(),
                    change: BTreeMap::new(),
                    durable_reserved: BTreeSet::new(),
                    durable_change: BTreeMap::new(),
                    rewards: Vec::new(),
                }
            })
            .collect();
        Self {
            wallets,
            randomness,
            counter: 0,
            os_payment_entropy: true,
            leaves: Vec::new(),
        }
    }

    /// Locking removes owned spend/view keys and private note copies. Pending
    /// reservation identifiers/amounts remain so a live unlock cannot reuse inputs.
    pub fn lock(&mut self) {
        use zeroize::Zeroize;
        for w in &mut self.wallets {
            w.keys = None;
            w.erase_notes();
        }
        self.leaves.clear();
        self.randomness.zeroize();
        self.counter = 0;
    }

    pub fn is_locked(&self) -> bool {
        self.wallets.iter().any(|w| w.keys.is_none())
    }

    pub(crate) fn unlock(&mut self, key: SpendKey) -> Result<(), String> {
        if self.wallets.len() != 1 || key.address() != self.wallets[0].address {
            return Err("keystore does not match this wallet".into());
        }
        let vk = key.view_key();
        self.wallets[0].keys = Some(WalletSecrets { sk: key, vk });
        Ok(())
    }

    pub(crate) fn journal_key(
        &self,
        network: &Digest,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PayError> {
        let keys = self.wallets[0].keys.as_ref().ok_or(PayError::Locked)?;
        Ok(journal_key_from_spend_key(&keys.sk, network))
    }

    pub(crate) fn durable_reservations(
        &mut self,
        reserved: BTreeSet<Nullifier>,
        change: BTreeMap<Nullifier, u64>,
    ) {
        self.wallets[0].durable_reserved = reserved;
        self.wallets[0].durable_change = change;
    }

    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.wallets.iter().position(|w| w.name == name)
    }

    pub fn get(&self, name: &str) -> Option<&Wallet> {
        self.wallets.iter().find(|w| w.name == name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Wallet> {
        self.wallets.iter()
    }

    pub fn address(&self, wallet: usize) -> Address {
        self.wallets[wallet].address()
    }

    /// Height of the last scanned block.
    pub fn height(&self) -> Option<Height> {
        (self.leaves.len() as u64).checked_sub(1)
    }

    fn next_random(&mut self, label: &str) -> Digest {
        self.counter = self
            .counter
            .checked_add(1)
            .expect("wallet randomness counter exhausted");
        let value = self.randomness.derive(label, self.counter);
        // Discard the prior state: the live state must not reconstruct older draws.
        self.randomness = self
            .randomness
            .child("wallet randomness ratchet v1", self.counter);
        value
    }

    /// A transaction output's `rho` must be derived from the input nullifiers (see
    /// `output_rhos`); genesis packages may use random values.
    fn new_note(&mut self, owner: Digest, value: u64, rho: Digest) -> Note {
        Note {
            owner,
            value,
            cond: Condition { unlock_height: 0 },
            rho,
            rseed: self.next_random("devnet note rseed"),
        }
    }

    /// Devnet genesis funds: creates a package for each (wallet, amount) with
    /// secret randomness, records it, and returns the commitments for the
    /// genesis tree in that order.
    pub fn genesis_notes(&mut self, specs: &[(usize, u64)]) -> Vec<Commitment> {
        let notes: Vec<Note> = specs
            .iter()
            .map(|&(w, value)| {
                let rho = self.next_random("devnet genesis rho");
                self.new_note(self.wallets[w].address.owner(), value, rho)
            })
            .collect();
        self.genesis(&notes);
        notes.iter().map(note_commitment).collect()
    }

    /// Records the genesis tree's packages, in tree order, that belong to a
    /// wallet. Genesis packages are not encrypted, so they are matched by owner.
    pub fn genesis(&mut self, notes: &[Note]) {
        assert!(self.leaves.is_empty(), "genesis comes first");
        for (index, note) in notes.iter().enumerate() {
            if let Some(w) = self
                .wallets
                .iter_mut()
                .find(|w| w.address.owner() == note.owner)
            {
                w.notes.push(Owned {
                    note: *note,
                    index: index as u64,
                    found: 0,
                });
            }
        }
        self.leaves.push(notes.len() as u64);
    }

    /// Scans the main-chain block at `height`, the one after the last scanned:
    /// trial-decrypts its new packages, records those that decrypt to non-zero
    /// value, gives the miner package that matured in this block its tree
    /// position, records this block's miner package as a pending reward, and
    /// marks the packages its nullifiers spend.
    pub fn scan(&mut self, height: Height, body: &BlockBody) {
        if self.is_locked() {
            return;
        }
        assert_eq!(
            Some(height),
            self.height().map(|h| h + 1),
            "blocks are scanned once, in order"
        );
        let base = *self.leaves.last().expect("genesis is recorded");
        let mut new = 0u64;
        for (i, (cm, tag, ct)) in body.outputs().enumerate() {
            new += 1;
            for w in &mut self.wallets {
                if let Some(note) = w
                    .keys
                    .as_ref()
                    .expect("wallet is unlocked")
                    .vk
                    .decrypt(cm, tag, ct)
                {
                    if note.value != 0 {
                        w.notes.push(Owned {
                            note,
                            index: base + i as u64,
                            found: height,
                        });
                    }
                    break;
                }
            }
        }
        // After its slot outputs the block appends the miner package of the
        // block COINBASE_MATURITY earlier (or the zero digest): one leaf.
        for w in &mut self.wallets {
            if let Some((note, _)) = w
                .rewards
                .iter()
                .find(|(_, paid)| paid + COINBASE_MATURITY == height)
            {
                w.notes.push(Owned {
                    note: *note,
                    index: base + new,
                    found: height,
                });
            }
            w.rewards
                .retain(|(_, paid)| paid + COINBASE_MATURITY + MAX_REORG_DEPTH >= height);
        }
        new += 1;
        // Then the payouts' packages, whose plaintexts are public: a wallet
        // recognises its own by the owner.
        for (i, p) in body.payouts.iter().enumerate() {
            if let Some(w) = self
                .wallets
                .iter_mut()
                .find(|w| w.address.owner() == p.owner)
            {
                w.notes.push(Owned {
                    note: payout_note(p, height, i as u32),
                    index: base + new + i as u64,
                    found: height,
                });
            }
        }
        new += body.payouts.len() as u64;
        // This block's miner package: pending until it matures.
        let (cm, tag, ct) = body.miner_package();
        for w in &mut self.wallets {
            if let Some(note) = w
                .keys
                .as_ref()
                .expect("wallet is unlocked")
                .vk
                .decrypt(cm, tag, ct)
            {
                if note.value != 0 {
                    w.rewards.push((note, height));
                }
                break;
            }
        }
        self.leaves.push(base + new);
        let spent: BTreeSet<Nullifier> = body.slots.iter().flat_map(|s| s.nf).collect();
        for w in &mut self.wallets {
            let nk = w.key().nullifier_key();
            let (gone, kept): (Vec<Owned>, Vec<Owned>) = std::mem::take(&mut w.notes)
                .into_iter()
                .partition(|o| spent.contains(&nullifier(&nk, &o.note.rho)));
            w.notes = kept;
            w.spent.extend(gone.into_iter().map(|o| (o, height)));
            w.reserved.retain(|nf| !spent.contains(nf));
            w.change.retain(|nf, _| !spent.contains(nf));
        }
    }

    /// Undoes every block above `height`, as when a reorg replaces them: their
    /// packages are forgotten and the packages they spent are unspent again.
    pub fn rollback(&mut self, height: Height) {
        let keep = usize::try_from(height).expect("height fits in memory") + 1;
        if keep >= self.leaves.len() {
            return;
        }
        self.leaves.truncate(keep);
        for w in &mut self.wallets {
            let (back, still): (Vec<_>, Vec<_>) = std::mem::take(&mut w.spent)
                .into_iter()
                .partition(|(_, at)| *at > height);
            w.spent = still;
            w.notes.extend(back.into_iter().map(|(o, _)| o));
            w.notes.retain(|o| o.found <= height);
            w.rewards.retain(|(_, paid)| *paid <= height);
        }
    }

    /// When a transaction does not make it on chain (rejected by the mempool or
    /// invalidated before inclusion), releases its inputs.
    pub fn release(&mut self, slot: &Slot) {
        for w in &mut self.wallets {
            for nf in &slot.nf {
                w.reserved.remove(nf);
                w.change.remove(nf);
            }
        }
    }

    /// Total of unspent packages on the scanned chain (including immature
    /// packages and packages reserved by pending transactions) and of the
    /// miner packages that have not entered the tree yet.
    pub fn balance(&self, wallet: usize) -> u64 {
        let notes: u64 = self.wallets[wallet]
            .notes
            .iter()
            .map(|o| o.note.value)
            .sum();
        notes + self.pending_rewards(wallet).sum::<u64>()
    }

    /// Unspent packages a payment anchored at `height` can use: unlocked and
    /// not reserved by a pending transaction.
    pub fn spendable(&self, wallet: usize, height: Height) -> u64 {
        self.usable(wallet, height).map(|o| o.note.value).sum()
    }

    /// What becomes spendable after `height` without the wallet doing
    /// anything: the change of pending payments, the immature packages, and
    /// the miner packages that have not entered the tree yet.
    pub fn pending(&self, wallet: usize, height: Height) -> u64 {
        self.pending_values(wallet, height).sum()
    }

    /// Values of the wallet's miner packages that no scanned block has
    /// appended to the tree yet.
    fn pending_rewards(&self, wallet: usize) -> impl Iterator<Item = u64> + '_ {
        let scanned = self.height().unwrap_or(0);
        self.wallets[wallet]
            .rewards
            .iter()
            .filter(move |(_, paid)| paid + COINBASE_MATURITY > scanned)
            .map(|(note, _)| note.value)
    }

    fn usable(&self, wallet: usize, height: Height) -> impl Iterator<Item = &Owned> {
        let w = &self.wallets[wallet];
        w.notes
            .iter()
            .filter(move |o| o.note.cond.unlock_height <= height)
            .filter(move |o| {
                let nf = w.nf(&o.note);
                !w.reserved.contains(&nf) && !w.durable_reserved.contains(&nf)
            })
    }

    fn pending_values(&self, wallet: usize, height: Height) -> impl Iterator<Item = u64> + '_ {
        let w = &self.wallets[wallet];
        let immature = w
            .notes
            .iter()
            .filter(move |o| o.note.cond.unlock_height > height)
            .map(|o| o.note.value);
        w.change
            .iter()
            .filter(|(nf, _)| !w.durable_reserved.contains(nf))
            .map(|(_, value)| *value)
            .chain(w.durable_change.values().copied())
            .chain(immature)
            .chain(self.pending_rewards(wallet))
    }

    /// The error for a payment of `need` that the spendable packages at
    /// `height` cannot cover: whether it can wait for pending funds.
    fn shortfall(&self, wallet: usize, height: Height, need: u64) -> PayError {
        let values: Vec<u64> = self
            .usable(wallet, height)
            .map(|o| o.note.value)
            .chain(self.pending_values(wallet, height))
            .collect();
        if covers(&values, need) {
            PayError::FundsPending {
                pending: self.pending(wallet, height),
            }
        } else {
            PayError::InsufficientFunds
        }
    }

    /// Builds a payment anchored at the latest root of `state`, which must be
    /// the scanned chain's: at most two inputs, outputs [to recipient, change],
    /// each encrypted to its owner's address, proven with `system`, with the
    /// anti-spam nonce `pow` requires. On success the inputs are reserved.
    #[allow(clippy::too_many_arguments)]
    pub fn build_payment(
        &mut self,
        state: &ChainState,
        params: &ChainParams,
        pow: &TxPow,
        system: &dyn ProofSystem,
        from: usize,
        to: &Address,
        amount: u64,
        priority: bool,
    ) -> Result<PendingTx, PayError> {
        self.build_payment_with_rng(
            state,
            params,
            pow,
            system,
            from,
            to,
            amount,
            priority,
            || SecretSeed::from_os_rng().map_err(|_| PayError::Randomness),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_payment_with_rng(
        &mut self,
        state: &ChainState,
        params: &ChainParams,
        pow: &TxPow,
        system: &dyn ProofSystem,
        from: usize,
        to: &Address,
        amount: u64,
        priority: bool,
        rng: impl FnOnce() -> Result<SecretSeed, PayError>,
    ) -> Result<PendingTx, PayError> {
        let plan = self.prepare_payment(state, from, amount, priority)?;
        self.prove_payment_with_rng(state, params, pow, system, from, to, amount, &plan, rng)
    }

    pub(crate) fn prepare_payment(
        &self,
        state: &ChainState,
        from: usize,
        amount: u64,
        priority: bool,
    ) -> Result<PaymentPlan, PayError> {
        let wallet = self.wallets.get(from).ok_or(PayError::UnknownWallet)?;
        if wallet.keys.is_none() {
            return Err(PayError::Locked);
        }
        if amount < MIN_PACKAGE_DEPOSIT {
            return Err(PayError::AmountTooSmall);
        }
        let (anchor, anchor_height) = state
            .anchors
            .latest()
            .expect("anchor window is never empty");
        let e = epoch_of(anchor_height);
        let fee = if priority {
            fee_priority(e)
        } else {
            fee_base(e)
        };
        let need = amount.checked_add(fee).ok_or(PayError::InsufficientFunds)?;

        let mut spendable: Vec<Owned> = self.usable(from, anchor_height).copied().collect();
        spendable.sort_by_key(|o| (o.note.value, o.index));
        let inputs: Vec<Owned> = if let Some(one) = spendable.iter().find(|o| o.note.value >= need)
        {
            vec![*one]
        } else {
            let top: Vec<Owned> = spendable.iter().rev().take(2).copied().collect();
            let sum = top
                .iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.note.value));
            match sum {
                Some(s) if top.len() == 2 && s >= need => top,
                _ => return Err(self.shortfall(from, anchor_height, need)),
            }
        };
        let total = inputs
            .iter()
            .try_fold(0u64, |n, o| n.checked_add(o.note.value))
            .ok_or(PayError::InsufficientFunds)?;
        let change = total - need;
        if change != 0 && change < MIN_PACKAGE_DEPOSIT {
            return Err(PayError::ChangeTooSmall);
        }

        let nfs = inputs.iter().map(|o| wallet.nf(&o.note)).collect();
        Ok(PaymentPlan {
            inputs,
            nfs,
            anchor,
            anchor_height,
            fee,
            change,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_payment(
        &mut self,
        state: &ChainState,
        params: &ChainParams,
        pow: &TxPow,
        system: &dyn ProofSystem,
        to: &Address,
        amount: u64,
        plan: &PaymentPlan,
    ) -> Result<PendingTx, PayError> {
        self.prove_payment_with_rng(state, params, pow, system, 0, to, amount, plan, || {
            SecretSeed::from_os_rng().map_err(|_| PayError::Randomness)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_payment_with_rng(
        &mut self,
        state: &ChainState,
        params: &ChainParams,
        pow: &TxPow,
        system: &dyn ProofSystem,
        from: usize,
        to: &Address,
        amount: u64,
        plan: &PaymentPlan,
        rng: impl FnOnce() -> Result<SecretSeed, PayError>,
    ) -> Result<PendingTx, PayError> {
        let inputs = &plan.inputs;
        let (anchor, fee, change) = (plan.anchor, plan.fee, plan.change);
        if self.os_payment_entropy {
            self.randomness = rng()?;
            self.counter = 0;
        }
        let sk = self.wallets[from].key().clone();
        let real = |o: &Owned| -> InputWitness {
            InputWitness::Real {
                note: o.note,
                sk: sk.clone(),
                path: state
                    .commitments
                    .path(o.index)
                    .expect("owned note is in tree"),
            }
        };
        let first = real(&inputs[0]);
        let second = match inputs.get(1) {
            Some(o) => real(o),
            None => InputWitness::Dummy {
                nk: self.next_random("devnet dummy nk"),
                rho: self.next_random("devnet dummy rho"),
            },
        };
        let inputs_w = [first, second];
        let rho = output_rhos(&inputs_w);
        let out_to = self.new_note(to.owner(), amount, rho[0]);
        let out_change = self.new_note(sk.owner(), change, rho[1]);
        let outputs = [out_to, out_change];
        let randomness = [
            self.next_random("devnet encryption"),
            self.next_random("devnet encryption"),
        ];
        let (ct, tag) = encrypt_outputs(&outputs, [to, &self.wallets[from].address()], randomness);
        let blind = self.next_random("devnet fee blind");

        let witness = SlotWitness {
            anchor,
            inputs: inputs_w,
            outputs,
            ct,
            tag,
            fee,
        };
        let ctx = RelationContext {
            anchors: &state.anchors,
            tree_depth: params.commitment_tree_depth,
        };
        let (slot, proof, fee) = system
            .prove_slot(&ctx, &witness, blind)
            .map_err(PayError::Prove)?;
        let nonce = pow.solve(&proof.slot_id);
        let w = &mut self.wallets[from];
        for o in inputs {
            let nf = w.nf(&o.note);
            w.reserved.insert(nf);
        }
        if change != 0 {
            let first = w.nf(&inputs[0].note);
            w.change.insert(first, change);
        }
        Ok(PendingTx {
            slot,
            proof,
            fee,
            nonce,
        })
    }
}

pub(crate) fn journal_key_from_spend_key(
    key: &SpendKey,
    network: &Digest,
) -> zeroize::Zeroizing<[u8; 32]> {
    let mut hash = blake3::Hasher::new_derive_key("siworld encrypted payment journal key v1");
    hash.update(key.expose_secret());
    hash.update(network.as_bytes());
    zeroize::Zeroizing::new(*hash.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_circuits::MockProver;

    #[test]
    fn payment_entropy_failure_does_not_reserve_inputs_or_change_balance() {
        let params = ChainParams::devnet();
        let mut wallets = Wallets::from_keys(
            vec![("test".into(), SpendKey::from_digest(Digest([1; 32])))],
            SecretSeed::from_os_rng().unwrap(),
        );
        let cms = wallets.genesis_notes(&[(0, 100 * siworld_core::params::ATOMS_PER_SIP)]);
        let state = ChainState::genesis_with_commitments(&params, &cms);
        let pow = TxPow::for_params(&params);
        let to = SpendKey::from_digest(Digest([2; 32])).address();
        let before = wallets.balance(0);
        let prior = wallets.randomness.derive("probe", 0);
        let result = wallets.build_payment_with_rng(
            &state,
            &params,
            &pow,
            &MockProver,
            0,
            &to,
            siworld_core::params::ATOMS_PER_SIP,
            false,
            || Err(PayError::Randomness),
        );
        assert!(matches!(result, Err(PayError::Randomness)));
        assert_eq!(wallets.balance(0), before);
        assert_eq!(wallets.spendable(0, 0), before);
        assert!(wallets.wallets[0].reserved.is_empty());
        assert!(wallets.wallets[0].change.is_empty());
        assert_eq!(wallets.randomness.derive("probe", 0), prior);
        wallets
            .build_payment(
                &state,
                &params,
                &pow,
                &MockProver,
                0,
                &to,
                siworld_core::params::ATOMS_PER_SIP,
                false,
            )
            .unwrap();
        assert_ne!(wallets.randomness.derive("probe", 0), prior);
    }

    #[test]
    fn successive_wallet_draws_discard_previous_seed_state() {
        let seed = SecretSeed::from_os_rng().unwrap();
        let previous = seed.derive("draw", 1);
        let mut wallets = Wallets::from_keys(vec![], seed);
        assert_eq!(wallets.next_random("draw"), previous);
        assert_ne!(wallets.randomness.derive("draw", 1), previous);
    }
}
