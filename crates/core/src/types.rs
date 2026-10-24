//! On-chain and package data structures. Every on-chain structure is
//! fixed-length with a unique encoding.

use std::fmt;

use crate::params::{SIGNATURE_LEN, SLOT_INPUTS, SLOT_OUTPUTS};

pub type Height = u64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub const ZERO: Digest = Digest([0; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        f.write_str("…")
    }
}

fn blake3_digest(context: &str, data: &[u8]) -> Digest {
    let mut h = blake3::Hasher::new_derive_key(context);
    h.update(data);
    Digest(*h.finalize().as_bytes())
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Nullifier(pub Digest);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Commitment(pub Digest);

/// Package ciphertext length: a 1,088-byte ML-KEM-768 ciphertext, a 240-byte
/// ChaCha20-Poly1305 body, and its 16-byte tag (memo length is open, docs/security-model.md).
pub const CIPHERTEXT_LEN: usize = 1344;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ciphertext(pub [u8; CIPHERTEXT_LEN]);

/// Package conditions. Phase 1 has only `unlock_height`; 0 means unconditional.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Condition {
    pub unlock_height: Height,
}

/// Package plaintext, visible only to its holder. Assets and memos belong to
/// phase 2 and their lengths are open, so they are not modelled yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    pub owner: Digest,
    /// SI amount (atom): 0 (dummy package) or at least MIN_PACKAGE_DEPOSIT.
    pub value: u64,
    pub cond: Condition,
    pub rho: Digest,
    pub rseed: Digest,
}

/// One slot of a container: all public on-chain data of a 2-in / 2-out transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Slot {
    pub nf: [Nullifier; SLOT_INPUTS],
    pub cm: [Commitment; SLOT_OUTPUTS],
    pub ct: [Ciphertext; SLOT_OUTPUTS],
    pub tag: [u8; SLOT_OUTPUTS],
}

impl Slot {
    pub const ENCODED_LEN: usize = SLOT_INPUTS * 32 + SLOT_OUTPUTS * (32 + CIPHERTEXT_LEN + 1);

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        for nf in &self.nf {
            out.extend_from_slice(nf.0.as_bytes());
        }
        for cm in &self.cm {
            out.extend_from_slice(cm.0.as_bytes());
        }
        for ct in &self.ct {
            out.extend_from_slice(&ct.0);
        }
        out.extend_from_slice(&self.tag);
        out
    }

    /// Slot hash (excluding the proof). Slots in a block are in strictly ascending order of it.
    pub fn id(&self) -> Digest {
        blake3_digest("siworld v0 slot id", &self.encode())
    }

    /// d_ct: digest of every public slot field that does not enter the set element E directly
    /// (both ciphertexts and both view tags). Fixed length, so no framing is needed.
    pub fn ct_digest(&self) -> Digest {
        let mut data = Vec::with_capacity(SLOT_OUTPUTS * (CIPHERTEXT_LEN + 1));
        for ct in &self.ct {
            data.extend_from_slice(&ct.0);
        }
        data.extend_from_slice(&self.tag);
        blake3_digest("siworld d_ct v1", &data)
    }
}

/// Until a proof system is chosen, the container proof is opaque bytes. It is a
/// witness carried with the block; neither the header nor the body root commits
/// to it.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ContainerProof(pub Vec<u8>);

/// Coinbase: the three public amounts of the 90/5/5 split, the hash of the
/// miner's pre-confirmation key, and the miner package (docs/protocol.md, Economics).
///
/// The miner package holds the miner's reward share plus the block's fees,
/// encrypted to the miner. Its commitment is not appended to the commitment
/// tree by this block: it waits in the pending-reward queue and is appended by
/// the block `COINBASE_MATURITY` blocks later, so that slashing can still burn
/// it until then. The miner's address never appears on chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Coinbase {
    /// BLAKE3 hash of the miner's pre-confirmation public key. Not a field
    /// element, and not derived from the miner's address.
    pub committee_key: Digest,
    pub miner_amount: u64,
    pub dev_direct_amount: u64,
    pub dev_lock_amount: u64,
    /// Miner package: `miner_amount` plus the block's fees. The fee part is
    /// not public.
    pub miner_note_cm: Commitment,
    pub miner_note_ct: Ciphertext,
    pub miner_note_tag: u8,
}

impl Coinbase {
    pub fn total(&self) -> Option<u64> {
        self.miner_amount
            .checked_add(self.dev_direct_amount)?
            .checked_add(self.dev_lock_amount)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.committee_key.as_bytes());
        out.extend_from_slice(&self.miner_amount.to_le_bytes());
        out.extend_from_slice(&self.dev_direct_amount.to_le_bytes());
        out.extend_from_slice(&self.dev_lock_amount.to_le_bytes());
        out.extend_from_slice(self.miner_note_cm.0.as_bytes());
        out.extend_from_slice(&self.miner_note_ct.0);
        out.push(self.miner_note_tag);
        out
    }
}

/// The two development-fund accounts (docs/protocol.md, Economics).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DevAccount {
    /// Credited ⌊reward/20⌋ per block, spendable after COINBASE_MATURITY.
    Direct,
    /// Deposited ⌊reward/20⌋ per block, released linearly over DEV_LOCK_SECONDS.
    Lock,
}

impl DevAccount {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Direct),
            1 => Some(Self::Lock),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::Direct => 0,
            Self::Lock => 1,
        }
    }
}

/// An ML-DSA-65 signature as it appears in a block.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PayoutSignature(pub [u8; SIGNATURE_LEN]);

impl fmt::Debug for PayoutSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PayoutSignature({:?})",
            blake3_digest("siworld debug", &self.0)
        )
    }
}

/// A development-fund payout (docs/protocol.md, Economics): a public entry of a block
/// body that moves `amount` from one fund account into a shielded package
/// whose plaintext is public: `owner`, `amount`, `rseed`, no condition, and
/// a ρ derived from the block height and the payout's index in the block
/// (so it is not part of the entry, and the entry carries no ciphertext).
/// The recipient's wallet recognises the package by its owner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Payout {
    pub account: DevAccount,
    /// The account's payout count before this one: replay protection.
    pub counter: u64,
    pub amount: u64,
    /// The recipient package's owner and commitment randomness.
    pub owner: Digest,
    pub rseed: Digest,
    /// The account key's signature over [`Self::signed_bytes`].
    pub signature: PayoutSignature,
}

impl Payout {
    pub const ENCODED_LEN: usize = 1 + 8 + 8 + 32 + 32 + SIGNATURE_LEN;

    /// What the account key signs: the chain id (`ChainParams::chain_id`), so
    /// that the signature is valid on one network only, then every field but
    /// the signature.
    pub fn signed_bytes(&self, chain_id: &Digest) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + Self::ENCODED_LEN - SIGNATURE_LEN);
        out.extend_from_slice(chain_id.as_bytes());
        out.push(self.account.to_byte());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(self.rseed.as_bytes());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.push(self.account.to_byte());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(self.rseed.as_bytes());
        out.extend_from_slice(&self.signature.0);
        out
    }
}

/// Block body: coinbase, payouts and slots. The container proof is not part
/// of it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockBody {
    pub coinbase: Coinbase,
    pub payouts: Vec<Payout>,
    pub slots: Vec<Slot>,
}

impl BlockBody {
    /// Body hash committed to by the header, preventing body substitution.
    pub fn hash(&self) -> Digest {
        let mut data = self.coinbase.encode();
        data.extend_from_slice(&(self.payouts.len() as u64).to_le_bytes());
        for payout in &self.payouts {
            data.extend_from_slice(&payout.encode());
        }
        data.extend_from_slice(&(self.slots.len() as u64).to_le_bytes());
        for slot in &self.slots {
            data.extend_from_slice(slot.id().as_bytes());
        }
        blake3_digest("siworld v0 block body", &data)
    }

    /// The slots' output packages as (commitment, view tag, ciphertext), in
    /// the order the state transition appends them to the commitment tree:
    /// each slot's two outputs. The block then appends the miner package that
    /// matured from `COINBASE_MATURITY` blocks earlier (or the zero digest),
    /// which is not an output of this body, and then its payouts' packages
    /// (public plaintexts, no ciphertext); see [`Self::miner_package`] for
    /// the package this body pays.
    pub fn outputs(&self) -> impl Iterator<Item = (&Commitment, u8, &Ciphertext)> {
        self.slots.iter().flat_map(|s| {
            s.cm.iter()
                .zip(s.tag)
                .zip(&s.ct)
                .map(|((cm, tag), ct)| (cm, tag, ct))
        })
    }

    /// This block's miner package as (commitment, view tag, ciphertext). Its
    /// commitment enters the tree `COINBASE_MATURITY` blocks later.
    pub fn miner_package(&self) -> (&Commitment, u8, &Ciphertext) {
        let c = &self.coinbase;
        (&c.miner_note_cm, c.miner_note_tag, &c.miner_note_ct)
    }
}

/// Roots after a state transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Roots {
    pub commitment_root: Digest,
    pub nullifier_root: Digest,
    pub anchors_root: Digest,
    pub state_root: Digest,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: u32,
    pub height: Height,
    pub parent: Digest,
    /// Seconds since the Unix epoch. Feeds only difficulty adjustment; package
    /// conditions use height.
    pub timestamp: u64,
    /// PoW target, big-endian: the work must be below it. Fixed by ASERT.
    pub target: [u8; 32],
    pub nonce: u64,
    pub state_root: Digest,
    pub commitment_root: Digest,
    pub nullifier_root: Digest,
    pub body_root: Digest,
    pub container_size: u32,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_without_nonce();
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    fn encode_without_nonce(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(self.parent.as_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.target);
        out.extend_from_slice(self.state_root.as_bytes());
        out.extend_from_slice(self.commitment_root.as_bytes());
        out.extend_from_slice(self.nullifier_root.as_bytes());
        out.extend_from_slice(self.body_root.as_bytes());
        out.extend_from_slice(&self.container_size.to_le_bytes());
        out
    }

    pub fn hash(&self) -> Digest {
        blake3_digest("siworld v0 header", &self.encode())
    }

    /// Seed of the sequential PoW: every header field except the nonce.
    pub fn pow_seed(&self) -> Digest {
        blake3_digest("siworld v0 pow seed", &self.encode_without_nonce())
    }
}

/// A block as relayed: the PoW header, the body it commits to, and the container
/// proof Π. Any valid Π for the same header and body is as good as another.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: Header,
    pub body: BlockBody,
    pub proof: ContainerProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(fill: u8) -> Slot {
        Slot {
            nf: [Nullifier(Digest([fill; 32])); SLOT_INPUTS],
            cm: [Commitment(Digest([fill; 32])); SLOT_OUTPUTS],
            ct: [Ciphertext([fill; CIPHERTEXT_LEN]); SLOT_OUTPUTS],
            tag: [fill; SLOT_OUTPUTS],
        }
    }

    fn body() -> BlockBody {
        let mut slots = vec![slot(1), slot(2)];
        for (i, s) in slots.iter_mut().enumerate() {
            for j in 0..SLOT_OUTPUTS {
                s.cm[j] = Commitment(Digest([(10 * i + j) as u8; 32]));
                s.tag[j] = (10 * i + j) as u8;
            }
        }
        BlockBody {
            coinbase: Coinbase {
                committee_key: Digest([7; 32]),
                miner_amount: 1,
                dev_direct_amount: 2,
                dev_lock_amount: 3,
                miner_note_cm: Commitment(Digest([99; 32])),
                miner_note_ct: Ciphertext([9; CIPHERTEXT_LEN]),
                miner_note_tag: 99,
            },
            payouts: vec![payout(5)],
            slots,
        }
    }

    fn payout(fill: u8) -> Payout {
        Payout {
            account: DevAccount::Lock,
            counter: 3,
            amount: 4,
            owner: Digest([fill; 32]),
            rseed: Digest([fill + 1; 32]),
            signature: PayoutSignature([fill + 4; SIGNATURE_LEN]),
        }
    }

    #[test]
    fn body_outputs_list_slot_outputs_only() {
        let b = body();
        let got: Vec<(u8, u8)> = b.outputs().map(|(cm, tag, _)| (cm.0 .0[0], tag)).collect();
        assert_eq!(got, [(0, 0), (1, 1), (10, 10), (11, 11)]);
        let (cm, tag, _) = b.miner_package();
        assert_eq!((cm.0 .0[0], tag), (99, 99));
    }

    #[test]
    fn body_hash_binds_miner_package_ciphertext_tag_and_committee_key() {
        let b = body();
        let mut t = b.clone();
        t.coinbase.miner_note_tag ^= 1;
        assert_ne!(t.hash(), b.hash());
        let mut c = b.clone();
        c.coinbase.miner_note_ct.0[CIPHERTEXT_LEN - 1] ^= 1;
        assert_ne!(c.hash(), b.hash());
        let mut k = b.clone();
        k.coinbase.committee_key.0[0] ^= 1;
        assert_ne!(k.hash(), b.hash());
    }

    #[test]
    fn body_hash_binds_every_payout_field_and_their_number() {
        let b = body();
        let mut none = b.clone();
        none.payouts.clear();
        assert_ne!(none.hash(), b.hash());
        let mut two = b.clone();
        two.payouts.push(payout(5));
        assert_ne!(two.hash(), b.hash());
        let edits: [fn(&mut Payout); 6] = [
            |p| p.account = DevAccount::Direct,
            |p| p.counter ^= 1,
            |p| p.amount ^= 1,
            |p| p.owner.0[0] ^= 1,
            |p| p.rseed.0[31] ^= 1,
            |p| p.signature.0[SIGNATURE_LEN - 1] ^= 1,
        ];
        for edit in edits {
            let mut e = b.clone();
            edit(&mut e.payouts[0]);
            assert_ne!(e.hash(), b.hash());
        }
    }

    #[test]
    fn payout_encoding_is_fixed_length_and_the_signature_covers_the_rest() {
        let p = payout(1);
        let chain = Digest([0xc0; 32]);
        assert_eq!(p.encode().len(), Payout::ENCODED_LEN);
        assert_eq!(
            p.signed_bytes(&chain).len(),
            32 + Payout::ENCODED_LEN - SIGNATURE_LEN
        );
        assert_eq!(&p.signed_bytes(&chain)[..32], chain.as_bytes());
        assert_eq!(
            &p.encode()[..Payout::ENCODED_LEN - SIGNATURE_LEN],
            &p.signed_bytes(&chain)[32..]
        );
        assert_ne!(p.signed_bytes(&chain), p.signed_bytes(&Digest([0xc1; 32])));
        assert_eq!(DevAccount::from_byte(0), Some(DevAccount::Direct));
        assert_eq!(DevAccount::from_byte(1), Some(DevAccount::Lock));
        assert_eq!(DevAccount::from_byte(2), None);
    }

    #[test]
    fn slot_encoding_is_fixed_length() {
        assert_eq!(slot(0).encode().len(), Slot::ENCODED_LEN);
        assert_eq!(slot(0xff).encode().len(), Slot::ENCODED_LEN);
    }

    #[test]
    fn slot_id_depends_on_every_field() {
        let base = slot(1);
        let mut a = base;
        a.nf[1] = Nullifier(Digest([2; 32]));
        let mut b = base;
        b.ct[1].0[CIPHERTEXT_LEN - 1] ^= 1;
        let mut c = base;
        c.tag[1] = 9;
        for changed in [a, b, c] {
            assert_ne!(changed.id(), base.id());
        }
    }

    fn header() -> Header {
        Header {
            version: 0,
            height: 1,
            parent: Digest([1; 32]),
            timestamp: 2,
            target: [3; 32],
            nonce: 4,
            state_root: Digest([5; 32]),
            commitment_root: Digest([6; 32]),
            nullifier_root: Digest([7; 32]),
            body_root: Digest([8; 32]),
            container_size: 9,
        }
    }

    /// The PoW seed binds every header field except the nonce, so a nonce cannot
    /// be moved to another header and the search space is the nonce alone.
    #[test]
    fn pow_seed_binds_everything_but_nonce() {
        let base = header();
        let mut nonce = base;
        nonce.nonce ^= 1;
        assert_eq!(nonce.pow_seed(), base.pow_seed());
        assert_ne!(nonce.hash(), base.hash());

        let mut changed = Vec::new();
        let edits: [fn(&mut Header); 10] = [
            |h| h.version ^= 1,
            |h| h.height ^= 1,
            |h| h.parent.0[31] ^= 1,
            |h| h.timestamp ^= 1,
            |h| h.target[31] ^= 1,
            |h| h.state_root.0[0] ^= 1,
            |h| h.commitment_root.0[0] ^= 1,
            |h| h.nullifier_root.0[0] ^= 1,
            |h| h.body_root.0[0] ^= 1,
            |h| h.container_size ^= 1,
        ];
        for edit in edits {
            let mut h = base;
            edit(&mut h);
            changed.push(h.pow_seed());
        }
        changed.push(base.pow_seed());
        changed.sort();
        changed.dedup();
        assert_eq!(changed.len(), 11);
    }

    /// E binds nf and cm directly and everything else through d_ct, so d_ct must cover every
    /// remaining public byte, view tags included; otherwise a miner could rewrite a tag without
    /// invalidating the proof (docs/cryptography.md).
    #[test]
    fn ct_digest_binds_ciphertexts_and_view_tags() {
        let base = slot(1);
        let mut changed = Vec::new();
        for j in 0..SLOT_OUTPUTS {
            for i in [0, CIPHERTEXT_LEN - 1] {
                let mut s = base;
                s.ct[j].0[i] ^= 1;
                changed.push(s);
            }
            let mut s = base;
            s.tag[j] ^= 1;
            changed.push(s);
        }
        let mut seen = vec![base.ct_digest()];
        for s in changed {
            let d = s.ct_digest();
            assert!(!seen.contains(&d));
            seen.push(d);
        }
        // Swapping the two outputs' ciphertexts or tags is a different slot.
        let mut s = slot(1);
        s.ct[0].0[0] = 7;
        s.tag[0] = 7;
        let mut swapped = s;
        swapped.ct.swap(0, 1);
        assert_ne!(swapped.ct_digest(), s.ct_digest());
        let mut swapped = s;
        swapped.tag.swap(0, 1);
        assert_ne!(swapped.ct_digest(), s.ct_digest());
        // nf and cm enter E directly, not through d_ct.
        let mut s = base;
        s.nf[0] = Nullifier(Digest([2; 32]));
        s.cm[1] = Commitment(Digest([2; 32]));
        assert_eq!(s.ct_digest(), base.ct_digest());
    }
}
