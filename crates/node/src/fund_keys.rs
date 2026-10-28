//! Encrypted fund custody and explicit, durably recorded authorization. Local format;
//! account keys, payout signatures and consensus are unchanged.
use crate::devfund::DevFundSigner;
use crate::keystore::{atomic_write_bytes, derived_key, WalletFileLock};
use crate::secrets::{read_private_bytes, read_secret};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use siworld_core::{DevAccount, Digest};
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};
const MAGIC: &[u8; 8] = b"SIFUND01";
const AAD: &[u8] = b"siworld development fund seed v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";

#[derive(Clone)]
pub struct FundKeystore([u8; 96]);
impl core::fmt::Debug for FundKeystore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FundKeystore(REDACTED)")
    }
}
impl FundKeystore {
    pub fn seal(seed: &Digest, password: &str) -> Result<Self, String> {
        if !(12..=1024).contains(&password.len()) {
            return Err("new fund passwords require 12 to 1024 UTF-8 bytes".into());
        }
        let mut out = [0u8; 96];
        out[..8].copy_from_slice(MAGIC);
        getrandom::fill(&mut out[8..48]).map_err(|_| "OS randomness unavailable")?;
        let k = derived_key(password, &out[8..24])?;
        let mut plain = Zeroizing::new(seed.0);
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&out[..48]);
        let tag = XChaCha20Poly1305::new(<&Key>::try_from(k.as_ref()).expect("key length"))
            .encrypt_inout_detached(
                <&XNonce>::try_from(&out[24..48]).expect("nonce length"),
                &aad,
                plain.as_mut_slice().into(),
            )
            .map_err(|_| "cannot encrypt fund key")?;
        out[48..80].copy_from_slice(plain.as_ref());
        out[80..].copy_from_slice(&tag);
        let store = Self(out);
        if store.seed(password)?.as_ref() != seed.as_bytes() {
            return Err("fund encryption read-back mismatch".into());
        }
        Ok(store)
    }
    fn seed(&self, password: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        let k = derived_key(password, &self.0[8..24])?;
        let mut plain = Zeroizing::new([0u8; 32]);
        plain.copy_from_slice(&self.0[48..80]);
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&self.0[..48]);
        XChaCha20Poly1305::new(<&Key>::try_from(k.as_ref()).expect("key length"))
            .decrypt_inout_detached(
                <&XNonce>::try_from(&self.0[24..48]).expect("nonce length"),
                &aad,
                plain.as_mut_slice().into(),
                &Tag::try_from(&self.0[80..]).expect("tag length"),
            )
            .map_err(|_| "incorrect fund password or damaged keystore")?;
        Ok(plain)
    }
    pub fn open(&self, password: &str) -> Result<DevFundSigner, String> {
        let plain = self.seed(password)?;
        let mut seed = Digest(*plain);
        let signer = DevFundSigner::from_seed(&seed);
        seed.0.zeroize();
        Ok(signer)
    }
    pub(crate) fn journal_key(
        &self,
        password: &str,
        genesis: &Digest,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let seed = self.seed(password)?;
        let mut material = Zeroizing::new(Vec::new());
        material.extend_from_slice(seed.as_ref());
        material.extend_from_slice(genesis.as_bytes());
        Ok(Zeroizing::new(blake3::derive_key(
            "siworld fund payout journal key v1",
            &material,
        )))
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn decode(b: &[u8]) -> Result<Self, String> {
        if b.len() != 96 || &b[..8] != MAGIC {
            return Err("encrypted fund keystore required; migrate legacy seeds offline".into());
        }
        Ok(Self(b.try_into().expect("checked length")))
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::decode(&read_private_bytes(path, 96)?)
    }
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        atomic_write_bytes(path, &self.0, false, || Ok(()))
    }
    pub(crate) fn rewrap(&self, password: &str, new_password: &str) -> Result<Self, String> {
        let plain = self.seed(password)?;
        let mut d = Digest(*plain);
        let result = Self::seal(&d, new_password);
        d.0.zeroize();
        result
    }
}
/// A dedicated owner-only fund directory is the offline/live ownership domain.
/// Keep it separate from the node data directory and never delete its lock.
pub fn lock_file(path: &Path) -> Result<WalletFileLock, String> {
    WalletFileLock::acquire(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
}
pub fn generate_file(path: &Path, password: &str) -> Result<FundKeystore, String> {
    let _lock = lock_file(path)?;
    let mut random = Zeroizing::new([0; 32]);
    getrandom::fill(random.as_mut()).map_err(|_| "OS randomness unavailable")?;
    let mut seed = Digest(*random);
    let store = FundKeystore::seal(&seed, password);
    seed.0.zeroize();
    let store = store?;
    store.save_new(path)?;
    Ok(store)
}
pub fn migrate_file(path: &Path, password: &str) -> Result<(), String> {
    let _lock = lock_file(path)?;
    let raw = read_secret(path)?;
    let mut seed = crate::parse_hex32(raw.trim()).ok_or("not a legacy fund seed")?;
    let store = FundKeystore::seal(&seed, password);
    seed.0.zeroize();
    atomic_write_bytes(path, &store?.0, true, || Ok(()))
}
pub fn rotate_file(path: &Path, password: &str, new_password: &str) -> Result<(), String> {
    let _lock = lock_file(path)?;
    let store = FundKeystore::load(path)?.rewrap(password, new_password)?;
    atomic_write_bytes(path, &store.0, true, || Ok(()))
}
/// Authenticated, freshly encrypted backup or restore to an unused file.
pub fn copy_file(source: &Path, output: &Path, password: &str) -> Result<(), String> {
    let _lock = lock_file(source)?;
    FundKeystore::load(source)?
        .rewrap(password, password)?
        .save_new(output)
}

/// Immutable local cumulative policy. Amounts include retained legacy intents.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundBudget {
    pub version: u32,
    pub id: String,
    #[serde(rename = "direct_si")]
    pub direct_sip: String,
    #[serde(rename = "lock_si")]
    pub lock_sip: String,
    #[serde(rename = "total_si")]
    pub total_sip: String,
    #[serde(rename = "max_payout_si")]
    pub max_payout_sip: String,
}
pub(crate) struct BudgetLimits {
    pub accounts: [u64; 2],
    pub total: u64,
    pub max: u64,
}
impl FundBudget {
    pub(crate) fn validate(&self) -> Result<BudgetLimits, String> {
        let amount = |s: &str| crate::amount::parse_sip(s).ok_or("invalid cumulative SIP budget");
        let accounts = [amount(&self.direct_sip)?, amount(&self.lock_sip)?];
        let total = amount(&self.total_sip)?;
        let max = amount(&self.max_payout_sip)?;
        if self.version != 1
            || !canonical_id(&self.id)
            || accounts == [0, 0]
            || total == 0
            || max == 0
        {
            return Err("invalid cumulative fund budget".into());
        }
        Ok(BudgetLimits {
            accounts,
            total,
            max,
        })
    }
}
fn canonical_id(s: &str) -> bool {
    crate::payments::PaymentId::parse(s).is_ok_and(|id| id.to_string() == s)
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundGrant {
    pub version: u32,
    pub genesis: String,
    pub approval_id: String,
    pub budget: FundBudget,
    pub seconds: u64,
    #[serde(rename = "direct_si")]
    pub direct_sip: String,
    #[serde(rename = "lock_si")]
    pub lock_sip: String,
    #[serde(rename = "max_payout_si")]
    pub max_payout_sip: String,
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<crate::fund_approval::GrantApproval>,
}
impl FundGrant {
    pub fn read(path: &Path) -> Result<Self, String> {
        serde_json::from_slice(&read_private_bytes(path, 32 << 10)?)
            .map_err(|_| "invalid fund authorization file".into())
    }
    pub(crate) fn validate(&self, genesis: &Digest) -> Result<Authorization, String> {
        let amount =
            |s: &str| crate::amount::parse_sip(s).ok_or("invalid SIP authorization amount");
        let remaining = [amount(&self.direct_sip)?, amount(&self.lock_sip)?];
        let max = amount(&self.max_payout_sip)?;
        let budget = self.budget.validate()?;
        if !matches!(
            (self.version, self.approval.is_some()),
            (2, false) | (3, true)
        ) || !canonical_id(&self.approval_id)
            || self.genesis != crate::hex(genesis)
            || !(1..=3600).contains(&self.seconds)
            || max == 0
            || max > budget.max
            || remaining == [0, 0]
            || self.recipients.is_empty()
            || self.recipients.len() > 32
        {
            return Err("invalid fund authorization bounds or genesis".into());
        }
        let mut owners = Vec::new();
        for s in &self.recipients {
            let owner = crate::address::parse_address(s)
                .ok_or("invalid fund recipient address")?
                .owner();
            if owners.contains(&owner) {
                return Err("duplicate fund recipient owner".into());
            }
            owners.push(owner);
        }
        Ok(Authorization {
            id: self.approval_id.clone(),
            remaining,
            max,
            owners,
            deadline: Instant::now() + Duration::from_secs(self.seconds),
        })
    }
}
pub(crate) struct Authorization {
    pub(crate) id: String,
    pub(crate) remaining: [u64; 2],
    pub(crate) max: u64,
    owners: Vec<Digest>,
    pub(crate) deadline: Instant,
}
impl Authorization {
    pub(crate) fn allows(&self, account: DevAccount, owner: &Digest, amount: u64) -> bool {
        Instant::now() < self.deadline && self.permits(account, owner, amount)
    }
    pub(crate) fn permits(&self, account: DevAccount, owner: &Digest, amount: u64) -> bool {
        amount <= self.max
            && amount <= self.remaining[account.to_byte() as usize]
            && self.owners.contains(owner)
    }
    pub(crate) fn charge(&mut self, account: DevAccount, amount: u64) {
        self.remaining[account.to_byte() as usize] -= amount;
    }
}
pub struct FundStatus {
    pub configured: bool,
    pub locked: bool,
    pub direct_remaining: u64,
    pub lock_remaining: u64,
    pub max_payout: u64,
}

#[cfg(test)]
mod denomination_compatibility_tests {
    use super::{FundBudget, FundGrant};

    #[test]
    fn fund_policy_keeps_signed_serialization_bytes() {
        let original = br#"{"version":1,"id":"1111111111111111111111111111111111111111111111111111111111111111","direct_si":"1.25","lock_si":"2.5","total_si":"3.75","max_payout_si":"0.5"}"#;
        let policy: FundBudget = serde_json::from_slice(original).unwrap();
        assert_eq!(serde_json::to_vec(&policy).unwrap().as_slice(), original);
        assert_eq!(
            crate::fund_approval::policy_hash(&policy),
            crate::fund_approval::hash("siworld cumulative fund policy v1", original)
        );
        let incompatible = std::str::from_utf8(original)
            .unwrap()
            .replace("direct_si", "direct_sip");
        assert!(serde_json::from_str::<FundBudget>(&incompatible).is_err());
    }

    #[test]
    fn fund_grant_keeps_signed_serialization_bytes() {
        let original = br#"{"version":2,"genesis":"2222222222222222222222222222222222222222222222222222222222222222","approval_id":"3333333333333333333333333333333333333333333333333333333333333333","budget":{"version":1,"id":"1111111111111111111111111111111111111111111111111111111111111111","direct_si":"1.25","lock_si":"2.5","total_si":"3.75","max_payout_si":"0.5"},"seconds":60,"direct_si":"1","lock_si":"2","max_payout_si":"0.25","recipients":[]}"#;
        let grant: FundGrant = serde_json::from_slice(original).unwrap();
        assert_eq!(serde_json::to_vec(&grant).unwrap().as_slice(), original);
        let incompatible = std::str::from_utf8(original)
            .unwrap()
            .replace("max_payout_si", "max_payout_sip");
        assert!(serde_json::from_str::<FundGrant>(&incompatible).is_err());
    }
}
