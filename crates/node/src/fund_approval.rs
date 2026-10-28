//! Independent, offline ML-DSA approval documents. Local custody, not consensus.
use crate::keystore::{atomic_write_bytes, derived_key};
use crate::secrets::read_private_bytes;
use crate::{
    fund_keys::{FundBudget, FundGrant},
    hex, parse_hex, parse_hex32,
};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use siworld_core::{
    params::{SIGNATURE_LEN, VERIFYING_KEY_LEN},
    Digest,
};
use siworld_crypto::{Signature, SigningKey, VerifyingKey};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};
const MAGIC: &[u8; 8] = b"SIFAPP01";
const AAD: &[u8] =
    b"siworld independent fund approver seed v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";
const GRANT_DOMAIN: &[u8] = b"siworld independent fund grant approval v1\0";
const CHANGE_DOMAIN: &[u8] = b"siworld independent fund policy change v1\0";
pub fn id(value: &str) -> bool {
    parse_hex32(value).is_some() && value.to_lowercase() == value
}
pub fn hash(context: &str, bytes: &[u8]) -> String {
    hex(&Digest(blake3::derive_key(context, bytes)))
}
pub fn policy_hash(policy: &FundBudget) -> String {
    hash(
        "siworld cumulative fund policy v1",
        &serde_json::to_vec(policy).expect("policy serialization"),
    )
}
pub fn key_id(key: &VerifyingKey) -> String {
    hash("siworld independent fund approver id v1", &key.0)
}
fn message(domain: &[u8], body: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(body).map_err(|_| "cannot encode approval statement")?);
    Ok(bytes)
}
fn verify(
    key: &VerifyingKey,
    domain: &[u8],
    body: &impl Serialize,
    signature: &str,
) -> Result<(), String> {
    let bytes = parse_hex::<SIGNATURE_LEN>(signature)
        .filter(|_| signature.to_lowercase() == signature)
        .ok_or("invalid approval signature encoding")?;
    if !key.verify(&message(domain, body)?, &Signature(bytes)) {
        return Err("independent fund approval signature invalid".into());
    }
    Ok(())
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&read_private_bytes(path, 32 << 10)?)
        .map_err(|_| "invalid approval document".into())
}
pub fn save_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    atomic_write_bytes(
        path,
        &serde_json::to_vec(value).map_err(|_| "cannot encode approval document")?,
        false,
        || Ok(()),
    )
}
pub fn read_key(path: &Path) -> Result<VerifyingKey, String> {
    let bytes = read_private_bytes(path, 2 * VERIFYING_KEY_LEN)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| "invalid approval public key")?;
    parse_hex(s)
        .filter(|_| s.to_lowercase() == s)
        .map(VerifyingKey)
        .ok_or_else(|| "invalid approval public key".into())
}
pub fn save_key(path: &Path, key: &VerifyingKey) -> Result<(), String> {
    atomic_write_bytes(
        path,
        crate::genesis::hex_bytes(&key.0).as_bytes(),
        false,
        || Ok(()),
    )
}
/// The approver's private key never belongs in the node or its fund backup.
pub struct ApprovalSigner(SigningKey);
impl ApprovalSigner {
    fn from_seed(seed: &[u8]) -> Self {
        let mut d = Digest(blake3::derive_key(
            "siworld independent fund approver ML-DSA-65 key v1",
            seed,
        ));
        let signer = Self(SigningKey::generate(&d));
        d.0.zeroize();
        signer
    }
    fn seed(path: &Path, password: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let b = read_private_bytes(path, 96)?;
        if b.len() != 96 || &b[..8] != MAGIC {
            return Err("independent encrypted approval key required".into());
        }
        let k = derived_key(password, &b[8..24])?;
        let mut plain = Zeroizing::new(b[48..80].to_vec());
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&b[..48]);
        XChaCha20Poly1305::new(<&Key>::try_from(k.as_ref()).expect("key length"))
            .decrypt_inout_detached(
                <&XNonce>::try_from(&b[24..48]).expect("nonce"),
                &aad,
                plain.as_mut_slice().into(),
                &Tag::try_from(&b[80..]).expect("tag"),
            )
            .map_err(|_| "incorrect approval key password or damaged key")?;
        Ok(plain)
    }
    fn seal(seed: &[u8], password: &str) -> Result<[u8; 96], String> {
        if !(12..=1024).contains(&password.len()) {
            return Err("approval passwords require 12 to 1024 UTF-8 bytes".into());
        }
        let mut b = [0u8; 96];
        b[..8].copy_from_slice(MAGIC);
        getrandom::fill(&mut b[8..48]).map_err(|_| "OS randomness unavailable")?;
        let k = derived_key(password, &b[8..24])?;
        let mut plain = Zeroizing::new(seed.to_vec());
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&b[..48]);
        let tag = XChaCha20Poly1305::new(<&Key>::try_from(k.as_ref()).expect("key length"))
            .encrypt_inout_detached(
                <&XNonce>::try_from(&b[24..48]).expect("nonce"),
                &aad,
                plain.as_mut_slice().into(),
            )
            .map_err(|_| "cannot encrypt approval key")?;
        b[48..80].copy_from_slice(&plain);
        b[80..].copy_from_slice(&tag);
        Ok(b)
    }
    pub fn generate_file(path: &Path, password: &str) -> Result<Self, String> {
        let _lock = crate::fund_keys::lock_file(path)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| "OS randomness unavailable")?;
        let b = Self::seal(seed.as_ref(), password)?;
        atomic_write_bytes(path, &b, false, || Ok(()))?;
        Self::load(path, password)
    }
    pub fn load(path: &Path, password: &str) -> Result<Self, String> {
        Ok(Self::from_seed(&Self::seed(path, password)?))
    }
    pub fn copy_file(
        path: &Path,
        output: &Path,
        password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        let _lock = crate::fund_keys::lock_file(path)?;
        let plain = Self::seed(path, password)?;
        let b = Self::seal(&plain, new_password)?;
        atomic_write_bytes(output, &b, false, || Ok(()))
    }
    pub fn rotate_file(path: &Path, password: &str, new_password: &str) -> Result<(), String> {
        let _lock = crate::fund_keys::lock_file(path)?;
        let plain = Self::seed(path, password)?;
        let b = Self::seal(&plain, new_password)?;
        atomic_write_bytes(path, &b, true, || Ok(()))
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    pub fn save_public(path: &Path, key: &VerifyingKey) -> Result<(), String> {
        save_key(path, key)
    }
    fn sign(&self, domain: &[u8], body: &impl Serialize) -> Result<String, String> {
        let mut hedge = Digest([0; 32]);
        getrandom::fill(&mut hedge.0).map_err(|_| "OS randomness unavailable")?;
        let sig = self.0.sign(&message(domain, body)?, &hedge);
        hedge.0.zeroize();
        Ok(crate::genesis::hex_bytes(&sig.0))
    }
    pub fn approve_change(&self, request: &ChangeRequest) -> Result<SignedChange, String> {
        request.validate()?;
        if request.key_id != key_id(&self.verifying_key()) {
            return Err("approval signer identity mismatch".into());
        }
        Ok(SignedChange {
            request: request.clone(),
            signature: self.sign(CHANGE_DOMAIN, request)?,
        })
    }
    pub fn approve_grant(
        &self,
        grant: &FundGrant,
        context: &SigningContext,
    ) -> Result<FundGrant, String> {
        context.validate()?;
        if context.key_id != key_id(&self.verifying_key())
            || policy_hash(&grant.budget) != context.policy_hash
        {
            return Err("approval policy or signer mismatch".into());
        }
        let mut out = grant.clone();
        out.version = 2;
        out.approval = None;
        out.validate(&crate::parse_hex32(&context.genesis).ok_or("invalid genesis")?)?;
        out.version = 3;
        let signature = self.sign(GRANT_DOMAIN, &(context, &out))?;
        out.approval = Some(GrantApproval {
            context: context.clone(),
            signature,
        });
        Ok(out)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningContext {
    pub version: u32,
    pub genesis: String,
    pub fund_id: String,
    pub key_id: String,
    pub revision: u64,
    pub policy_hash: String,
    pub revision_hash: String,
}
impl SigningContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || [
                &self.genesis,
                &self.fund_id,
                &self.key_id,
                &self.policy_hash,
                &self.revision_hash,
            ]
            .iter()
            .any(|s| !id(s))
        {
            return Err("invalid approval signing context".into());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantApproval {
    pub context: SigningContext,
    pub signature: String,
}
impl GrantApproval {
    pub fn verify(
        &self,
        grant: &FundGrant,
        key: &VerifyingKey,
        expected: &SigningContext,
    ) -> Result<(), String> {
        if &self.context != expected || grant.version != 3 {
            return Err("stale or mismatched approval context".into());
        }
        let mut unsigned = grant.clone();
        unsigned.approval = None;
        verify(
            key,
            GRANT_DOMAIN,
            &(&self.context, unsigned),
            &self.signature,
        )
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRequest {
    pub version: u32,
    pub genesis: String,
    pub fund_id: String,
    pub key_id: String,
    pub change_id: String,
    pub revision: u64,
    pub previous_revision: Option<String>,
    pub previous_policy: Option<String>,
    pub expected_sequence: u64,
    pub expected_state: String,
    pub reserved_atoms: [u64; 2],
    pub policy: FundBudget,
    pub reason: String,
}
impl ChangeRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.policy.validate()?;
        if self.version != 1
            || [
                &self.genesis,
                &self.fund_id,
                &self.key_id,
                &self.change_id,
                &self.expected_state,
            ]
            .iter()
            .any(|s| !id(s))
            || self.previous_revision.as_ref().is_some_and(|s| !id(s))
            || self.previous_policy.as_ref().is_some_and(|s| !id(s))
            || self.reason.trim().is_empty()
            || self.reason.len() > 1024
            || self.reason.chars().any(char::is_control)
            || self.revision > 4096
        {
            return Err("invalid signed budget change bounds".into());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedChange {
    pub request: ChangeRequest,
    pub signature: String,
}
impl SignedChange {
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), String> {
        self.request.validate()?;
        if self.request.key_id != key_id(key) {
            return Err("approval key mismatch".into());
        }
        verify(key, CHANGE_DOMAIN, &self.request, &self.signature)
    }
    pub fn hash(&self) -> String {
        hash(
            "siworld signed fund policy change v1",
            &serde_json::to_vec(self).expect("change serialization"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp(name: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("siworld-{name}-{n}"));
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
    fn policy() -> FundBudget {
        FundBudget {
            version: 1,
            id: "ab".repeat(32),
            direct_sip: "100000".into(),
            lock_sip: "100000".into(),
            total_sip: "200000".into(),
            max_payout_sip: "100000".into(),
        }
    }
    fn request(key: &VerifyingKey) -> ChangeRequest {
        ChangeRequest {
            version: 1,
            genesis: "01".repeat(32),
            fund_id: "02".repeat(32),
            key_id: key_id(key),
            change_id: "03".repeat(32),
            revision: 0,
            previous_revision: None,
            previous_policy: None,
            expected_sequence: 0,
            expected_state: "04".repeat(32),
            reserved_atoms: [0, 0],
            policy: policy(),
            reason: "initial enrollment".into(),
        }
    }
    #[test]
    fn encrypted_approver_lifecycle_and_signature_tamper_fail_closed() {
        let root = temp("approver");
        let dir = root.join("keys");
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.join("key");
        let signer = ApprovalSigner::generate_file(&path, "correct horse battery staple").unwrap();
        assert!(ApprovalSigner::load(&path, "wrong password").is_err());
        let public = dir.join("public");
        ApprovalSigner::save_public(&public, &signer.verifying_key()).unwrap();
        assert_eq!(read_key(&public).unwrap(), signer.verifying_key());
        let req = request(&signer.verifying_key());
        let signed = signer.approve_change(&req).unwrap();
        signed.verify(&signer.verifying_key()).unwrap();
        let mut changed = signed.clone();
        changed.request.reason = "changed after review".into();
        assert!(changed.verify(&signer.verifying_key()).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn revision_request_rejects_invalid_bounds_before_signing() {
        let root = temp("bounds");
        let dir = root.join("keys");
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let signer =
            ApprovalSigner::generate_file(&dir.join("key"), "correct horse battery staple")
                .unwrap();
        let mut req = request(&signer.verifying_key());
        req.reason = "\n".into();
        assert!(signer.approve_change(&req).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
