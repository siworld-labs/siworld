//! Independent receiver protocol for private order archives. No network server,
//! physical-domain detection, automatic send gate or global rollback guarantee.
use crate::keystore::{atomic_write_bytes, derived_key, WalletFileLock};
use crate::orders::archive::{self, json, private_dir, publish, stage_for, sync_dir, Manifest};
use crate::orders::Checkpoint;
use crate::secrets::read_private_bytes;
use crate::{hex, parse_hex, parse_hex32};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use siworld_core::params::{SIGNATURE_LEN, VERIFYING_KEY_LEN};
use siworld_core::Digest;
use siworld_crypto::{Signature, SigningKey, VerifyingKey};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};
const MAX_RECEIPTS: usize = 4096;
const MAX_JSON: usize = 32 << 10;
const KEY_MAGIC: &[u8; 8] = b"SIRKEY01";
const KEY_AAD: &[u8] = b"siworld retention receipt signer v1:argon2id:xchacha20poly1305";
fn hash(context: &str, bytes: &[u8]) -> String {
    hex(&Digest(blake3::derive_key(context, bytes)))
}
fn valid_hash(s: &str) -> bool {
    parse_hex32(s).is_some() && s.to_lowercase() == s
}
fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&read_private_bytes(path, MAX_JSON)?)
        .map_err(|_| "invalid retention record".into())
}
fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    atomic_write_bytes(path, &json(value)?, false, || Ok(()))
}
fn random_digest() -> Result<Digest, String> {
    let mut b = [0; 32];
    getrandom::fill(&mut b).map_err(|_| "OS randomness unavailable")?;
    Ok(Digest(b))
}
fn key_id(key: &VerifyingKey) -> String {
    hash("siworld retention verifying key id v1", &key.0)
}
fn message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, String> {
    let mut b = domain.to_vec();
    b.extend_from_slice(&json(value)?);
    Ok(b)
}
const RECEIPT_DOMAIN: &[u8] = b"siworld retained order archive receipt v1\0";
const STATUS_DOMAIN: &[u8] = b"siworld retained order archive current status v1\0";
const CONFIG_DOMAIN: &[u8] = b"siworld retained order archive receiver config v1\0";
/// Dedicated encrypted receipt key. It is never a wallet or development-fund key.
pub struct ReceiptSigner(SigningKey);
impl ReceiptSigner {
    fn from_seed(seed: &[u8]) -> Self {
        let mut d = Digest(blake3::derive_key(
            "siworld retention ML-DSA-65 key v1",
            seed,
        ));
        let key = SigningKey::generate(&d);
        d.0.zeroize();
        Self(key)
    }
    pub fn generate_file(path: &Path, password: &str) -> Result<Self, String> {
        if password.len() < 12 {
            return Err("new receipt key passwords require 12 UTF-8 bytes".into());
        }
        let mut out = [0u8; 96];
        out[..8].copy_from_slice(KEY_MAGIC);
        getrandom::fill(&mut out[8..48]).map_err(|_| "OS randomness unavailable")?;
        let mut plain = Zeroizing::new([0u8; 32]);
        getrandom::fill(plain.as_mut()).map_err(|_| "OS randomness unavailable")?;
        let signer = Self::from_seed(plain.as_ref());
        let k = derived_key(password, &out[8..24])?;
        let cipher = XChaCha20Poly1305::new(<&Key>::try_from(k.as_ref()).expect("key length"));
        let mut aad = KEY_AAD.to_vec();
        aad.extend_from_slice(&out[..48]);
        let tag = cipher
            .encrypt_inout_detached(
                <&XNonce>::try_from(&out[24..48]).expect("nonce"),
                &aad,
                plain.as_mut_slice().into(),
            )
            .map_err(|_| "cannot encrypt receipt key")?;
        out[48..80].copy_from_slice(plain.as_ref());
        out[80..].copy_from_slice(&tag);
        atomic_write_bytes(path, &out, false, || Ok(()))?;
        let loaded = Self::load(path, password)?;
        if loaded.verifying_key() != signer.verifying_key() {
            return Err("receipt key read-back mismatch".into());
        }
        Ok(loaded)
    }
    pub fn load(path: &Path, password: &str) -> Result<Self, String> {
        let out = read_private_bytes(path, 96)?;
        if out.len() != 96 || &out[..8] != KEY_MAGIC {
            return Err("invalid encrypted receipt key".into());
        }
        let k = derived_key(password, &out[8..24])?;
        let mut plain = Zeroizing::new(out[48..80].to_vec());
        let mut aad = KEY_AAD.to_vec();
        aad.extend_from_slice(&out[..48]);
        XChaCha20Poly1305::new(<&Key>::try_from(k.as_ref()).expect("key length"))
            .decrypt_inout_detached(
                <&XNonce>::try_from(&out[24..48]).expect("nonce"),
                &aad,
                plain.as_mut_slice().into(),
                &Tag::try_from(&out[80..]).expect("tag"),
            )
            .map_err(|_| "incorrect receipt key password or damaged key")?;
        Ok(Self::from_seed(&plain))
    }
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.0.verifying_key()
    }
    fn sign(&self, domain: &[u8], body: &impl Serialize) -> Result<String, String> {
        let mut hedge = random_digest()?;
        let signature = self.0.sign(&message(domain, body)?, &hedge);
        hedge.0.zeroize();
        Ok(signature.0.iter().map(|b| format!("{b:02x}")).collect())
    }
}
pub fn save_trusted_key(path: &Path, key: &VerifyingKey) -> Result<(), String> {
    let s: String = key.0.iter().map(|b| format!("{b:02x}")).collect();
    atomic_write_bytes(path, s.as_bytes(), false, || Ok(()))
}
pub fn read_trusted_key(path: &Path) -> Result<VerifyingKey, String> {
    let bytes = read_private_bytes(path, 2 * VERIFYING_KEY_LEN)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| "invalid receipt public key")?;
    parse_hex(s)
        .filter(|_| s.to_lowercase() == s)
        .map(VerifyingKey)
        .ok_or_else(|| "invalid receipt public key".into())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub challenge: String,
    pub previous_receipt: Option<String>,
}
impl Request {
    pub fn fresh(previous_receipt: Option<String>) -> Result<Self, String> {
        let q = Self {
            version: 1,
            challenge: hex(&random_digest()?),
            previous_receipt,
        };
        q.validate()?;
        Ok(q)
    }
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !valid_hash(&self.challenge)
            || self.challenge == "00".repeat(32)
            || self
                .previous_receipt
                .as_ref()
                .is_some_and(|s| !valid_hash(s))
        {
            return Err("invalid retention challenge request".into());
        }
        Ok(())
    }
    pub fn read(path: &Path) -> Result<Self, String> {
        let q: Self = load_json(path)?;
        q.validate()?;
        Ok(q)
    }
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        save_json(path, self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub version: u32,
    pub revision: u64,
    pub key_id: String,
    pub archive_id: String,
    pub manifest: Manifest,
    pub request: Request,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub body: ReceiptBody,
    pub signature: String,
}
fn verify_signature(
    key: &VerifyingKey,
    domain: &[u8],
    body: &impl Serialize,
    signature: &str,
) -> Result<(), String> {
    let s = parse_hex::<SIGNATURE_LEN>(signature)
        .filter(|_| signature.to_lowercase() == signature)
        .ok_or("invalid receipt signature encoding")?;
    if !key.verify(&message(domain, body)?, &Signature(s)) {
        return Err("retention signature verification failed".into());
    }
    Ok(())
}
impl Receipt {
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), String> {
        self.body.request.validate()?;
        if self.body.version != 1
            || self.body.revision == 0
            || self.body.revision > MAX_RECEIPTS as u64
            || self.body.key_id != key_id(key)
            || self.body.archive_id != self.body.manifest.id()?
        {
            return Err("invalid retention receipt statement".into());
        }
        verify_signature(key, RECEIPT_DOMAIN, &self.body, &self.signature)
    }
    pub fn verify(
        &self,
        key: &VerifyingKey,
        manifest: &Manifest,
        request: &Request,
    ) -> Result<(), String> {
        self.verify_signature(key)?;
        if &self.body.manifest != manifest || &self.body.request != request {
            return Err("retention receipt request/archive mismatch".into());
        }
        Ok(())
    }
    pub fn id(&self) -> Result<String, String> {
        Ok(hash("siworld retention signed receipt id v1", &json(self)?))
    }
    pub fn read(path: &Path) -> Result<Self, String> {
        load_json(path)
    }
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        save_json(path, self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusBody {
    pub version: u32,
    pub key_id: String,
    pub request: Request,
    pub receipt: Receipt,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub body: StatusBody,
    pub signature: String,
}
impl Status {
    pub fn verify(&self, key: &VerifyingKey, request: &Request) -> Result<Receipt, String> {
        request.validate()?;
        if self.body.version != 1
            || self.body.key_id != key_id(key)
            || &self.body.request != request
        {
            return Err("retention status challenge mismatch".into());
        }
        self.body.receipt.verify_signature(key)?;
        verify_signature(key, STATUS_DOMAIN, &self.body, &self.signature)?;
        Ok(self.body.receipt.clone())
    }
    pub fn read(path: &Path) -> Result<Self, String> {
        load_json(path)
    }
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        save_json(path, self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigBody {
    version: u32,
    key_id: String,
    initial: Checkpoint,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    body: ConfigBody,
    signature: String,
}
/// Receiver storage and signer must be independently administered in deployment.
/// A fresh signature cannot detect rollback of the receiver's entire own state.
pub struct Retainer<'a> {
    root: PathBuf,
    signer: &'a ReceiptSigner,
    _lock: WalletFileLock,
}
impl<'a> Retainer<'a> {
    pub fn create(
        root: &Path,
        signer: &'a ReceiptSigner,
        initial: &Checkpoint,
    ) -> Result<Self, String> {
        initial.validate()?;
        let mut stage = stage_for(root)?;
        let p = stage.0.as_ref().unwrap();
        let body = ConfigBody {
            version: 1,
            key_id: key_id(signer.verifying_key()),
            initial: initial.clone(),
        };
        save_json(
            &p.join("config.json"),
            &Config {
                signature: signer.sign(CONFIG_DOMAIN, &body)?,
                body,
            },
        )?;
        publish(&mut stage, root)?;
        Self::open(root, signer)
    }
    pub fn open(root: &Path, signer: &'a ReceiptSigner) -> Result<Self, String> {
        private_dir(root)?;
        let lock = WalletFileLock::acquire(root)?;
        let root = fs::canonicalize(root).map_err(|_| "cannot inspect retention root")?;
        let r = Self {
            root,
            signer,
            _lock: lock,
        };
        r.scan()?;
        Ok(r)
    }
    fn config(&self) -> Result<ConfigBody, String> {
        let c: Config = load_json(&self.root.join("config.json"))?;
        c.body.initial.validate()?;
        if c.body.version != 1 || c.body.key_id != key_id(self.signer.verifying_key()) {
            return Err("retention signer/config mismatch".into());
        }
        verify_signature(
            self.signer.verifying_key(),
            CONFIG_DOMAIN,
            &c.body,
            &c.signature,
        )?;
        Ok(c.body)
    }
    fn entry(&self, revision: u64) -> PathBuf {
        self.root.join(format!("entry-{revision:016x}"))
    }
    fn scan(&self) -> Result<Vec<Receipt>, String> {
        let config = self.config()?;
        let mut count = 0;
        let mut listed = 0;
        for e in fs::read_dir(&self.root).map_err(|_| "cannot list retention root")? {
            listed += 1;
            if listed > 2 * MAX_RECEIPTS + 2 {
                return Err("retention directory entry limit".into());
            }
            let e = e.map_err(|_| "cannot list retention root")?;
            let name = e
                .file_name()
                .into_string()
                .map_err(|_| "invalid retention name")?;
            if name == "config.json" || name == ".wallet.lock" {
                continue;
            }
            // A crash can leave an unpublished random staging directory. It is
            // retained for investigation and never counted as an accepted entry.
            if name
                .strip_prefix(".si-archive-")
                .and_then(|s| s.strip_suffix(".tmp"))
                .is_some_and(|s| parse_hex::<16>(s).is_some())
            {
                continue;
            }
            let seq = name
                .strip_prefix("entry-")
                .filter(|s| s.len() == 16)
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or("unexpected retention entry")?;
            if seq == 0 || seq > MAX_RECEIPTS as u64 || name != format!("entry-{seq:016x}") {
                return Err("invalid retention revision".into());
            }
            count += 1;
        }
        let mut receipts: Vec<Receipt> = Vec::new();
        let mut previous = None;
        let mut cp = config.initial;
        for i in 1..=count {
            let entry = self.entry(i as u64);
            private_dir(&entry)?;
            let names: Vec<_> = fs::read_dir(&entry)
                .map_err(|_| "retention history gap")?
                .take(3)
                .collect::<Result<_, _>>()
                .map_err(|_| "cannot inspect retention entry")?;
            if names.len() != 2
                || names
                    .iter()
                    .any(|e| e.file_name() != "archive" && e.file_name() != "receipt.json")
            {
                return Err("unexpected retained generation file".into());
            }
            let receipt = Receipt::read(&entry.join("receipt.json"))?;
            receipt.verify_signature(self.signer.verifying_key())?;
            if receipt.body.revision != i as u64
                || receipt.body.request.previous_receipt != previous
                || archive::inspect(&entry.join("archive"))? != receipt.body.manifest
            {
                return Err("retention history/digest mismatch".into());
            }
            self.ancestor(&entry.join("archive"), &receipt.body.manifest, &cp)?;
            cp = receipt.body.manifest.checkpoint.clone();
            previous = Some(receipt.id()?);
            receipts.push(receipt);
        }
        Ok(receipts)
    }
    fn ancestor(
        &self,
        path: &Path,
        manifest: &Manifest,
        previous: &Checkpoint,
    ) -> Result<(), String> {
        if previous.sequence > manifest.checkpoint.sequence
            || Checkpoint::read(
                &path
                    .join("witness")
                    .join(Checkpoint::filename(previous.sequence)),
            )? != *previous
        {
            return Err("retention checkpoint rollback or fork".into());
        }
        Ok(())
    }
    pub fn accept(&mut self, source: &Path, request: &Request) -> Result<Receipt, String> {
        self.accept_with_hook(source, request, || Ok(()))
    }
    fn accept_with_hook(
        &mut self,
        source: &Path,
        request: &Request,
        hook: impl FnOnce() -> Result<(), String>,
    ) -> Result<Receipt, String> {
        request.validate()?;
        let source = fs::canonicalize(source).map_err(|_| "cannot inspect incoming archive")?;
        if source.starts_with(&self.root) || self.root.starts_with(&source) {
            return Err("incoming archive and receiver must be separate".into());
        }
        let manifest = archive::inspect(&source)?;
        let receipts = self.scan()?;
        if let Some(last) = receipts.last() {
            if last.body.request == *request && last.body.manifest == manifest {
                // A prior call may have renamed successfully but failed its
                // parent sync. Re-establish publication before acknowledging.
                self.sync_publication()?;
                return Ok(last.clone());
            }
        }
        let previous = receipts.last().map(Receipt::id).transpose()?;
        if request.previous_receipt != previous {
            return Err("retention previous receipt mismatch".into());
        }
        if receipts.len() == MAX_RECEIPTS {
            return Err("retention capacity reached; no automatic history deletion".into());
        }
        let cp = receipts
            .last()
            .map(|r| r.body.manifest.checkpoint.clone())
            .unwrap_or(self.config()?.initial);
        self.ancestor(&source, &manifest, &cp)?;
        let revision = receipts.len() as u64 + 1;
        let output = self.entry(revision);
        let mut stage = stage_for(&output)?;
        let p = stage.0.as_ref().unwrap();
        if archive::copy_into(&source, &p.join("archive"))? != manifest {
            return Err("incoming archive changed while copying".into());
        }
        self.ancestor(&p.join("archive"), &manifest, &cp)?;
        let body = ReceiptBody {
            version: 1,
            revision,
            key_id: key_id(self.signer.verifying_key()),
            archive_id: manifest.id()?,
            manifest: manifest.clone(),
            request: request.clone(),
        };
        let receipt = Receipt {
            signature: self.signer.sign(RECEIPT_DOMAIN, &body)?,
            body,
        };
        save_json(&p.join("receipt.json"), &receipt)?;
        hook()?;
        publish(&mut stage, &output)?;
        // No acknowledgement is returned until durable publication/read-back.
        if archive::inspect(&output.join("archive"))? != manifest
            || Receipt::read(&output.join("receipt.json"))? != receipt
        {
            return Err("published retention generation read-back mismatch".into());
        }
        receipt.verify(self.signer.verifying_key(), &manifest, request)?;
        Ok(receipt)
    }
    pub fn status(&mut self, request: &Request) -> Result<Status, String> {
        request.validate()?;
        let receipts = self.scan()?;
        if let Some(pin) = &request.previous_receipt {
            if !receipts.iter().any(|r| r.id().as_ref() == Ok(pin)) {
                return Err("retention minimum receipt not in history".into());
            }
        }
        let receipt = receipts
            .last()
            .ok_or("receiver has no accepted archive")?
            .clone();
        self.sync_publication()?;
        let body = StatusBody {
            version: 1,
            key_id: key_id(self.signer.verifying_key()),
            request: request.clone(),
            receipt,
        };
        Ok(Status {
            signature: self.signer.sign(STATUS_DOMAIN, &body)?,
            body,
        })
    }
    fn sync_publication(&self) -> Result<(), String> {
        sync_dir(&self.root)?;
        sync_dir(self.root.parent().unwrap_or(Path::new(".")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::Staging;
    use crate::orders::archive::make_dir;
    const PASSWORD: &str = "temporary receiver interruption password";
    #[test]
    fn retention_process_child() {
        let Some(root) = std::env::var_os("SI_RETENTION_CRASH_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let signer = ReceiptSigner::load(&root.join("key"), PASSWORD).unwrap();
        let mut receiver = Retainer::open(&root.join("receiver"), &signer).unwrap();
        let request = Request::read(&root.join("request.json")).unwrap();
        if std::env::var_os("SI_RETENTION_AFTER_PUBLISH").is_some() {
            receiver.accept(&root.join("archive"), &request).unwrap();
            std::process::exit(85);
        }
        let _ =
            receiver.accept_with_hook(&root.join("archive"), &request, || std::process::exit(86));
        panic!("child did not exit");
    }
    #[test]
    fn interrupted_receiving_never_promotes_staging_and_lost_ack_replays_the_committed_receipt() {
        let root = std::env::temp_dir().join(format!(
            "si-retention-crash-{}",
            hex(&random_digest().unwrap())
        ));
        make_dir(&root).unwrap();
        let cleanup = Staging(Some(root.clone()));
        make_dir(&root.join("ledger")).unwrap();
        make_dir(&root.join("witness")).unwrap();
        let l = crate::orders::OrderLedger::create(
            &root.join("ledger"),
            &root.join("witness"),
            PASSWORD,
            Digest([1; 32]),
            Digest([2; 32]),
        )
        .unwrap();
        let manifest = l.archive(&root.join("archive"), None).unwrap();
        let signer = ReceiptSigner::generate_file(&root.join("key"), PASSWORD).unwrap();
        Retainer::create(&root.join("receiver"), &signer, &manifest.checkpoint).unwrap();
        let request = Request::fresh(None).unwrap();
        request.save_new(&root.join("request.json")).unwrap();
        let child = |after: bool| {
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args([
                "--exact",
                "retention::tests::retention_process_child",
                "--nocapture",
            ])
            .env("SI_RETENTION_CRASH_ROOT", &root);
            if after {
                c.env("SI_RETENTION_AFTER_PUBLISH", "1");
            } else {
                c.env_remove("SI_RETENTION_AFTER_PUBLISH");
            }
            let out = c.output().unwrap();
            assert_eq!(
                out.status.code(),
                Some(if after { 85 } else { 86 }),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        child(false);
        assert!(!root.join("receiver/entry-0000000000000001").exists());
        let mut receiver = Retainer::open(&root.join("receiver"), &signer).unwrap();
        assert!(receiver.status(&request).is_err());
        let first = receiver.accept(&root.join("archive"), &request).unwrap();
        drop(receiver);
        fs::remove_file(root.join("request.json")).unwrap();
        let next = Request::fresh(Some(first.id().unwrap())).unwrap();
        next.save_new(&root.join("request.json")).unwrap();
        child(true);
        let stored =
            Receipt::read(&root.join("receiver/entry-0000000000000002/receipt.json")).unwrap();
        let mut reopened = Retainer::open(&root.join("receiver"), &signer).unwrap();
        assert_eq!(
            reopened.accept(&root.join("archive"), &next).unwrap(),
            stored
        );
        assert!(!root.join("receiver/entry-0000000000000003").exists());
        drop(reopened);
        drop(l);
        drop(cleanup);
    }
}
