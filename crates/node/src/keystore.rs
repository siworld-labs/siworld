//! Versioned, authenticated local wallet storage; not a consensus format.
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use siworld_core::Digest;
use siworld_crypto::{is_canonical, SpendKey};
use zeroize::{Zeroize, Zeroizing};

use crate::secrets::{read_secret, write_private_bytes};

const PREFIX: &str = "SIWALLET1:";
const AAD: &[u8] =
    b"siworld wallet keystore v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305:spend-key";
const MEMORY_KIB: u32 = 65536;
const MAX_PASSWORD: usize = 1024;

/// Only ciphertext is retained. Each format version fixes its KDF/AEAD limits;
/// attacker-controlled parameters can never request unbounded KDF resources.
#[derive(Clone)]
pub struct Keystore([u8; 88]);
impl core::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keystore(REDACTED)")
    }
}

pub(crate) fn derived_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err("password must contain 1 to 1024 UTF-8 bytes".into());
    }
    let params = Params::new(MEMORY_KIB, 3, 1, Some(32)).map_err(|_| "invalid wallet KDF")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut memory = Zeroizing::new(vec![Block::default(); MEMORY_KIB as usize]);
    argon
        .hash_password_into_with_memory(password.as_bytes(), salt, key.as_mut(), &mut *memory)
        .map_err(|_| "wallet key derivation failed")?;
    Ok(key)
}

impl Keystore {
    pub fn seal(key: &SpendKey, password: &str) -> Result<Self, String> {
        if !(12..=MAX_PASSWORD).contains(&password.len()) {
            return Err("new wallet passwords require 12 to 1024 UTF-8 bytes".into());
        }
        let mut out = [0u8; 88];
        getrandom::fill(&mut out[..40]).map_err(|_| "OS randomness unavailable")?;
        let derived = derived_key(password, &out[..16])?;
        let cipher =
            XChaCha20Poly1305::new(<&Key>::try_from(derived.as_ref()).expect("key length"));
        let mut plain = Zeroizing::new(*key.expose_secret());
        let tag = cipher
            .encrypt_inout_detached(
                <&XNonce>::try_from(&out[16..40]).expect("nonce length"),
                AAD,
                plain.as_mut_slice().into(),
            )
            .map_err(|_| "wallet encryption failed")?;
        out[40..72].copy_from_slice(plain.as_ref());
        out[72..].copy_from_slice(&tag);
        let store = Self(out);
        // Validate identity before any destination file is published.
        if store.open(password)? != *key {
            return Err("wallet identity validation failed".into());
        }
        Ok(store)
    }

    pub fn open(&self, password: &str) -> Result<SpendKey, String> {
        let key = derived_key(password, &self.0[..16])?;
        let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"));
        let mut plain = Zeroizing::new([0u8; 32]);
        plain.copy_from_slice(&self.0[40..72]);
        cipher
            .decrypt_inout_detached(
                <&XNonce>::try_from(&self.0[16..40]).expect("nonce length"),
                AAD,
                plain.as_mut_slice().into(),
                &Tag::try_from(&self.0[72..]).expect("tag length"),
            )
            .map_err(|_| "incorrect wallet password or damaged keystore")?;
        let mut digest = Digest(*plain);
        if !is_canonical(&digest) {
            digest.0.zeroize();
            return Err("invalid wallet key".into());
        }
        let key = SpendKey::from_digest(digest);
        digest.0.zeroize();
        Ok(key)
    }

    pub fn encode(&self) -> String {
        use std::fmt::Write;
        let mut text = String::from(PREFIX);
        for b in self.0 {
            write!(text, "{b:02x}").expect("string formatting");
        }
        text.push('\n');
        text
    }

    pub fn decode(text: &str) -> Result<Self, String> {
        let text = text.strip_suffix('\n').unwrap_or(text);
        let bytes = text
            .strip_prefix(PREFIX)
            .and_then(crate::parse_hex::<88>)
            .ok_or("unsupported or malformed wallet keystore")?;
        Ok(Self(bytes))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::decode(&read_secret(path)?)
    }

    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        atomic_write(path, &self.encode(), false, || Ok(()))
    }
}

/// Passwords enter via a hidden terminal prompt or an owner-only file, never
/// through a password command-line argument or an environment variable.
pub fn read_password(file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>, String> {
    read_password_for("Wallet", file, confirm)
}
pub fn read_password_for(
    label: &str,
    file: Option<&Path>,
    confirm: bool,
) -> Result<Zeroizing<String>, String> {
    let password = if let Some(path) = file {
        let mut text = read_secret(path)?;
        if text.ends_with('\n') {
            text.pop();
            if text.ends_with('\r') {
                text.pop();
            }
        }
        if text.contains(['\r', '\n']) {
            return Err("password file must contain one line".into());
        }
        text
    } else {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return Err("use a terminal or --password-file FILE".into());
        }
        let password = Zeroizing::new(
            rpassword::prompt_password(format!("{label} password: "))
                .map_err(|_| "cannot read wallet password")?,
        );
        if confirm {
            let again = Zeroizing::new(
                rpassword::prompt_password(format!("Confirm {label} password: "))
                    .map_err(|_| "cannot read wallet password")?,
            );
            if *password != *again {
                return Err("wallet passwords do not match".into());
            }
        }
        password
    };
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err("invalid password length".into());
    }
    Ok(password)
}

pub fn legacy_key(path: &Path) -> Result<SpendKey, String> {
    let text = read_secret(path)?;
    let mut digest = crate::parse_hex32(text.trim())
        .filter(is_canonical)
        .ok_or("not a legacy wallet key")?;
    let key = SpendKey::from_digest(digest);
    digest.0.zeroize();
    Ok(key)
}

/// One process owns wallet migration/recovery or a running data directory.
/// The persistent lock file must not be deleted to bypass ownership.
pub struct WalletFileLock(#[allow(dead_code)] std::fs::File);

#[cfg(unix)]
impl WalletFileLock {
    pub fn acquire(dir: &Path) -> Result<Self, String> {
        use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(dir).map_err(|_| "cannot inspect wallet directory")?;
        if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err("wallet directory must be owner-only and not a symlink".into());
        }
        let fd = open(
            dir.join(".wallet.lock"),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "cannot open wallet lock")?;
        let file = std::fs::File::from(fd);
        let m = file.metadata().map_err(|_| "cannot inspect wallet lock")?;
        if !m.is_file()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
        {
            return Err("invalid wallet lock file".into());
        }
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "wallet directory is already in use")?;
        Ok(Self(file))
    }
}
#[cfg(unix)]
impl Drop for WalletFileLock {
    fn drop(&mut self) {
        // Release ownership explicitly: a transient fork/spawn copy of this
        // open-file description must not extend a finished operation's lock.
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}
#[cfg(not(unix))]
impl WalletFileLock {
    pub fn acquire(_dir: &Path) -> Result<Self, String> {
        Err("wallet file protection is unavailable on this platform".into())
    }
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn atomic_write(
    path: &Path,
    text: &str,
    replace: bool,
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    atomic_write_bytes(path, text.as_bytes(), replace, before_publish)
}

pub(crate) fn atomic_write_bytes(
    path: &Path,
    bytes: &[u8],
    replace: bool,
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| "OS randomness unavailable")?;
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let temp = Temporary(parent.join(format!(".wallet-{name}.tmp")));
    write_private_bytes(&temp.0, bytes)?; // create_new, mode 0600, write_all and fsync
    before_publish()?;
    if replace {
        std::fs::rename(&temp.0, path).map_err(|_| "cannot atomically replace wallet file")?;
    } else {
        // Exclusive publication on the same filesystem; never overwrite a target.
        std::fs::hard_link(&temp.0, path)
            .map_err(|_| "cannot publish wallet file (destination may exist)")?;
        std::fs::remove_file(&temp.0)
            .map_err(|_| "wallet published; temporary link cleanup failed")?;
    }
    std::fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|_| "wallet published; directory sync failed")?;
    Ok(())
}

pub fn migrate_wallet(dir: &Path, password: &str) -> Result<(), String> {
    let _lock = WalletFileLock::acquire(dir)?;
    let path = dir.join("key");
    let key = legacy_key(&path)?;
    let store = Keystore::seal(&key, password)?;
    atomic_write(&path, &store.encode(), true, || Ok(()))
}

pub fn backup_wallet(dir: &Path, output: &Path, password: &str) -> Result<(), String> {
    let _lock = WalletFileLock::acquire(dir)?;
    let key = Keystore::load(&dir.join("key"))?.open(password)?;
    Keystore::seal(&key, password)?.save_new(output)
}

pub fn restore_wallet(backup: &Path, dir: &Path, password: &str) -> Result<(), String> {
    let store = Keystore::load(backup)?;
    let key = store.open(password)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|_| "cannot create restore directory")?;
    let _lock = WalletFileLock::acquire(dir)?;
    let occupied = std::fs::read_dir(dir)
        .map_err(|_| "cannot inspect restore directory")?
        .any(|entry| entry.map_or(true, |e| e.file_name() != ".wallet.lock"));
    if occupied {
        return Err("restore requires a new or empty wallet directory".into());
    }
    Keystore::seal(&key, password)?.save_new(&dir.join("key"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::secrets::write_secret;
    #[test]
    fn dropping_ownership_unlocks_despite_a_transient_duplicate_handle() {
        let dir =
            std::env::temp_dir().join(format!("siworld-explicit-unlock-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = WalletFileLock::acquire(&dir).unwrap();
        // Models the open-file description transiently inherited during a
        // concurrent process launch, before CLOEXEC closes its descriptors.
        let inherited = lock.0.try_clone().unwrap();
        assert!(WalletFileLock::acquire(&dir).is_err());
        drop(lock);
        let next = WalletFileLock::acquire(&dir);
        assert!(next.is_ok());
        drop(next);
        drop(inherited);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn interrupted_publication_preserves_old_file_and_cleans_temporary() {
        let dir =
            std::env::temp_dir().join(format!("siworld-atomic-wallet-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("key");
        write_secret(&path, "original").unwrap();
        assert!(atomic_write(&path, "encrypted", true, || Err(
            "injected interruption".into()
        ))
        .is_err());
        assert_eq!(&*read_secret(&path).unwrap(), "original");
        assert_eq!(dir.read_dir().unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
