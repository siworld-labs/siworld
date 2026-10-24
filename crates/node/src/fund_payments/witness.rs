//! Immutable encrypted generations in a separate custody domain.
use super::*;
use crate::orders::archive::{json, make_dir, private_dir, sync_dir};
const MAX_GENERATIONS: usize = 16_384;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub identity: String,
    pub witness: String,
    pub sequence: u64,
    pub state_hash: String,
    pub previous: String,
}
impl Checkpoint {
    pub fn read(path: &Path) -> Result<Self, String> {
        let cp: Self = serde_json::from_slice(&read_private_bytes(path, 2048)?)
            .map_err(|_| "invalid fund checkpoint")?;
        cp.validate()?;
        Ok(cp)
    }
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        atomic_write_bytes(path, &json(self)?, false, || Ok(()))
    }
    pub fn id(&self) -> Result<String, String> {
        self.validate()?;
        Ok(crate::genesis::hex_bytes(&blake3::derive_key(
            "siworld fund witness checkpoint v1",
            &json(self)?,
        )))
    }
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || [
                &self.identity,
                &self.witness,
                &self.state_hash,
                &self.previous,
            ]
            .iter()
            .any(|s| crate::parse_hex32(s).is_none() || s.to_lowercase() != **s)
        {
            return Err("invalid fund checkpoint".into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    identity: String,
    witness: String,
    first: u64,
}
fn identity(g: &Genesis) -> String {
    blake3::hash(&context(g)).to_hex().to_string()
}
fn cp_name(seq: u64) -> String {
    format!("generation-{seq:016x}")
}
fn read_generation(path: &Path) -> Result<(Checkpoint, Vec<u8>), String> {
    let bytes = read_private_bytes(path, MAX_BYTES + 2052)?;
    if bytes.len() < 4 {
        return Err("invalid fund generation".into());
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().expect("length")) as usize;
    if n > 2048 || n > bytes.len() - 4 {
        return Err("invalid fund generation".into());
    }
    let cp: Checkpoint = serde_json::from_slice(&bytes[4..4 + n])
        .map_err(|_| "invalid fund generation checkpoint")?;
    cp.validate()?;
    let state = bytes[4 + n..].to_vec();
    if state.len() > MAX_BYTES || blake3::hash(&state).to_hex().as_str() != cp.state_hash {
        return Err("fund generation hash mismatch".into());
    }
    Ok((cp, state))
}
fn write_generation(path: &Path, cp: &Checkpoint, state: &[u8]) -> Result<(), String> {
    let meta = json(cp)?;
    let mut bytes = (meta.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&meta);
    bytes.extend_from_slice(state);
    atomic_write_bytes(path, &bytes, false, || Ok(()))
}
pub(super) struct Witness {
    pub(super) directory: PathBuf,
    _lock: WalletFileLock,
    checkpoints: Vec<Checkpoint>,
    pub(super) bytes: Vec<u8>,
}
impl Witness {
    pub(super) fn create(
        path: &Path,
        g: &Genesis,
        id: &str,
        bytes: &[u8],
        data: &Data,
    ) -> Result<Self, String> {
        make_dir(path)?;
        let lock = WalletFileLock::acquire(path)?;
        atomic_write_bytes(
            &path.join("identity.json"),
            &json(&Identity {
                version: 1,
                identity: identity(g),
                witness: id.into(),
                first: data.sequence,
            })?,
            false,
            || Ok(()),
        )?;
        let cp = Checkpoint {
            version: 1,
            identity: identity(g),
            witness: id.into(),
            sequence: data.sequence,
            state_hash: blake3::hash(bytes).to_hex().to_string(),
            previous: "00".repeat(32),
        };
        write_generation(&path.join(cp_name(data.sequence)), &cp, bytes)?;
        sync_dir(path.parent().unwrap_or(Path::new(".")))?;
        Ok(Self {
            directory: std::fs::canonicalize(path).map_err(|_| "cannot resolve fund witness")?,
            _lock: lock,
            checkpoints: vec![cp],
            bytes: bytes.to_vec(),
        })
    }
    pub(super) fn open(path: &Path, g: &Genesis) -> Result<Self, String> {
        private_dir(path)?;
        let lock = WalletFileLock::acquire(path)?;
        let meta: Identity =
            serde_json::from_slice(&read_private_bytes(&path.join("identity.json"), 2048)?)
                .map_err(|_| "invalid fund witness identity")?;
        if meta.version != 1
            || meta.identity != identity(g)
            || crate::parse_hex32(&meta.witness).is_none()
        {
            return Err("fund witness identity mismatch".into());
        }
        let mut sequences = BTreeSet::new();
        // Bound directory scanning as well as history verification.
        for (i, e) in std::fs::read_dir(path)
            .map_err(|_| "cannot list fund witness")?
            .enumerate()
        {
            if i > MAX_GENERATIONS + 4 {
                return Err("fund witness capacity exceeded".into());
            }
            let name = e
                .map_err(|_| "cannot list fund witness")?
                .file_name()
                .into_string()
                .map_err(|_| "invalid witness name")?;
            if let Some(seq) = name.strip_prefix("generation-") {
                let n = u64::from_str_radix(seq, 16).map_err(|_| "invalid witness generation")?;
                if name != cp_name(n) || !sequences.insert(n) {
                    return Err("invalid witness generation".into());
                }
            }
        }
        if sequences.is_empty() || sequences.len() > MAX_GENERATIONS {
            return Err("fund witness history missing or full".into());
        }
        let mut cps = Vec::<Checkpoint>::new();
        for seq in sequences {
            let (cp, _) = read_generation(&path.join(cp_name(seq)))?;
            let (expected_seq, previous) = if let Some(last) = cps.last() {
                (
                    last.sequence
                        .checked_add(1)
                        .ok_or("witness sequence overflow")?,
                    last.id()?,
                )
            } else {
                (meta.first, "00".repeat(32))
            };
            if seq != expected_seq
                || cp.sequence != seq
                || cp.identity != meta.identity
                || cp.witness != meta.witness
                || cp.previous != previous
            {
                return Err("fund witness prefix mismatch".into());
            }
            cps.push(cp);
        }
        let cp = cps.last().expect("nonempty");
        let (_, bytes) = read_generation(&path.join(cp_name(cp.sequence)))?;
        if blake3::hash(&bytes).to_hex().as_str() != cp.state_hash {
            return Err("fund witness state hash mismatch".into());
        }
        Ok(Self {
            directory: std::fs::canonicalize(path).map_err(|_| "cannot resolve fund witness")?,
            _lock: lock,
            checkpoints: cps,
            bytes,
        })
    }
    pub(super) fn checkpoint(&self) -> &Checkpoint {
        self.checkpoints.last().expect("nonempty")
    }
    pub(super) fn contains(&self, cp: &Checkpoint) -> bool {
        self.checkpoints.iter().any(|c| c == cp)
    }
    pub(super) fn ensure_outside(&self, dir: &Path) -> Result<(), String> {
        let d = std::fs::canonicalize(dir).map_err(|_| "cannot resolve fund directory")?;
        if d.starts_with(&self.directory) || self.directory.starts_with(&d) {
            return Err("fund and witness directories must be separate".into());
        }
        Ok(())
    }
    pub(super) fn external(&self, path: &Path, fund: &Path) -> Result<PathBuf, String> {
        crate::orders::archive::external_path(path, &[fund, &self.directory])
    }
    pub(super) fn verify_pin(&self, path: &Path, fund: &Path) -> Result<Checkpoint, String> {
        let cp = Checkpoint::read(&self.external(path, fund)?)?;
        if &cp != self.checkpoint() {
            return Err("fund_checkpoint_freshness_mismatch".into());
        }
        Ok(cp)
    }
    pub(super) fn healthy(&self) -> Result<(), String> {
        let cp = self.checkpoint();
        if read_generation(&self.directory.join(cp_name(cp.sequence)))?.0 != *cp
            || std::fs::symlink_metadata(
                self.directory.join(cp_name(
                    cp.sequence
                        .checked_add(1)
                        .ok_or("witness sequence overflow")?,
                )),
            )
            .is_ok()
        {
            return Err("fund witness changed during ownership".into());
        }
        Ok(())
    }
    pub(super) fn check_data(
        &self,
        bytes: &[u8],
        data: &Data,
        key: &[u8; 32],
        g: &Genesis,
    ) -> Result<(), String> {
        let cp = self.checkpoint();
        if data.witness.as_deref() != Some(cp.witness.as_str()) || data.sequence != cp.sequence {
            return Err("fund witness/source freshness mismatch".into());
        }
        let remote = decrypt(key, &context(g), &self.bytes).map_err(|e| e.to_string())?;
        validate(&remote, g).map_err(|e| e.to_string())?;
        if let Some(r) = &data.recovery {
            let mut normalized = data.clone();
            normalized.recovery = None;
            if r.checkpoint != *cp || normalized != remote {
                return Err("fund restored journal mismatch".into());
            }
        } else if blake3::hash(bytes).to_hex().as_str() != cp.state_hash || remote != *data {
            return Err("fund witness/source freshness mismatch".into());
        }
        Ok(())
    }
    pub(super) fn append(&mut self, bytes: &[u8], data: &Data) -> Result<(), String> {
        self.healthy()?;
        let previous = self.checkpoint();
        if self.checkpoints.len() >= MAX_GENERATIONS
            || previous.sequence.checked_add(1) != Some(data.sequence)
            || data.witness.as_deref() != Some(previous.witness.as_str())
            || data.recovery.is_some()
        {
            return Err("invalid fund witness append".into());
        }
        let cp = Checkpoint {
            version: 1,
            identity: previous.identity.clone(),
            witness: previous.witness.clone(),
            sequence: data.sequence,
            state_hash: blake3::hash(bytes).to_hex().to_string(),
            previous: previous.id()?,
        };
        // Checkpoint and encrypted state are one immutable atomic publication.
        write_generation(&self.directory.join(cp_name(data.sequence)), &cp, bytes)?;
        self.checkpoints.push(cp);
        self.bytes = bytes.to_vec();
        Ok(())
    }
}
