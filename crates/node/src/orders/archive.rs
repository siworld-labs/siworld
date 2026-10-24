//! Locked, immutable archive generations. Private local format, not consensus.
use super::*;
use crate::backup::{publish_directory, Staging};
use crate::secrets::write_private_bytes;
use std::fs;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub checkpoint: Checkpoint,
    pub ledger_bytes: u64,
    pub ledger_blake3: String,
    pub witness_count: u64,
    pub witness_blake3: String,
}
impl Manifest {
    pub fn id(&self) -> Result<String, String> {
        self.validate()?;
        Ok(
            blake3::derive_key("siworld order archive manifest v1", &json(self)?)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
    fn validate(&self) -> Result<(), String> {
        self.checkpoint.validate()?;
        if self.version != 1
            || !(64..=MAX_FILE as u64).contains(&self.ledger_bytes)
            || self.witness_count != self.checkpoint.sequence + 1
            || [&self.ledger_blake3, &self.witness_blake3]
                .iter()
                .any(|s| parse_hex32(s).is_none() || s.to_lowercase() != **s)
        {
            return Err("invalid order archive manifest".into());
        }
        Ok(())
    }
}
pub(crate) fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|_| "cannot encode retention data".into())
}
/// Resolve parent aliases and reject known managed trees before writing an
/// auxiliary reference. Physical separation remains an operator responsibility.
pub fn external_path(path: &Path, excluded: &[&Path]) -> Result<PathBuf, String> {
    external_file(path, excluded)
}
pub(crate) fn sync_dir(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "cannot sync archive directory".into())
}
pub(crate) fn private_dir(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "cannot inspect archive directory")?;
    if !m.is_dir() {
        return Err("archive requires regular directories".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err("archive directories must be owner-only".into());
        }
    }
    Ok(())
}
pub(crate) fn make_dir(path: &Path) -> Result<(), String> {
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
        .map_err(|_| "cannot create private archive directory".into())
}
pub(crate) fn stage_for(output: &Path) -> Result<Staging, String> {
    if fs::symlink_metadata(output).is_ok() {
        return Err("archive destination must not exist".into());
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
    let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let p = parent.join(format!(".si-archive-{name}.tmp"));
    make_dir(&p)?;
    Ok(Staging(Some(p)))
}
pub(crate) fn publish(stage: &mut Staging, output: &Path) -> Result<(), String> {
    let p = stage.0.as_ref().expect("unpublished stage");
    sync_dir(p)?;
    publish_directory(p, output)?;
    stage.0 = None;
    sync_dir(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .map_err(|_| "archive published; parent sync failed; inspect before retry".into())
}
fn exact_entries(path: &Path, expected: &BTreeSet<String>, allow_lock: bool) -> Result<(), String> {
    private_dir(path)?;
    let mut seen = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|_| "cannot list archive")? {
        let entry = entry.map_err(|_| "cannot list archive")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid archive file name")?;
        if allow_lock && name == ".wallet.lock" {
            continue;
        }
        if seen.len() >= expected.len() || !expected.contains(&name) || !seen.insert(name) {
            return Err("unexpected archive entry".into());
        }
    }
    if &seen != expected {
        return Err("missing archive entry".into());
    }
    Ok(())
}
fn witness_hash(root: &Path, cp: &Checkpoint) -> Result<String, String> {
    let expected = (0..=cp.sequence).map(Checkpoint::filename).collect();
    exact_entries(root, &expected, true)?;
    let mut h = blake3::Hasher::new_derive_key("siworld order archive witness bytes v1");
    for seq in 0..=cp.sequence {
        let bytes = read_private_bytes(&root.join(Checkpoint::filename(seq)), 2048)?;
        let c: Checkpoint =
            serde_json::from_slice(&bytes).map_err(|_| "invalid archived checkpoint")?;
        c.validate()?;
        if c.sequence != seq
            || c.ledger_id != cp.ledger_id
            || c.genesis != cp.genesis
            || c.owner != cp.owner
            || (seq == cp.sequence && c != *cp)
        {
            return Err("archive witness identity mismatch".into());
        }
        h.update(&seq.to_le_bytes());
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    Ok(h.finalize().to_hex().to_string())
}
/// Integrity/read-back checks only: an independent receiver needs no password.
/// Only password-authenticated restoration checks the ledger's event preimages.
pub fn inspect(path: &Path) -> Result<Manifest, String> {
    exact_entries(
        path,
        &["ledger".into(), "witness".into(), "manifest.json".into()].into(),
        false,
    )?;
    exact_entries(&path.join("ledger"), &["orders.enc".into()].into(), true)?;
    let m: Manifest =
        serde_json::from_slice(&read_private_bytes(&path.join("manifest.json"), 4096)?)
            .map_err(|_| "invalid order archive manifest")?;
    m.validate()?;
    let bytes = read_private_bytes(&path.join("ledger/orders.enc"), MAX_FILE)?;
    if bytes.len() as u64 != m.ledger_bytes
        || blake3::hash(&bytes).to_hex().as_str() != m.ledger_blake3
        || witness_hash(&path.join("witness"), &m.checkpoint)? != m.witness_blake3
    {
        return Err("order archive digest mismatch".into());
    }
    Ok(m)
}
fn authenticated(path: &Path, password: &str) -> Result<Manifest, String> {
    let m = inspect(path)?;
    let data = decrypt(
        &read_private_bytes(&path.join("ledger/orders.enc"), MAX_FILE)?,
        password,
    )?;
    let cps = checkpoints(&data)?;
    if cps.last() != Some(&m.checkpoint) {
        return Err("archive ledger/checkpoint mismatch".into());
    }
    for cp in cps {
        if Checkpoint::read(&path.join("witness").join(Checkpoint::filename(cp.sequence)))? != cp {
            return Err("archive witness/ledger mismatch".into());
        }
    }
    Ok(m)
}
pub fn check(path: &Path, password: &str) -> Result<Manifest, String> {
    authenticated(path, password)
}
/// Copy only the fixed, verified format. No paths from a manifest are followed.
pub(crate) fn copy_into(source: &Path, destination: &Path) -> Result<Manifest, String> {
    let expected = inspect(source)?;
    make_dir(destination)?;
    make_dir(&destination.join("ledger"))?;
    make_dir(&destination.join("witness"))?;
    write_private_bytes(
        &destination.join("ledger/orders.enc"),
        &read_private_bytes(&source.join("ledger/orders.enc"), MAX_FILE)?,
    )?;
    for seq in 0..expected.witness_count {
        let name = Checkpoint::filename(seq);
        write_private_bytes(
            &destination.join("witness").join(&name),
            &read_private_bytes(&source.join("witness").join(name), 2048)?,
        )?;
    }
    write_private_bytes(&destination.join("manifest.json"), &json(&expected)?)?;
    sync_dir(&destination.join("ledger"))?;
    sync_dir(&destination.join("witness"))?;
    sync_dir(destination)?;
    if inspect(destination)? != expected {
        return Err("archive copy read-back mismatch".into());
    }
    Ok(expected)
}
impl OrderLedger {
    /// The exclusive source locks remain held for capture, validation, read-back
    /// and atomic publication. Every published generation contains both sources.
    pub fn archive(&self, output: &Path, previous: Option<&Path>) -> Result<Manifest, String> {
        self.archive_with_hook(output, previous, || Ok(()))
    }
    fn archive_with_hook(
        &self,
        output: &Path,
        previous: Option<&Path>,
        hook: impl FnOnce() -> Result<(), String>,
    ) -> Result<Manifest, String> {
        let cp = self.checkpoint()?;
        let output = external_file(output, &[&self.dir, &self.witness])?;
        if let Some(p) = previous {
            let previous = self.read_external_checkpoint(p)?;
            if self.cps.get(previous.sequence as usize) != Some(&previous) {
                return Err("order_checkpoint_not_ancestor".into());
            }
        }
        let mut stage = stage_for(&output)?;
        let p = stage.0.as_ref().unwrap();
        make_dir(&p.join("ledger"))?;
        make_dir(&p.join("witness"))?;
        let bytes = read_private_bytes(&self.dir.join("orders.enc"), MAX_FILE)?;
        write_private_bytes(&p.join("ledger/orders.enc"), &bytes)?;
        for c in &self.cps {
            let name = Checkpoint::filename(c.sequence);
            let raw = read_private_bytes(&self.witness.join(&name), 2048)?;
            if Checkpoint::read(&self.witness.join(&name))? != *c {
                return Err("source witness changed during capture".into());
            }
            write_private_bytes(&p.join("witness").join(name), &raw)?;
        }
        let manifest = Manifest {
            version: 1,
            checkpoint: cp,
            ledger_bytes: bytes.len() as u64,
            ledger_blake3: blake3::hash(&bytes).to_hex().to_string(),
            witness_count: self.cps.len() as u64,
            witness_blake3: witness_hash(&p.join("witness"), self.cps.last().unwrap())?,
        };
        write_private_bytes(&p.join("manifest.json"), &json(&manifest)?)?;
        if authenticated(p, &self.password)? != manifest {
            return Err("archive authentication mismatch".into());
        }
        sync_dir(&p.join("ledger"))?;
        sync_dir(&p.join("witness"))?;
        hook()?;
        publish(&mut stage, &output)?;
        if inspect(&output)? != manifest {
            return Err("published archive read-back mismatch".into());
        }
        Ok(manifest)
    }
}
/// Publish one new root containing sibling ledger/witness directories. Existing
/// sources are never replaced; expected freshness must come from outside them.
pub fn restore(
    source: &Path,
    output: &Path,
    password: &str,
    expected: &Checkpoint,
) -> Result<Manifest, String> {
    let m = authenticated(source, password)?;
    expected.validate()?;
    if &m.checkpoint != expected {
        return Err("order_ledger_freshness_mismatch".into());
    }
    let source = fs::canonicalize(source).map_err(|_| "cannot inspect archive source")?;
    let output = external_file(output, &[&source])?;
    let mut stage = stage_for(&output)?;
    // copy_into creates its destination; use a child then publish that child.
    let p = stage.0.as_ref().unwrap().join("generation");
    if copy_into(&source, &p)? != m || authenticated(&p, password)? != m {
        return Err("restored archive changed".into());
    }
    publish_directory(&p, &output)?;
    sync_dir(output.parent().unwrap_or(Path::new(".")))
        .map_err(|_| "order restore published; parent sync failed; inspect before retry")?;
    stage
        .0
        .take()
        .map(fs::remove_dir_all)
        .transpose()
        .map_err(|_| "restore published; staging cleanup failed")?;
    Ok(m)
}
pub fn restore_file(
    source: &Path,
    output: &Path,
    password: &str,
    pin: &Path,
) -> Result<Manifest, String> {
    let source = fs::canonicalize(source).map_err(|_| "cannot inspect archive source")?;
    let pin = external_file(pin, &[&source])?;
    restore(&source, output, password, &Checkpoint::read(&pin)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_failure_before_publication_does_not_change_sources_or_publish() {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let root = std::env::temp_dir().join(format!("si-archive-test-{name}"));
        make_dir(&root).unwrap();
        let cleanup = Staging(Some(root.clone()));
        make_dir(&root.join("ledger")).unwrap();
        make_dir(&root.join("witness")).unwrap();
        let l = OrderLedger::create(
            &root.join("ledger"),
            &root.join("witness"),
            "temporary archive test password",
            Digest([1; 32]),
            Digest([2; 32]),
        )
        .unwrap();
        let output = root.join("archive");
        let before = fs::read(l.dir.join("orders.enc")).unwrap();
        assert!(l
            .archive_with_hook(&output, None, || Err("injected interruption".into()))
            .is_err());
        assert!(!output.exists());
        assert_eq!(fs::read(l.dir.join("orders.enc")).unwrap(), before);
        assert!(!fs::read_dir(&root).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".si-archive-")));
        drop(l);
        drop(cleanup);
    }
}
