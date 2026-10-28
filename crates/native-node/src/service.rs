//! Exclusive continuous service for a disposable native engineering network.
//! Private atomic exports permit monitoring without polling the live database.
use crate::{
    local,
    pool::{MAX_ENTRIES, MIN_READY, Pool},
    producer,
    proofs::{NativeProver, NativeVerifier},
    state::State,
    store::Store,
    wire::Hash,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const LEASE_FILE: &str = "service.lock";
pub const STATUS_FILE: &str = "service-status.json";
pub const OBSERVATION_TARGET_MS: u64 = 86_400_000;
const EXPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_JSON_BYTES: u64 = 65_536;
const MAX_CLOCK_DRIFT_MS: u64 = 30_000;
const POW_ITERATIONS: u64 = 64;

fn wall_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes epoch".to_owned())?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds supported range".into())
}
fn elapsed_ms(start: Instant, now: Instant) -> u64 {
    now.saturating_duration_since(start)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}
fn private(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}
fn check_directory(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "service directory unavailable")?;
    if !meta.is_dir() || meta.file_type().is_symlink() || !private(&meta) {
        return Err("service directory must be real and private".into());
    }
    Ok(())
}
fn create_directory(path: &Path) -> Result<(), String> {
    let mut options = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        options.mode(0o700);
    }
    match options.create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err("private service directory creation failed".into()),
    }
    check_directory(path)
}
fn new_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| "refusing to overwrite service evidence".into())
}
fn checked_file(path: &Path, write: bool, max: u64) -> Result<File, String> {
    let before = fs::symlink_metadata(path).map_err(|_| "private service file unavailable")?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || !private(&before)
        || before.len() > max
    {
        return Err("invalid private service file".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .open(path)
        .map_err(|_| "private service file open failed")?;
    let opened = file
        .metadata()
        .map_err(|_| "private service file metadata unavailable")?;
    let after =
        fs::symlink_metadata(path).map_err(|_| "private service file changed while opening")?;
    if !same_file(&before, &opened)
        || !same_file(&opened, &after)
        || !after.is_file()
        || after.file_type().is_symlink()
        || !private(&opened)
        || opened.len() > max
    {
        return Err("private service file changed while opening".into());
    }
    Ok(file)
}
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "service directory durability failed".into())
}
fn json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| "service JSON encoding failed")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err("service JSON byte limit".into());
    }
    Ok(bytes)
}
fn write_once(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = json_bytes(value)?;
    let parent = path
        .parent()
        .ok_or("service evidence requires a parent directory")?;
    check_directory(parent)?;
    let mut file = new_file(path)?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "immutable service evidence durability failed")?;
    sync_directory(parent)
}
fn read_json(path: &Path) -> Result<Value, String> {
    let mut file = checked_file(path, false, MAX_JSON_BYTES)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "service JSON read failed")?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err("service JSON byte limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid service JSON".into())
}

/// OS lifetime lock. Opening the file never truncates evidence. All callers
/// acquire this lease before touching the database or constructing a prover.
pub struct Lease {
    _file: File,
}
impl Lease {
    pub fn acquire(directory: &Path) -> Result<Self, String> {
        check_directory(directory)?;
        let path = directory.join(LEASE_FILE);
        let file = match new_file(&path) {
            Ok(file) => file,
            Err(_) => checked_file(&path, true, MAX_JSON_BYTES)?,
        };
        let opened = file
            .metadata()
            .map_err(|_| "service lease metadata unavailable")?;
        let after = fs::symlink_metadata(&path).map_err(|_| "service lease changed")?;
        if !opened.is_file()
            || !same_file(&opened, &after)
            || after.file_type().is_symlink()
            || !private(&opened)
        {
            return Err("invalid service lease".into());
        }
        file.try_lock()
            .map_err(|_| "another service or operation holds the engineering lease")?;
        Ok(Self { _file: file })
    }
}

/// Wall time is admission metadata only; completion always uses Instant.
pub struct ClockGuard {
    started_wall_ms: u64,
    last_wall_ms: u64,
    last_elapsed_ms: u64,
}
impl ClockGuard {
    pub fn new(wall: u64) -> Self {
        Self {
            started_wall_ms: wall,
            last_wall_ms: wall,
            last_elapsed_ms: 0,
        }
    }
    pub fn observe(&mut self, wall: u64, elapsed: u64) -> Result<(), String> {
        if wall < self.last_wall_ms
            || elapsed < self.last_elapsed_ms
            || wall.saturating_sub(self.started_wall_ms).abs_diff(elapsed) > MAX_CLOCK_DRIFT_MS
        {
            return Err("wall-clock discontinuity requires observation restart".into());
        }
        self.last_wall_ms = wall;
        self.last_elapsed_ms = elapsed;
        Ok(())
    }
}
pub fn observation_complete(elapsed: u64) -> bool {
    elapsed >= OBSERVATION_TARGET_MS
}
fn hash_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone)]
pub struct RunIdentity {
    pub run_id: String,
    process_id: u32,
    network: Hash,
    binary_sha256: String,
    configuration_sha256: String,
    started_unix_ms: u64,
}
impl RunIdentity {
    pub fn new(
        network: Hash,
        binary: String,
        configuration: String,
        started_unix_ms: u64,
    ) -> Result<Self, String> {
        if network == [0; 32]
            || !hash_text(&binary)
            || !hash_text(&configuration)
            || started_unix_ms == 0
        {
            return Err("invalid service run identity".into());
        }
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy).map_err(|_| "OS entropy unavailable for service run")?;
        Ok(Self {
            run_id: local::hex(&entropy),
            process_id: std::process::id(),
            network,
            binary_sha256: binary,
            configuration_sha256: configuration,
            started_unix_ms,
        })
    }
    fn receipt(&self) -> Value {
        json!({"schema_version":1,"run_id":self.run_id,"process_id":self.process_id,"network_id":local::hex(&self.network),"binary_sha256":self.binary_sha256,"configuration_sha256":self.configuration_sha256,"started_unix_ms":self.started_unix_ms,"observation_target_ms":OBSERVATION_TARGET_MS})
    }
}
pub struct Status {
    started: Instant,
    observation_started: Option<Instant>,
    observation_stopped: Option<Instant>,
    phase: &'static str,
    height: u64,
    tip: Hash,
    state_fingerprint: Hash,
    cumulative_work: String,
    state_available: bool,
    pow_attempts: u64,
    progress_sequence: u64,
    last_progress_elapsed_ms: u64,
    error_code: Option<&'static str>,
}
impl Status {
    pub fn new(_identity: &RunIdentity) -> Self {
        Self {
            started: Instant::now(),
            observation_started: None,
            observation_stopped: None,
            phase: "starting",
            height: 0,
            tip: [0; 32],
            state_fingerprint: [0; 32],
            cumulative_work: "0".repeat(128),
            state_available: false,
            pow_attempts: 0,
            progress_sequence: 0,
            last_progress_elapsed_ms: 0,
            error_code: None,
        }
    }
    pub fn observation_elapsed_ms(&self, now: Instant) -> u64 {
        let end = self
            .observation_stopped
            .map_or(now, |stopped| stopped.min(now));
        self.observation_started
            .map_or(0, |start| elapsed_ms(start, end))
    }
    fn state(&mut self, state: &State) {
        self.height = state.height;
        self.tip = state.tip;
        self.state_fingerprint = state.fingerprint();
        self.cumulative_work = local::hex(&state.cumulative_work.to_big_endian());
        self.state_available = true;
    }
    fn progress(&mut self) -> Result<(), String> {
        self.progress_sequence = self
            .progress_sequence
            .checked_add(1)
            .ok_or("service progress sequence exhausted")?;
        self.last_progress_elapsed_ms = elapsed_ms(self.started, Instant::now());
        Ok(())
    }
    pub fn to_json(
        &self,
        identity: &RunIdentity,
        now: Instant,
        sequence: u64,
    ) -> Result<Value, String> {
        let observation = self.observation_elapsed_ms(now);
        Ok(
            json!({"schema_version":1,"run_id":identity.run_id,"process_id":identity.process_id,"network_id":local::hex(&identity.network),"binary_sha256":identity.binary_sha256,"configuration_sha256":identity.configuration_sha256,"sequence":sequence,"phase":self.phase,"height":self.height,"tip":local::hex(&self.tip),"state_fingerprint":local::hex(&self.state_fingerprint),"cumulative_work":self.cumulative_work,"state_available":self.state_available,"updated_unix_ms":wall_ms()?,"started_unix_ms":identity.started_unix_ms,"elapsed_monotonic_ms":elapsed_ms(self.started,now),"observation_elapsed_ms":observation,"observation_target_ms":OBSERVATION_TARGET_MS,"observation_complete":observation_complete(observation) && self.error_code.is_none(),"pow_attempts":self.pow_attempts,"progress_sequence":self.progress_sequence,"last_progress_elapsed_ms":self.last_progress_elapsed_ms,"error_code":self.error_code}),
        )
    }
}

fn remove_owned_temporary(path: &Path, identity: &fs::Metadata) {
    if let Ok(current) = fs::symlink_metadata(path)
        && current.is_file()
        && !current.file_type().is_symlink()
        && same_file(identity, &current)
    {
        let _ = fs::remove_file(path);
    }
}

/// Replace only a private regular destination, using a unique owned temporary.
/// Failure removes that temporary only and preserves pre-existing evidence.
pub fn atomic_json(destination: &Path, value: &Value) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or("service export requires a parent directory")?;
    check_directory(parent)?;
    let previous = match fs::symlink_metadata(destination) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && private(&meta) => {
            Some(meta)
        }
        Ok(_) => return Err("invalid existing service export".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("service export metadata unavailable".into()),
    };
    let bytes = json_bytes(value)?;
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).map_err(|_| "OS entropy unavailable for atomic export")?;
    let temporary = parent.join(format!(".native-status-{}.tmp", local::hex(&entropy)));
    let mut file = new_file(&temporary)?;
    let temporary_identity = file
        .metadata()
        .map_err(|_| "atomic export temporary metadata failed")?;
    let result = (|| {
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "atomic service export durability failed")?;
        match (previous.as_ref(), fs::symlink_metadata(destination)) {
            (Some(before), Ok(after))
                if same_file(before, &after)
                    && after.is_file()
                    && !after.file_type().is_symlink() => {}
            (None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("service export destination changed".into()),
        }
        let current =
            fs::symlink_metadata(&temporary).map_err(|_| "atomic export temporary changed")?;
        if !current.is_file()
            || current.file_type().is_symlink()
            || !same_file(&temporary_identity, &current)
        {
            return Err("atomic export temporary changed".into());
        }
        fs::rename(&temporary, destination)
            .map_err(|_| "atomic service export replacement failed")?;
        sync_directory(parent)
    })();
    if result.is_err() {
        remove_owned_temporary(&temporary, &temporary_identity);
    }
    result
}
pub fn write_run_receipt(directory: &Path, identity: &RunIdentity) -> Result<(), String> {
    check_directory(directory)?;
    let runs = directory.join("service-runs");
    create_directory(&runs)?;
    let run = runs.join(&identity.run_id);
    create_directory(&run)?;
    write_once(&run.join("run.json"), &identity.receipt())?;
    sync_directory(&runs)?;
    sync_directory(directory)
}
fn stop_path(directory: &Path, run_id: &str) -> Result<PathBuf, String> {
    if !hash_text(run_id) {
        return Err("invalid stop request run identity".into());
    }
    Ok(directory.join(format!("service-stop-{run_id}.json")))
}
pub fn write_stop_request(directory: &Path, run_id: &str) -> Result<(), String> {
    check_directory(directory)?;
    let value = json!({"schema_version":1,"run_id":run_id,"operation":"stop"});
    let path = stop_path(directory, run_id)?;
    if path.exists() {
        if read_json(&path)? == value {
            return Ok(());
        }
        return Err("existing stop request is inconsistent".into());
    }
    write_once(&path, &value)
}
pub fn stop_requested(directory: &Path, run_id: &str) -> Result<bool, String> {
    let path = stop_path(directory, run_id)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("stop request metadata unavailable".into()),
        Ok(_) => (),
    }
    if read_json(&path)? != json!({"schema_version":1,"run_id":run_id,"operation":"stop"}) {
        return Err("invalid run-bound stop request".into());
    }
    Ok(true)
}
pub fn exported_status(directory: &Path) -> Result<Value, String> {
    check_directory(directory)?;
    read_json(&directory.join(STATUS_FILE))
}

fn sha256_file(path: &Path, private_required: bool) -> Result<String, String> {
    let mut file = if private_required {
        checked_file(path, false, 1024 * 1024)?
    } else {
        let before = fs::symlink_metadata(path).map_err(|_| "binary identity unavailable")?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err("binary identity requires a regular file".into());
        }
        let file = File::open(path).map_err(|_| "binary identity read failed")?;
        if !same_file(
            &before,
            &file
                .metadata()
                .map_err(|_| "binary identity metadata failed")?,
        ) {
            return Err("binary identity changed".into());
        }
        file
    };
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes).map_err(|_| "identity read failed")?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(local::hex(&hash.finalize()))
}

fn calibration_target(hashes: u64, elapsed_ns: u64) -> Result<Hash, String> {
    use siworld_core::pow::Work;
    if hashes == 0 || elapsed_ns == 0 {
        return Err("empty proof-of-work calibration measurement".into());
    }
    let maximum = Work::from_big_endian(&[0xff; 32]);
    let denominator = Work::from(hashes) * Work::from(300_000_000_000u64);
    let target = (maximum * Work::from(elapsed_ns) / denominator)
        .max(Work::one())
        .min(maximum);
    Ok(target.to_big_endian()[32..]
        .try_into()
        .expect("256-bit calibrated target"))
}
/// Bounded initialization-only hash-rate calibration. Resume never recalibrates
/// immutable network work rules, and no timer substitutes for proof of work.
pub fn calibrate() -> Result<(u64, Hash, u64), String> {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|_| "OS entropy unavailable for calibration")?;
    let started = Instant::now();
    let mut hashes = 0u64;
    while hashes < 4096 && (hashes < 8 || started.elapsed() < Duration::from_millis(250)) {
        std::hint::black_box(siworld_core::pow::pow_hash(&seed, hashes, POW_ITERATIONS));
        hashes += 1;
    }
    let ns = started
        .elapsed()
        .as_nanos()
        .try_into()
        .map_err(|_| "calibration elapsed range")?;
    Ok((
        wall_ms()? / 1000,
        calibration_target(hashes, ns)?,
        POW_ITERATIONS,
    ))
}
fn check_workers(rayon: Option<&str>, hiding: Option<&str>) -> Result<(), String> {
    if rayon != Some("4") || hiding != Some("2") {
        return Err("continuous production requires RAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2".into());
    }
    Ok(())
}

struct Control {
    directory: PathBuf,
    identity: RunIdentity,
    status: Mutex<Status>,
    clock: Mutex<ClockGuard>,
    sequence: AtomicU64,
    failed: AtomicBool,
    shutdown: AtomicBool,
}
impl Control {
    fn sequence(&self) -> Result<u64, String> {
        self.sequence
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map_err(|_| "service export sequence exhausted".into())
    }
    fn checked_wall(&self) -> Result<u64, String> {
        let mut clock = self
            .clock
            .lock()
            .map_err(|_| "service clock lock poisoned")?;
        let wall = wall_ms()?;
        let elapsed = {
            let status = self
                .status
                .lock()
                .map_err(|_| "service status lock poisoned")?;
            elapsed_ms(status.started, Instant::now())
        };
        clock.observe(wall, elapsed)?;
        Ok(wall)
    }
    fn export(&self) -> Result<Value, String> {
        self.checked_wall()?;
        let status = self
            .status
            .lock()
            .map_err(|_| "service status lock poisoned")?;
        let value = status.to_json(&self.identity, Instant::now(), self.sequence()?)?;
        atomic_json(&self.directory.join(STATUS_FILE), &value)?;
        Ok(value)
    }
    fn event(&self, event: &'static str) -> Result<(), String> {
        let status = self
            .status
            .lock()
            .map_err(|_| "service status lock poisoned")?;
        let value = json!({"schema_version":1,"run_id":self.identity.run_id,"sequence":self.sequence()?,"event":event,"height":status.height,"tip":local::hex(&status.tip),"elapsed_monotonic_ms":elapsed_ms(status.started,Instant::now()),"error_code":status.error_code});
        let path = self.directory.join("service-events.jsonl");
        let mut file = match new_file(&path) {
            Ok(file) => file,
            Err(_) => checked_file(&path, true, u64::MAX)?,
        };
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::End(0))
            .map_err(|_| "service event append unavailable")?;
        file.write_all(&json_bytes(&value)?)
            .and_then(|_| file.sync_all())
            .map_err(|_| "service event durability failed")?;
        sync_directory(&self.directory)
    }
    fn phase(&self, phase: &'static str) -> Result<(), String> {
        {
            let mut status = self
                .status
                .lock()
                .map_err(|_| "service status lock poisoned")?;
            status.phase = phase;
            if phase == "stopping" && status.observation_stopped.is_none() {
                status.observation_stopped = Some(Instant::now());
            }
            if matches!(phase, "replaying" | "committing" | "stopping") {
                status.state_available = false;
            }
        }
        self.event("phase_changed")
    }
    fn state(&self, state: &State) -> Result<(), String> {
        self.status
            .lock()
            .map_err(|_| "service status lock poisoned")?
            .state(state);
        Ok(())
    }
    fn progress(&self) -> Result<(), String> {
        self.status
            .lock()
            .map_err(|_| "service status lock poisoned")?
            .progress()
    }
    fn stop(&self) -> Result<bool, String> {
        if self.failed.load(Ordering::SeqCst) {
            return Err("service exporter or clock failed".into());
        }
        stop_requested(&self.directory, &self.identity.run_id)
    }
    fn fail(&self, code: &'static str) {
        self.failed.store(true, Ordering::SeqCst);
        if let Ok(mut status) = self.status.lock() {
            status.phase = "error";
            if status.observation_stopped.is_none() {
                status.observation_stopped = Some(Instant::now());
            }
            status.error_code = Some(code);
        }
    }
}
fn exporter(control: Arc<Control>) {
    while !control.shutdown.load(Ordering::SeqCst) {
        if control.export().is_err() {
            control.fail("observation_export_failed");
            break;
        }
        std::thread::park_timeout(EXPORT_INTERVAL);
    }
}
fn verify_rewards(directory: &Path, store: &Store, control: &Control) -> Result<(), String> {
    for height in 1..=store.state().height {
        let block = store.block(height)?;
        let id = block.id()?;
        let secret = local::read_reward(directory, &id)?;
        producer::validate_reward_secret(&block, &secret)?;
        control.progress()?;
    }
    Ok(())
}
fn refill(
    state: &State,
    prover: &NativeProver,
    verifier: &NativeVerifier,
    pool: &mut Pool,
    control: &Control,
    target: usize,
) -> Result<bool, String> {
    pool.prune(state)?;
    while pool.len() < target {
        if control.stop()? {
            return Ok(false);
        }
        let value = producer::prepare_padding(state, prover)?;
        pool.insert(state, value, verifier)?;
        control.progress()?;
    }
    Ok(true)
}
/// Real nonce search. The full canonical proof-bearing body is seeded once per
/// timestamp change; every iteration hashes the cached seed and nonce only.
fn mine(
    block: &mut crate::wire::Block,
    state: &State,
    control: &Control,
    done: &AtomicBool,
) -> Result<bool, String> {
    let result = (|| {
        let mut seed = block.pow_seed()?;
        let mut since_progress = 0u64;
        let mut progress_at = Instant::now();
        loop {
            let work = siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations);
            since_progress = since_progress
                .checked_add(1)
                .ok_or("proof-of-work progress exhausted")?;
            let found = siworld_core::pow::meets_target(&work, &block.target);
            if found || progress_at.elapsed() >= Duration::from_millis(500) {
                {
                    let mut status = control
                        .status
                        .lock()
                        .map_err(|_| "service status lock poisoned")?;
                    status.pow_attempts = status
                        .pow_attempts
                        .checked_add(since_progress)
                        .ok_or("proof-of-work counter exhausted")?;
                    status.progress()?;
                }
                since_progress = 0;
                progress_at = Instant::now();
                if control.stop()? {
                    return Ok(false);
                }
                let timestamp = control.checked_wall()? / 1000;
                if found {
                    return Ok(true);
                }
                if timestamp > block.timestamp {
                    block.timestamp = timestamp.max(
                        state
                            .median_time_past()
                            .checked_add(1)
                            .ok_or("timestamp exhausted")?,
                    );
                    seed = block.pow_seed()?;
                }
            }
            block.nonce = block
                .nonce
                .checked_add(1)
                .ok_or("proof-of-work nonce exhausted")?;
        }
    })();
    done.store(true, Ordering::SeqCst);
    result
}
fn continuous(directory: &Path, control: &Control) -> Result<(), String> {
    let config = local::load(directory)?;
    if config.fixture {
        return Err(
            "continuous production rejects fixture work rules; initialize a new ASERT network"
                .into(),
        );
    }
    let verifier = NativeVerifier::new()?;
    control.phase("replaying")?;
    let mut store = Store::open_existing(directory.join("chain.redb"), config.clone(), &verifier)?;
    verify_rewards(directory, &store, control)?;
    control.state(store.state())?;
    control.phase("preparing")?;
    let prover = NativeProver::new()?;
    let mut pool = Pool::new(config.network);
    if refill(
        store.state(),
        &prover,
        &verifier,
        &mut pool,
        control,
        MIN_READY,
    )? {
        {
            let mut status = control
                .status
                .lock()
                .map_err(|_| "service status lock poisoned")?;
            status.observation_started = Some(Instant::now());
            status.progress()?;
        }
        loop {
            if control.stop()? {
                break;
            }
            control.phase("refilling")?;
            if !refill(
                store.state(),
                &prover,
                &verifier,
                &mut pool,
                control,
                MIN_READY,
            )? {
                break;
            }
            let positions = pool.take(store.state(), MIN_READY)?;
            let timestamp = (control.checked_wall()? / 1000).max(
                store
                    .state()
                    .median_time_past()
                    .checked_add(1)
                    .ok_or("timestamp exhausted")?,
            );
            let mut produced = producer::assemble(store.state(), &prover, positions, timestamp)?;
            if control.stop()? {
                break;
            }
            control.phase("mining")?;
            let done = AtomicBool::new(false);
            let mined = std::thread::scope(|scope| {
                let block = &mut produced.block;
                let state = store.state();
                let done_ref = &done;
                let worker = scope.spawn(move || mine(block, state, control, done_ref));
                // Proof generation runs ahead during real work search. A single
                // resident prover owns its data; independent admission is serial.
                let fill_result = (|| {
                    while pool.len() < MAX_ENTRIES
                        && pool.can_grow()
                        && !done.load(Ordering::SeqCst)
                    {
                        if control.stop()? {
                            break;
                        }
                        let value = producer::prepare_padding(state, &prover)?;
                        pool.insert(state, value, &verifier)?;
                        control.progress()?;
                    }
                    Ok::<(), String>(())
                })();
                if fill_result.is_err() {
                    control.fail("private_queue_failed");
                }
                let mined = worker
                    .join()
                    .map_err(|_| "proof-of-work worker panicked".to_owned())?;
                fill_result?;
                mined
            })?;
            if !mined || control.stop()? {
                break;
            }
            control.phase("committing")?;
            let id = produced.block.id()?;
            producer::validate_reward_secret(&produced.block, &produced.reward_secret)?;
            // Receipt is durable before its block can become accepted. Failure
            // leaves evidence for review and never restores an older database.
            local::save_reward(directory, &id, &produced.reward_secret)?;
            store.append(&produced.block, &verifier)?;
            control.state(store.state())?;
            control.progress()?;
            control.event("block_accepted")?;
            pool.prune(store.state())?;
        }
    }
    control.phase("stopping")?;
    let expected = (
        store.state().height,
        store.state().tip,
        store.state().fingerprint(),
        store.state().cumulative_work,
    );
    drop(store);
    // Graceful stop requires a full independent replay and every reward receipt.
    let replayed = Store::open_existing(directory.join("chain.redb"), config, &verifier)?;
    verify_rewards(directory, &replayed, control)?;
    let actual = (
        replayed.state().height,
        replayed.state().tip,
        replayed.state().fingerprint(),
        replayed.state().cumulative_work,
    );
    if actual != expected {
        return Err("graceful-stop replay changed the accepted state".into());
    }
    control.state(replayed.state())?;
    control.phase("stopped")?;
    control.event("service_stopped")
}

/// Run until an explicit run-bound graceful stop request or an integrity error.
/// The caller is responsible for launching this on the authorized deployment host.
pub fn run(directory: &Path) -> Result<(), String> {
    let _lease = Lease::acquire(directory)?;
    let config = local::load(directory)?;
    if config.fixture {
        return Err("continuous production requires an ASERT engineering configuration".into());
    }
    let rayon = std::env::var("RAYON_NUM_THREADS").ok();
    let hiding = std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").ok();
    check_workers(rayon.as_deref(), hiding.as_deref())?;
    let binary = std::env::current_exe().map_err(|_| "running binary identity unavailable")?;
    let identity = RunIdentity::new(
        config.network,
        sha256_file(&binary, false)?,
        sha256_file(&directory.join("engineering-network.bin"), true)?,
        wall_ms()?,
    )?;
    write_run_receipt(directory, &identity)?;
    let status = Status::new(&identity);
    let control = Arc::new(Control {
        directory: directory.to_owned(),
        clock: Mutex::new(ClockGuard::new(identity.started_unix_ms)),
        identity,
        status: Mutex::new(status),
        sequence: AtomicU64::new(0),
        failed: AtomicBool::new(false),
        shutdown: AtomicBool::new(false),
    });
    let export_control = Arc::clone(&control);
    let export_thread = std::thread::spawn(move || exporter(export_control));
    let result = (|| {
        let workers = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .thread_name(|index| format!("native-prover-{index}"))
            .build()
            .map_err(|_| "resident prover worker-pool creation failed")?;
        workers.install(|| continuous(directory, &control))
    })();
    if result.is_err() {
        control.fail("service_operation_failed");
        let _ = control.event("service_error");
    }
    control.shutdown.store(true, Ordering::SeqCst);
    export_thread.thread().unpark();
    if export_thread.join().is_err() {
        control.fail("observation_export_panicked");
        return Err("observation exporter panicked".into());
    }
    // A clock/export failure remains a failed run. Final evidence is written
    // without weakening the monotonic completion or clock guard.
    let result = if control.failed.load(Ordering::SeqCst) && result.is_ok() {
        Err("service observation failed".into())
    } else {
        result
    };
    let final_value = {
        let status = control
            .status
            .lock()
            .map_err(|_| "service status lock poisoned")?;
        status.to_json(&control.identity, Instant::now(), control.sequence()?)?
    };
    atomic_json(&directory.join(STATUS_FILE), &final_value)?;
    write_once(
        &directory
            .join("service-runs")
            .join(&control.identity.run_id)
            .join("final.json"),
        &final_value,
    )?;
    result
}
pub fn request_stop(directory: &Path) -> Result<(), String> {
    let status = exported_status(directory)?;
    let run = status
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or("service status has no run identity")?;
    if !matches!(
        status.get("phase").and_then(Value::as_str),
        Some(
            "starting"
                | "replaying"
                | "preparing"
                | "refilling"
                | "mining"
                | "committing"
                | "stopping"
        )
    ) {
        return Err("no active service run is exported".into());
    }
    write_stop_request(directory, run)
}

#[cfg(test)]
mod tests;
