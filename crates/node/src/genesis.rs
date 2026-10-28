//! Testnet genesis file.
//!
//! Every node of a testnet starts from the same JSON file: the network name,
//! the consensus parameters, the development fund's keys if the testnet has
//! a fund, and the funds allocated at genesis, which let participants pay
//! before any miner package matures. Allocated packages are public: their
//! randomness is derived from the genesis id, so anyone can rebuild the
//! genesis tree from the file, and only the owner can spend them.
//!
//! The genesis id commits to the whole file. It names the network on the wire
//! and in the data directory, and it is the parent of block 1, so a block of
//! one testnet is never valid on another.

use serde::{Deserialize, Serialize};
use siworld_core::codec::MAX_SLOTS;
use siworld_core::params::{
    ChainParams, DevFundKeys, ProofSystemKind, MIN_PACKAGE_DEPOSIT, VERIFYING_KEY_LEN,
};
use siworld_core::{Condition, Digest, Note};
use siworld_crypto::{domain_hash, expand, is_canonical, note_commitment};
use siworld_state::{ChainState, RecentRoots};

use crate::amount::{format_sip, parse_sip};
use crate::{hex, parse_hex, parse_hex32};

/// Most allocations a genesis file may list.
pub const MAX_ALLOCATIONS: usize = 10_000;

/// The file as written: hexadecimal digests and decimal SIP amounts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisFile {
    /// Lowercase letters, digits and `-`, at most 32 characters.
    pub network: String,
    /// Unix seconds; ASERT schedules blocks from it.
    pub timestamp: u64,
    /// Target seconds between blocks.
    pub block_time: u64,
    /// Sequential BLAKE3 hashes per nonce.
    pub pow_iterations: u64,
    /// Target of block 1, 64 hexadecimal digits, big-endian.
    pub target: String,
    /// Slots per block.
    pub container_size: u32,
    /// The proof system of the network's blocks.
    pub proofs: ProofsFile,
    /// The development fund's verifying keys; absent, the fund accrues but
    /// nobody can pay out of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_fund: Option<DevFundFile>,
    pub allocations: Vec<AllocationFile>,
}

/// [`ProofSystemKind`] as the file spells it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofsFile {
    /// Mock proofs: the node checks everything but the zero-knowledge
    /// relation. Coins of such a network can be forged.
    Mock,
    /// Plonky3 STARK proofs (`siworld-prover`).
    Plonky3,
}

impl ProofsFile {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mock" => Some(Self::Mock),
            "plonky3" => Some(Self::Plonky3),
            _ => None,
        }
    }

    pub fn kind(self) -> ProofSystemKind {
        match self {
            Self::Mock => ProofSystemKind::Mock,
            Self::Plonky3 => ProofSystemKind::Plonky3,
        }
    }

    pub fn of(kind: ProofSystemKind) -> Self {
        match kind {
            ProofSystemKind::Mock => Self::Mock,
            ProofSystemKind::Plonky3 => Self::Plonky3,
        }
    }
}

impl std::fmt::Display for ProofsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Mock => "mock",
            Self::Plonky3 => "plonky3",
        })
    }
}

/// The two ML-DSA-65 verifying keys, each 3,904 hexadecimal digits.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevFundFile {
    pub direct: String,
    pub lock: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationFile {
    /// The recipient's owner digest, 64 hexadecimal digits.
    pub owner: String,
    /// In SIP, for example `"1000"` or `"0.5"`.
    pub amount: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GenesisError {
    Json(String),
    BadNetwork,
    BadTarget,
    BadBlockTime,
    /// A development-fund key is not 3,904 hexadecimal digits.
    BadDevFundKey,
    BadPowIterations,
    BadContainerSize,
    TooManyAllocations,
    /// Allocation `i` has an owner that is not 64 hex digits of a canonical digest.
    BadOwner(usize),
    /// Allocation `i` has an amount that does not parse or is below the minimum
    /// deposit.
    BadAmount(usize),
    /// The allocations sum to more than `u64::MAX` atoms.
    TotalOverflow,
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid genesis JSON: {e}"),
            Self::BadNetwork => {
                f.write_str("network must be 1-32 lowercase letters, digits or '-'")
            }
            Self::BadTarget => f.write_str("target must be 64 hexadecimal digits, not zero"),
            Self::BadBlockTime => f.write_str("block_time must be at least 1"),
            Self::BadDevFundKey => write!(
                f,
                "dev_fund keys must be {} hexadecimal digits each",
                2 * VERIFYING_KEY_LEN
            ),
            Self::BadPowIterations => f.write_str("pow_iterations must be at least 1"),
            Self::BadContainerSize => {
                write!(f, "container_size must be a power of two up to {MAX_SLOTS}")
            }
            Self::TooManyAllocations => write!(f, "at most {MAX_ALLOCATIONS} allocations"),
            Self::BadOwner(i) => write!(f, "allocation {i}: owner is not a valid owner digest"),
            Self::BadAmount(i) => write!(
                f,
                "allocation {i}: amount must be a SIP amount of at least {}",
                format_sip(MIN_PACKAGE_DEPOSIT)
            ),
            Self::TotalOverflow => f.write_str("allocations overflow the supply"),
        }
    }
}

impl std::error::Error for GenesisError {}

/// A checked genesis file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Genesis {
    pub network: String,
    pub params: ChainParams,
    /// (owner, atoms), in genesis-tree order.
    pub allocations: Vec<(Digest, u64)>,
    /// Commits to everything above.
    pub id: Digest,
}

impl Genesis {
    pub fn from_json(text: &str) -> Result<Self, GenesisError> {
        let file: GenesisFile =
            serde_json::from_str(text).map_err(|e| GenesisError::Json(e.to_string()))?;
        Self::from_file(&file)
    }

    pub fn from_file(file: &GenesisFile) -> Result<Self, GenesisError> {
        let name_ok = !file.network.is_empty()
            && file.network.len() <= 32
            && file
                .network
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok {
            return Err(GenesisError::BadNetwork);
        }
        let target = parse_hex32(&file.target)
            .filter(|t| *t != Digest::ZERO)
            .ok_or(GenesisError::BadTarget)?;
        if file.block_time == 0 {
            return Err(GenesisError::BadBlockTime);
        }
        if file.pow_iterations == 0 {
            return Err(GenesisError::BadPowIterations);
        }
        if !file.container_size.is_power_of_two() || file.container_size as usize > MAX_SLOTS {
            return Err(GenesisError::BadContainerSize);
        }
        if file.allocations.len() > MAX_ALLOCATIONS {
            return Err(GenesisError::TooManyAllocations);
        }
        let mut total = 0u64;
        let allocations = file
            .allocations
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let owner = parse_hex32(&a.owner)
                    .filter(is_canonical)
                    .ok_or(GenesisError::BadOwner(i))?;
                let amount = parse_sip(&a.amount)
                    .filter(|v| *v >= MIN_PACKAGE_DEPOSIT)
                    .ok_or(GenesisError::BadAmount(i))?;
                total = total
                    .checked_add(amount)
                    .ok_or(GenesisError::TotalOverflow)?;
                Ok((owner, amount))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dev_fund_keys = match &file.dev_fund {
            Some(keys) => Some(DevFundKeys {
                direct: parse_key(&keys.direct)?,
                lock: parse_key(&keys.lock)?,
            }),
            None => None,
        };
        let params = ChainParams {
            proofs: file.proofs.kind(),
            container_size: file.container_size,
            pow_iterations: file.pow_iterations,
            target_block_time: file.block_time,
            genesis_target: target.0,
            genesis_timestamp: file.timestamp,
            dev_fund_keys,
            ..ChainParams::mainnet()
        };
        let id = genesis_id(&file.network, &params, &allocations);
        // Everything signed for this chain names it by its genesis id.
        let params = ChainParams {
            chain_id: id,
            ..params
        };
        Ok(Self {
            network: file.network.clone(),
            params,
            allocations,
            id,
        })
    }

    /// The file this genesis was read from, in canonical form.
    pub fn to_file(&self) -> GenesisFile {
        GenesisFile {
            network: self.network.clone(),
            timestamp: self.params.genesis_timestamp,
            block_time: self.params.target_block_time,
            pow_iterations: self.params.pow_iterations,
            target: hex(&Digest(self.params.genesis_target)),
            container_size: self.params.container_size,
            proofs: ProofsFile::of(self.params.proofs),
            dev_fund: self.params.dev_fund_keys.as_ref().map(|k| DevFundFile {
                direct: hex_bytes(&k.direct),
                lock: hex_bytes(&k.lock),
            }),
            allocations: self
                .allocations
                .iter()
                .map(|(owner, amount)| AllocationFile {
                    owner: hex(owner),
                    amount: format_sip(*amount),
                })
                .collect(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_file()).expect("plain data serializes") + "\n"
    }

    /// The allocated packages, in genesis-tree order.
    pub fn notes(&self) -> Vec<Note> {
        self.allocations
            .iter()
            .enumerate()
            .map(|(i, &(owner, value))| Note {
                owner,
                value,
                cond: Condition { unlock_height: 0 },
                rho: expand(&self.id, "genesis rho", i as u64),
                rseed: expand(&self.id, "genesis rseed", i as u64),
            })
            .collect()
    }

    /// The chain state before block 1. Its tip is the genesis id.
    pub fn state(&self) -> ChainState {
        // Testnet allocations are part of the checked genesis file and its
        // network id. Initialize through public state operations rather than
        // enabling the state crate's test-only constructor in normal builds.
        let mut state = ChainState::genesis(&self.params);
        for note in self.notes() {
            state
                .commitments
                .append(note_commitment(&note))
                .expect("checked testnet allocations fit the commitment tree");
        }
        state.anchors = RecentRoots::new(self.params.anchor_window);
        state.anchors.push(state.commitments.root(), 0);
        state.tip = self.id;
        state
    }
}

fn parse_key(s: &str) -> Result<[u8; VERIFYING_KEY_LEN], GenesisError> {
    parse_hex(s).ok_or(GenesisError::BadDevFundKey)
}

/// Lowercase hexadecimal of any byte string.
pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn genesis_id(network: &str, params: &ChainParams, allocations: &[(Digest, u64)]) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(network.len() as u32).to_le_bytes());
    bytes.extend_from_slice(network.as_bytes());
    for x in [
        params.genesis_timestamp,
        params.target_block_time,
        params.pow_iterations,
        u64::from(params.container_size),
        params.commitment_tree_depth as u64,
        params.anchor_window as u64,
    ] {
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    bytes.extend_from_slice(&params.genesis_target);
    bytes.push(params.proofs.to_byte());
    bytes.extend_from_slice(&(allocations.len() as u32).to_le_bytes());
    for (owner, amount) in allocations {
        bytes.extend_from_slice(owner.as_bytes());
        bytes.extend_from_slice(&amount.to_le_bytes());
    }
    if let Some(keys) = &params.dev_fund_keys {
        bytes.extend_from_slice(&keys.direct);
        bytes.extend_from_slice(&keys.lock);
    }
    domain_hash("siworld genesis v0", &[&bytes])
}

/// The target at which a miner trying `nonces_per_second` nonces finds a
/// block every `block_time` seconds on average: ⌊2^256 / (rate · time)⌋ − 1,
/// at least 1.
pub fn calibrated_target(nonces_per_second: u64, block_time: u64) -> [u8; 32] {
    use siworld_consensus::U512;
    let expected = U512::from(nonces_per_second.max(1)) * U512::from(block_time.max(1));
    let target = ((U512::one() << 256usize) / expected)
        .saturating_sub(U512::one())
        .max(U512::one());
    let ceiling = U512::from_big_endian(&[0xff; 32]);
    let bytes = target.min(ceiling).to_big_endian();
    bytes[32..].try_into().expect("at most 256 bits")
}

#[cfg(test)]
mod tests {
    use siworld_crypto::SpendKey;

    use super::*;

    type Change = fn(&mut GenesisFile);

    #[test]
    fn allocated_state_matches_the_existing_testnet_genesis() {
        for empty in [false, true] {
            let mut config = file();
            if empty {
                config.allocations.clear();
            }
            let genesis = Genesis::from_file(&config).unwrap();
            let cms: Vec<_> = genesis.notes().iter().map(note_commitment).collect();
            let expected = ChainState::genesis_with_commitments(&genesis.params, &cms);
            let actual = genesis.state();
            assert_eq!(actual.roots(), expected.roots());
            assert_eq!(actual.anchors.latest(), expected.anchors.latest());
            assert_eq!(actual.tip, genesis.id);
            assert_eq!(actual.timestamp(), expected.timestamp());
        }
    }

    fn file() -> GenesisFile {
        GenesisFile {
            network: "siworld-test-1".into(),
            timestamp: 1_800_000_000,
            block_time: 60,
            pow_iterations: 10_000,
            target: "00ff".to_string() + &"ff".repeat(30),
            container_size: 32,
            proofs: ProofsFile::Plonky3,
            dev_fund: None,
            allocations: vec![
                AllocationFile {
                    owner: hex(&SpendKey::from_digest(Digest([1; 32])).owner()),
                    amount: "1000".into(),
                },
                AllocationFile {
                    owner: hex(&SpendKey::from_digest(Digest([2; 32])).owner()),
                    amount: "0.5".into(),
                },
            ],
        }
    }

    #[test]
    fn json_round_trips_and_the_id_commits_to_every_field() {
        let g = Genesis::from_file(&file()).unwrap();
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap(), g);
        let changes: [Change; 8] = [
            |f| f.network.push('x'),
            |f| f.timestamp += 1,
            |f| f.block_time += 1,
            |f| f.pow_iterations += 1,
            |f| f.container_size = 16,
            |f| f.proofs = ProofsFile::Mock,
            |f| f.allocations[1].amount = "0.6".into(),
            |f| f.allocations.swap(0, 1),
        ];
        for change in changes {
            let mut f = file();
            change(&mut f);
            assert_ne!(Genesis::from_file(&f).unwrap().id, g.id);
        }
    }

    #[test]
    fn development_fund_keys_round_trip_and_change_the_id() {
        use crate::devfund::DevFundSigner;

        let signer = DevFundSigner::from_seed(&Digest([9; 32]));
        let keys = signer.verifying_keys();
        let mut with = file();
        with.dev_fund = Some(DevFundFile {
            direct: hex_bytes(&keys.direct),
            lock: hex_bytes(&keys.lock),
        });
        let g = Genesis::from_file(&with).unwrap();
        assert_eq!(g.params.dev_fund_keys, Some(keys));
        assert_eq!(g.params.chain_id, g.id);
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap(), g);
        assert_ne!(g.id, Genesis::from_file(&file()).unwrap().id);
        assert!(g.to_json().contains("\"dev_fund\""));
        assert!(!Genesis::from_file(&file())
            .unwrap()
            .to_json()
            .contains("dev_fund"));

        let mut bad = with.clone();
        bad.dev_fund.as_mut().unwrap().lock.pop();
        assert_eq!(
            Genesis::from_file(&bad).unwrap_err(),
            GenesisError::BadDevFundKey
        );
        let mut bad = with;
        bad.dev_fund
            .as_mut()
            .unwrap()
            .direct
            .replace_range(0..1, "x");
        assert_eq!(
            Genesis::from_file(&bad).unwrap_err(),
            GenesisError::BadDevFundKey
        );
    }

    #[test]
    fn the_genesis_state_holds_the_allocations_and_its_tip_is_the_id() {
        let g = Genesis::from_file(&file()).unwrap();
        let state = g.state();
        assert_eq!(state.tip, g.id);
        assert_eq!(state.commitments.len(), 2);
        let notes = g.notes();
        assert_eq!(notes[0].value, 1000 * siworld_core::params::ATOMS_PER_SIP);
        assert_eq!(
            notes[1].owner,
            SpendKey::from_digest(Digest([2; 32])).owner()
        );
        assert_ne!(notes[0].rho, notes[1].rho);
        assert_eq!(state.commitments.leaf(1), Some(note_commitment(&notes[1])));
    }

    #[test]
    fn bad_files_are_rejected() {
        let cases: [(Change, GenesisError); 8] = [
            (|f| f.network = "Upper".into(), GenesisError::BadNetwork),
            (|f| f.network.clear(), GenesisError::BadNetwork),
            (|f| f.target = "00".repeat(32), GenesisError::BadTarget),
            (|f| f.block_time = 0, GenesisError::BadBlockTime),
            (|f| f.pow_iterations = 0, GenesisError::BadPowIterations),
            (|f| f.container_size = 24, GenesisError::BadContainerSize),
            (
                |f| f.allocations[1].owner = "ff".repeat(32),
                GenesisError::BadOwner(1),
            ),
            (
                |f| f.allocations[0].amount = "0.00001".into(),
                GenesisError::BadAmount(0),
            ),
        ];
        for (change, err) in cases {
            let mut f = file();
            change(&mut f);
            assert_eq!(Genesis::from_file(&f), Err(err));
        }
        assert!(matches!(
            Genesis::from_json(r#"{"network":"x"}"#),
            Err(GenesisError::Json(_))
        ));
    }

    #[test]
    fn calibrated_target_scales_with_rate_and_block_time() {
        // One nonce per second and one-second blocks: every nonce wins.
        assert_eq!(calibrated_target(1, 1), [0xff; 32]);
        let t = calibrated_target(1 << 10, 1 << 6);
        // 2^256 / 2^16 − 1 = 2^240 − 1.
        let mut want = [0u8; 32];
        want[2..].fill(0xff);
        assert_eq!(t, want);
    }
}
