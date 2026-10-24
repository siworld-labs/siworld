//! On-disk block store.
//!
//! A node keeps every block it has accepted, in the order it accepted them,
//! and rebuilds its chain at start by accepting them again: chain state is a
//! function of the blocks, so the blocks are all that must survive a restart.
//! Replaying in acceptance order rebuilds the same fork choice, ties included
//! (the branch seen first stays), and every parent comes before its children.
//! Snapshots that let a restart skip the replay are a later optimisation
//! (docs/security-model.md).
//!
//! The store also records the network it belongs to, so a node pointed at a
//! data directory from another network refuses to start instead of mixing
//! chains.

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use siworld_core::codec::DecodeError;
use siworld_core::{Block, Digest};

/// Acceptance order → encoded block.
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
/// Store-wide values.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const NETWORK: &str = "network";

#[derive(Debug)]
pub enum StoreError {
    /// The database failed (I/O, corruption detected by redb, locking).
    Db(String),
    /// The store belongs to another network.
    WrongNetwork,
    /// A stored block does not decode.
    Corrupt { seq: u64, error: DecodeError },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::WrongNetwork => f.write_str("the data directory belongs to another network"),
            Self::Corrupt { seq, error } => write!(f, "stored block {seq} is corrupt: {error:?}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn db_err<E: Into<redb::Error>>(e: E) -> StoreError {
    StoreError::Db(e.into().to_string())
}

pub struct BlockStore {
    db: Database,
    /// Number of stored blocks; the next block's key.
    len: u64,
}

impl BlockStore {
    /// Opens the store at `path`, creating it for `network` if it does not
    /// exist. Fails with [`StoreError::WrongNetwork`] if it was created for
    /// another network.
    pub fn open(path: &Path, network: &Digest) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(db_err)?;
        let txn = db.begin_write().map_err(db_err)?;
        let len = {
            let mut meta = txn.open_table(META).map_err(db_err)?;
            let stored = meta
                .get(NETWORK)
                .map_err(db_err)?
                .map(|v| v.value().to_vec());
            match stored {
                Some(id) if id != network.as_bytes() => return Err(StoreError::WrongNetwork),
                Some(_) => {}
                None => {
                    meta.insert(NETWORK, network.as_bytes().as_slice())
                        .map_err(db_err)?;
                }
            }
            txn.open_table(BLOCKS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?
        };
        txn.commit().map_err(db_err)?;
        Ok(Self { db, len })
    }

    /// Number of stored blocks.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends a block the node has just accepted. Durable when it returns.
    pub fn append(&mut self, block: &Block) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        txn.open_table(BLOCKS)
            .map_err(db_err)?
            .insert(self.len, block.encode().as_slice())
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        self.len += 1;
        Ok(())
    }

    /// Every stored block in acceptance order.
    pub fn blocks(&self) -> Result<Vec<Block>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(BLOCKS).map_err(db_err)?;
        table
            .iter()
            .map_err(db_err)?
            .map(|row| {
                let (seq, bytes) = row.map_err(db_err)?;
                Block::decode(bytes.value()).map_err(|error| StoreError::Corrupt {
                    seq: seq.value(),
                    error,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use siworld_core::{
        BlockBody, Ciphertext, Coinbase, Commitment, ContainerProof, Header, CIPHERTEXT_LEN,
    };

    use super::*;

    /// A fresh path under the system temporary directory, removed on drop.
    struct TempPath(PathBuf);

    impl TempPath {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-storage-{name}-{}.redb",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn block(height: u64) -> Block {
        Block {
            header: Header {
                version: 0,
                height,
                parent: Digest([height as u8; 32]),
                timestamp: height,
                target: [0xff; 32],
                nonce: height,
                state_root: Digest::ZERO,
                commitment_root: Digest::ZERO,
                nullifier_root: Digest::ZERO,
                body_root: Digest::ZERO,
                container_size: 0,
            },
            body: BlockBody {
                coinbase: Coinbase {
                    committee_key: Digest::ZERO,
                    miner_amount: height,
                    dev_direct_amount: 0,
                    dev_lock_amount: 0,
                    miner_note_cm: Commitment(Digest::ZERO),
                    miner_note_ct: Ciphertext([0; CIPHERTEXT_LEN]),
                    miner_note_tag: 0,
                },
                payouts: Vec::new(),
                slots: Vec::new(),
            },
            proof: ContainerProof(vec![height as u8; 3]),
        }
    }

    #[test]
    fn blocks_survive_reopening_in_acceptance_order() {
        let path = TempPath::new("reopen");
        let net = Digest([1; 32]);
        {
            let mut store = BlockStore::open(&path.0, &net).unwrap();
            assert!(store.is_empty());
            for h in [3, 1, 2] {
                store.append(&block(h)).unwrap();
            }
        }
        let mut store = BlockStore::open(&path.0, &net).unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(store.blocks().unwrap(), vec![block(3), block(1), block(2)]);
        store.append(&block(4)).unwrap();
        assert_eq!(store.blocks().unwrap().last(), Some(&block(4)));
    }

    #[test]
    fn a_store_from_another_network_is_refused() {
        let path = TempPath::new("network");
        BlockStore::open(&path.0, &Digest([1; 32])).unwrap();
        assert!(matches!(
            BlockStore::open(&path.0, &Digest([2; 32])),
            Err(StoreError::WrongNetwork)
        ));
        BlockStore::open(&path.0, &Digest([1; 32])).unwrap();
    }
}
