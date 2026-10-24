//! Slot relation, the proof-system interface, and the mock prover.
//!
//! `relation` is the executable specification of the transaction circuit
//! (docs/protocol.md, "Transaction proof requirements"); the real circuit must match it
//! clause by clause. `system` is the interface consensus, the mempool and the
//! wallet use to make and check proofs; `siworld-prover` implements it with
//! Plonky3. `mock` only checks the relation and provides neither zero knowledge
//! nor soundness: anyone can forge a mock proof. Devnet and tests only.

pub mod dummy;
pub mod mock;
pub mod relation;
pub mod statement;
pub mod system;

pub use mock::{AggregateError, FeeOpening, Leaf, MockProver, MockVerifier, SlotProof};
pub use relation::{
    check_slot, encrypt_outputs, output_rhos, slot_for, InputWitness, RelationContext,
    RelationError, SlotWitness,
};
pub use statement::{
    ContainerPublic, ContainerVerifier, HEIGHT_BITS, NUM_ROOT_PUBLIC, ROOT_ANCHORS, ROOT_CM_MINER,
    ROOT_COUNT, ROOT_HEIGHT, ROOT_SET, ROOT_SHARE,
};
pub use system::{ProofSystem, ProveError};
