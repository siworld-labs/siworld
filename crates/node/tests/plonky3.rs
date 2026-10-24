//! Two nodes on a Plonky3 network at `FriParams::fast()` (insecure, quick):
//! blocks carry real container proofs, a payment is proven by the wallet,
//! relayed, included by another miner and accepted by the first node.
#![cfg(feature = "plonky3")]

use std::sync::Arc;

use siworld_consensus::{mine, TipChange};
use siworld_core::issuance::{block_reward, epoch_of, fee_base, reward_split};
use siworld_core::params::ATOMS_PER_SI;
use siworld_core::{Block, Digest};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::hex;
use siworld_node::node::{Balance, Node};
use siworld_node::wire::{decode_tx, encode_tx};
use siworld_prover::Plonky3System;

const SI: u64 = ATOMS_PER_SI;

fn key(i: u8) -> SpendKey {
    SpendKey::from_digest(Digest([i; 32]))
}

/// Two slots per block, so the root aggregates the two leaves directly.
fn genesis() -> Genesis {
    Genesis::from_file(&GenesisFile {
        network: "plonky3-test".into(),
        timestamp: 1_000,
        block_time: 1,
        pow_iterations: 1,
        target: "0f".to_string() + &"ff".repeat(31),
        container_size: 2,
        proofs: ProofsFile::Plonky3,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: hex(&key(1).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap()
}

fn node(i: u8, system: &Arc<Plonky3System>) -> Node {
    Node::open(
        genesis(),
        key(i),
        SecretSeed::from_os_rng().unwrap(),
        None,
        system.clone(),
    )
    .unwrap()
}

fn mine_one(node: &mut Node) -> Block {
    let now = 1_000 + node.height() + 1;
    let mut block = node.template(now).unwrap();
    assert!(mine(&mut block.header, node.chain.params.pow_iterations));
    assert_eq!(node.accept(&block).unwrap(), TipChange::Extended);
    block
}

fn relay(from: &Node, to: &mut Node, height: u64) -> TipChange {
    let hash = from.chain.main_hash(height).unwrap();
    let bytes = from.chain.block(&hash).unwrap().encode();
    to.accept(&Block::decode(&bytes).unwrap()).unwrap()
}

fn share(height: u64) -> u64 {
    reward_split(block_reward(epoch_of(height))).0
}

#[test]
fn a_proven_payment_crosses_the_network() {
    let genesis = genesis();
    assert_eq!(
        genesis.params.proofs,
        siworld_core::params::ProofSystemKind::Plonky3
    );
    // a mines, so it builds the aggregation; b only verifies, trusting the
    // root key a derived (on a real network, the pinned one).
    let miner = Arc::new(Plonky3System::insecure_fast(&genesis.params, true).expect("setup"));
    let verifier = Arc::new(
        Plonky3System::insecure_fast_with_key(&genesis.params, miner.root_key()).expect("setup"),
    );
    let mut a = node(1, &miner);
    let mut b = node(2, &verifier);

    let block = mine_one(&mut a);
    assert_eq!(block.body.slots.len(), 2);
    assert!(block.proof.0.len() > 10_000, "a real container proof");
    assert_eq!(relay(&a, &mut b, 1), TipChange::Extended);

    // b admits the payment with its leaf proof, knowing only the root key;
    // a, the miner, includes it.
    let tx = a.pay(&b.address(), 10 * SI, false).unwrap();
    assert!(!tx.proof.body.is_empty(), "a real leaf proof");
    let fee = fee_base(epoch_of(1));
    b.submit_tx(decode_tx(&encode_tx(&tx)).unwrap(), Some(Digest([0xa; 32])))
        .unwrap();
    let paid = mine_one(&mut a);
    assert!(a.mempool.is_empty());
    assert_eq!(relay(&a, &mut b, 2), TipChange::Extended);
    assert!(b.mempool.is_empty(), "included transactions leave the pool");

    let change = 90 * SI - fee;
    let mined_by_a = share(1) + share(2) + fee;
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: change + mined_by_a,
            spendable: change,
            pending: mined_by_a
        }
    );
    assert_eq!(
        b.balance().unwrap(),
        Balance {
            total: 10 * SI,
            spendable: 10 * SI,
            pending: 0
        }
    );

    // A block whose proof does not match its slots is refused by the
    // verifier, whoever mined it: a validator never trusts the producer.
    let mut forged = paid.clone();
    forged.body.slots[0].tag[0] ^= 1;
    forged.header.nonce = 0;
    assert!(mine(&mut forged.header, 1));
    assert!(b.accept(&forged).is_err());
    assert!(a.accept(&forged).is_err());
}
