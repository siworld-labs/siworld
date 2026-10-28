//! Testnet node core without the network: blocks and transactions pass between
//! nodes as bytes, as the peer-to-peer layer carries them.
mod common;

use std::sync::Arc;

use siworld_circuits::MockProver;
use siworld_consensus::{mine, TipChange};
use siworld_core::issuance::{block_reward, epoch_of, fee_base, reward_split};
use siworld_core::params::{ATOMS_PER_SIP, COINBASE_MATURITY};
use siworld_core::DevAccount;
use siworld_core::{Block, Digest};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::devfund::{DevFundSigner, PayoutRefused};
use siworld_node::genesis::{
    hex_bytes, AllocationFile, DevFundFile, Genesis, GenesisFile, ProofsFile,
};
use siworld_node::hex;
use siworld_node::node::{Balance, Node};
use siworld_node::wire::{decode_tx, encode_tx};
use siworld_node::PayError;
use siworld_state::deposit;
use siworld_storage::BlockStore;

const SIP: u64 = ATOMS_PER_SIP;

fn key(i: u8) -> SpendKey {
    SpendKey::from_digest(Digest([i; 32]))
}

/// Cheap work: about 16 nonces of one hash per block.
fn genesis() -> Genesis {
    genesis_with(None)
}

fn fund_signer() -> DevFundSigner {
    DevFundSigner::from_seed(&Digest([0xdf; 32]))
}

fn genesis_with(dev_fund: Option<DevFundFile>) -> Genesis {
    Genesis::from_file(&GenesisFile {
        network: "node-test".into(),
        timestamp: 1_000,
        block_time: 1,
        pow_iterations: 1,
        target: "0f".to_string() + &"ff".repeat(31),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund,
        allocations: vec![AllocationFile {
            owner: hex(&key(1).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap()
}

fn node(i: u8, store: Option<BlockStore>) -> Node {
    Node::open(
        genesis(),
        key(i),
        SecretSeed::from_os_rng().unwrap(),
        store,
        Arc::new(MockProver),
    )
    .unwrap()
}

/// Mines a block on `node`'s tip and accepts it.
fn mine_one(node: &mut Node) -> Block {
    let now = 1_000 + node.height() + 1;
    let mut block = node.template(now).unwrap();
    assert!(mine(&mut block.header, node.chain.params.pow_iterations));
    assert_eq!(node.accept(&block).unwrap(), TipChange::Extended);
    block
}

/// Sends `to` every main-chain block of `from` above their last common
/// main-chain height, as encoded bytes, in order.
fn sync(from: &Node, to: &mut Node) -> Vec<TipChange> {
    let common = (0..=to.height().min(from.height()))
        .rev()
        .find(|&h| from.chain.main_hash(h) == to.chain.main_hash(h))
        .expect("genesis is common");
    (common + 1..=from.height())
        .map(|h| {
            let hash = from.chain.main_hash(h).unwrap();
            let bytes = from.chain.block(&hash).unwrap().encode();
            to.accept(&Block::decode(&bytes).unwrap()).unwrap()
        })
        .collect()
}

fn fee(height: u64) -> u64 {
    fee_base(epoch_of(height))
}

#[test]
fn startup_randomness_cannot_reconstruct_block_padding() {
    let startup = SecretSeed::from_os_rng().unwrap();
    // An attacker with the old startup root could derive the first template
    // seed. A fresh candidate must not be reproducible with that seed.
    let leaked = startup.child("blocks", 0).child("block seed", 1);
    let genesis = genesis();
    let mut producer =
        Node::open(genesis.clone(), key(1), startup, None, Arc::new(MockProver)).unwrap();
    let candidate = producer.template(1_001).unwrap();
    let guessed = siworld_consensus::build_unsealed(
        &genesis.state(),
        &genesis.state().anchors,
        &genesis.params,
        &MockProver,
        &siworld_consensus::Miner {
            address: key(1).address(),
            committee_key: siworld_crypto::domain_hash(
                "siworld testnet committee key",
                &[key(1).expose_secret()],
            ),
        },
        &[],
        &[],
        &leaked,
        1_001,
    )
    .unwrap();
    assert!(
        candidate.body != guessed.body,
        "startup randomness must not reproduce a candidate's padding"
    );
}

/// The miner's public reward share of the block at `height`.
fn share(height: u64) -> u64 {
    reward_split(block_reward(epoch_of(height))).0
}

#[test]
fn a_payment_relayed_to_another_miner_reaches_the_recipient() {
    let mut a = node(1, None);
    let mut b = node(2, None);
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: 100 * SIP,
            spendable: 100 * SIP,
            pending: 0
        }
    );
    assert_eq!(b.balance().unwrap().total, 0);
    mine_one(&mut a);
    mine_one(&mut a);
    assert_eq!(sync(&a, &mut b), vec![TipChange::Extended; 2]);
    assert_eq!(b.chain.state.tip, a.chain.state.tip);

    let paid_at = a.height();
    // a mined blocks 1 and 2: their miner packages are pending until they
    // mature.
    let mined_by_a = share(1) + share(2);
    let tx = a.pay(&b.address(), 10 * SIP, false).unwrap();
    assert_eq!(a.mempool.len(), 1);
    // The inputs are reserved until the payment is on chain; the change is
    // pending.
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: 100 * SIP + mined_by_a,
            spendable: 0,
            pending: 90 * SIP - fee(paid_at) + mined_by_a
        }
    );
    b.submit_tx(decode_tx(&encode_tx(&tx)).unwrap(), Some(Digest([0xa; 32])))
        .unwrap();

    mine_one(&mut b);
    assert!(b.mempool.is_empty(), "included transactions leave the pool");
    assert_eq!(sync(&b, &mut a), vec![TipChange::Extended]);
    assert!(a.mempool.is_empty());

    let change = 90 * SIP - fee(paid_at);
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: change + mined_by_a,
            spendable: change,
            pending: mined_by_a
        }
    );
    // b holds the payment and, as the miner of block 3, the pending miner
    // package: its reward share plus the fee.
    let mined_by_b = share(3) + fee(paid_at);
    assert_eq!(
        b.balance().unwrap(),
        Balance {
            total: 10 * SIP + mined_by_b,
            spendable: 10 * SIP,
            pending: mined_by_b
        }
    );
}

/// A miner package enters the tree COINBASE_MATURITY blocks after its block
/// and is spendable from then on; a reorg that removes its block makes it
/// pending again, and one that removes the block that appended it, but not
/// its own block, returns it to pending until the new branch appends it.
#[test]
fn miner_packages_mature_after_one_hundred_blocks_and_follow_reorgs() {
    let mut a = node(2, None);
    let mut c = node(3, None);
    assert_eq!(a.balance().unwrap().total, 0);

    // a and c share the first 60 blocks, all mined by a.
    for _ in 1..=60 {
        mine_one(&mut a);
    }
    assert_eq!(sync(&a, &mut c), vec![TipChange::Extended; 60]);
    let shared: u64 = (1..=60).map(share).sum();
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: shared,
            spendable: 0,
            pending: shared
        }
    );

    // a mines on to block 101, which appends block 1's package (unlocked at
    // 101), so that one is spendable and the rest are still pending.
    for _ in 61..=COINBASE_MATURITY + 1 {
        mine_one(&mut a);
    }
    let mined: u64 = (1..=COINBASE_MATURITY + 1).map(share).sum();
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: mined,
            spendable: share(1),
            pending: mined - share(1)
        }
    );
    assert_eq!(a.wallets.get("node").unwrap().notes().len(), 1);

    // c mines a heavier branch from block 60; a reorganizes onto it. Blocks
    // 61 to 101 were a's, so their packages are gone, and block 1's package,
    // appended by a's block 101, is pending again until c's block 101 appends
    // it; c's blocks 101 to 103 append the packages of blocks 1 to 3.
    for _ in 61..=COINBASE_MATURITY + 3 {
        mine_one(&mut c);
    }
    let changes = sync(&c, &mut a);
    assert_eq!(changes.len(), 43);
    assert_eq!(changes[41], TipChange::Reorg { fork: 60 }, "{changes:?}");
    assert_eq!(changes[42], TipChange::Extended);
    assert_eq!(a.chain.state.tip, c.chain.state.tip);
    let matured = share(1) + share(2) + share(3);
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: shared,
            spendable: matured,
            pending: shared - matured
        }
    );
    assert_eq!(a.wallets.get("node").unwrap().notes().len(), 3);

    // The matured packages are real: a spends one of them.
    a.pay(&c.address(), share(1) - fee(a.height()), false)
        .unwrap();
}

#[test]
fn a_reorg_rolls_the_wallet_back_to_the_fork() {
    let mut a = node(1, None);
    let mut b = node(2, None);
    a.pay(&b.address(), 10 * SIP, false).unwrap();
    mine_one(&mut a);
    // The change, and the miner package a mined for itself (its reward share
    // and the fee), still pending.
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: 90 * SIP + share(1),
            spendable: 90 * SIP - fee(0),
            pending: fee(0) + share(1)
        }
    );

    // b mines a heavier branch without the payment.
    mine_one(&mut b);
    mine_one(&mut b);
    assert_eq!(
        sync(&b, &mut a),
        vec![TipChange::None, TipChange::Reorg { fork: 0 }]
    );
    assert_eq!(a.chain.state.tip, b.chain.state.tip);
    // The payment left the chain with a's block: its input is unspent and
    // free again.
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: 100 * SIP,
            spendable: 100 * SIP,
            pending: 0
        }
    );
    a.pay(&b.address(), 10 * SIP, false).unwrap();
}

#[test]
fn a_send_while_the_change_is_unconfirmed_reports_pending_funds() {
    let mut a = node(1, None);
    let b = node(2, None);
    a.pay(&b.address(), 10 * SIP, false).unwrap();
    let change = 90 * SIP - fee(0);
    // a's only package is in flight: the change would cover a second payment
    // once the first confirms.
    assert_eq!(
        a.pay(&b.address(), 5 * SIP, false).unwrap_err(),
        PayError::FundsPending { pending: change }
    );
    // Even the change cannot cover this one.
    assert_eq!(
        a.pay(&b.address(), change, false).unwrap_err(),
        PayError::InsufficientFunds
    );
    assert_eq!(a.mempool.len(), 1, "failed sends leave the pool alone");

    mine_one(&mut a);
    a.pay(&b.address(), 5 * SIP, false).unwrap();
}

#[test]
fn a_send_that_needs_an_immature_miner_package_reports_pending_funds() {
    let mut a = node(1, None);
    let b = node(2, None);
    a.pay(&b.address(), 10 * SIP, false).unwrap();
    mine_one(&mut a);
    // The change plus the pending miner package a mined covers 90 SIP.
    assert_eq!(
        a.pay(&b.address(), 90 * SIP - fee(1), false).unwrap_err(),
        PayError::FundsPending {
            pending: fee(0) + share(1)
        }
    );
    a.pay(&b.address(), 90 * SIP - fee(0) - fee(1), false)
        .unwrap();
}

#[test]
fn paying_itself_splits_a_package_for_two_sends_in_a_row() {
    let mut a = node(1, None);
    let b = node(2, None);
    a.pay(&a.address(), 50 * SIP, false).unwrap();
    mine_one(&mut a);
    a.pay(&b.address(), 10 * SIP, false).unwrap();
    a.pay(&b.address(), 10 * SIP, false).unwrap();
    assert_eq!(a.mempool.len(), 2);
}

#[test]
fn a_dropped_payment_frees_its_input_and_clears_the_pending_change() {
    let mut a = node(1, None);
    let b = node(2, None);
    let tx = a.pay(&b.address(), 10 * SIP, false).unwrap();
    a.wallets.release(&tx.slot);
    assert_eq!(
        a.balance().unwrap(),
        Balance {
            total: 100 * SIP,
            spendable: 100 * SIP,
            pending: 0
        }
    );
}

#[test]
fn a_restarted_node_replays_its_store() {
    let path =
        std::env::temp_dir().join(format!("siworld-node-restart-{}.redb", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let open_store = || BlockStore::open(&path, &genesis().id).unwrap();

    let mut b = node(2, None);
    let side = mine_one(&mut b);
    let (tip, balance) = {
        let mut a = node(1, Some(open_store()));
        mine_one(&mut a);
        a.pay(&b.address(), 10 * SIP, false).unwrap();
        mine_one(&mut a);
        // A side block is stored too, and the replay keeps the same fork choice.
        assert_eq!(a.accept(&side).unwrap(), TipChange::None);
        (a.chain.state.tip, a.balance().unwrap())
    };
    let a = node(1, Some(open_store()));
    assert_eq!(a.chain.state.tip, tip);
    assert_eq!(a.height(), 2);
    assert!(a.chain.contains(&side.header.hash()));
    assert_eq!(a.balance().unwrap(), balance);
    let _ = std::fs::remove_file(&path);
}

/// The fund's node signs payouts and includes them in its own blocks; a node
/// without the keys cannot, and a payout is dropped from the queue once it is
/// on chain, so it is never included twice.
#[test]
fn the_development_fund_pays_through_its_own_miner() {
    let keys = fund_signer().verifying_keys();
    let genesis = genesis_with(Some(DevFundFile {
        direct: hex_bytes(&keys.direct),
        lock: hex_bytes(&keys.lock),
    }));
    let open = |i: u8| {
        Node::open(
            genesis.clone(),
            key(i),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap()
    };
    let mut fund = open(2);
    let mut other = open(3);
    assert_eq!(
        fund.payout(
            siworld_node::fund_payments::PayoutId::random().unwrap(),
            DevAccount::Direct,
            &other.address(),
            deposit(1)
        ),
        Err(PayoutRefused::NoKeys)
    );
    let password = "temporary node fund test password";
    let _journal = common::FundDir::attach(
        &mut fund,
        siworld_node::fund_keys::FundKeystore::seal(&Digest([0xdf; 32]), password).unwrap(),
        password,
    );
    fund.unlock_fund(
        password,
        &siworld_node::fund_keys::FundGrant {
            version: 2,
            approval_id: siworld_node::fund_payments::PayoutId::random()
                .unwrap()
                .to_string(),
            budget: siworld_node::fund_keys::FundBudget {
                version: 1,
                id: "ab".repeat(32),
                direct_sip: "1000000000".into(),
                lock_sip: "1000000000".into(),
                total_sip: "2000000000".into(),
                max_payout_sip: "1000000".into(),
            },
            genesis: hex(&fund.genesis.id),
            seconds: 3600,
            direct_sip: "1000000".into(),
            lock_sip: "1000000".into(),
            max_payout_sip: "1000000".into(),
            recipients: vec![siworld_node::address::encode_address(&other.address())],
            approval: None,
        },
    )
    .unwrap();
    assert_eq!(
        fund.payout(
            siworld_node::fund_payments::PayoutId::random().unwrap(),
            DevAccount::Direct,
            &other.address(),
            deposit(1)
        ),
        Err(PayoutRefused::Insufficient { spendable: 0 })
    );
    for _ in 1..=COINBASE_MATURITY + 1 {
        mine_one(&mut fund);
    }
    assert_eq!(fund.dev_fund().spendable(DevAccount::Direct), deposit(1));
    let payout = fund
        .payout(
            siworld_node::fund_payments::PayoutId::random().unwrap(),
            DevAccount::Direct,
            &other.address(),
            deposit(1),
        )
        .unwrap();
    assert_eq!(payout.counter, 0);
    let block = mine_one(&mut fund);
    assert_eq!(block.body.payouts, vec![payout]);
    assert_eq!(fund.dev_fund().payouts(DevAccount::Direct), 1);
    // Included, so no longer queued: the next block carries no payout.
    let block = mine_one(&mut fund);
    assert!(block.body.payouts.is_empty());

    // The recipient finds the package by its owner and can spend it at once.
    sync(&fund, &mut other);
    assert_eq!(
        other.balance().unwrap(),
        Balance {
            total: deposit(1),
            spendable: deposit(1),
            pending: 0
        }
    );
    other
        .pay(&fund.address(), deposit(1) - fee(other.height()), false)
        .unwrap();

    // A node whose genesis has no fund keys rejects such a block.
    let mut keyless = node(4, None);
    let hash = fund.chain.main_hash(1).unwrap();
    let first = fund.chain.block(&hash).unwrap().clone();
    assert!(keyless.accept(&first).is_err(), "different genesis");
}
