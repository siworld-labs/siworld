//! Mempool admission: zero-fee slots and transactions without their anti-spam
//! work are rejected, the pool and each peer's share of it are bounded, and
//! transactions leave it by fee tier, first come first served within a tier.

use std::sync::Arc;

use siworld_circuits::dummy::dummy_slot;
use siworld_circuits::MockProver;
use siworld_circuits::RelationContext;
use siworld_consensus::PendingTx;
use siworld_core::params::ATOMS_PER_SIP;
use siworld_core::Digest;
use siworld_node::mempool::admissible;
use siworld_node::{Config, Devnet, Mempool, MempoolError};

const SIP: u64 = ATOMS_PER_SIP;

/// A payment of 1 SIP from `from` to dave; each call spends a different package.
fn payment(net: &mut Devnet, from: &str, priority: bool) -> PendingTx {
    let state = net.state().clone();
    let params = net.chain.params.clone();
    let from = net.wallets.index_of(from).unwrap();
    let to = net.wallets.get("dave").unwrap().address();
    let (pow, system) = (net.tx_pow(), net.system());
    net.wallets
        .build_payment(
            &state,
            &params,
            &pow,
            system.as_ref(),
            from,
            &to,
            SIP,
            priority,
        )
        .unwrap()
}

/// Submits `tx` as this node's own, reporting an evicted transaction by its slot id.
fn submit(pool: &mut Mempool, net: &Devnet, tx: PendingTx) -> Result<Option<Digest>, MempoolError> {
    pool.submit(net.state(), tx, None)
        .map(|evicted| evicted.map(|t| t.slot.id()))
}

/// A pool with the devnet's work requirement.
fn pool(net: &Devnet) -> Mempool {
    Mempool::new(4_096, 256, net.tx_pow(), Arc::new(MockProver))
}

/// An empty package (all-dummy, zero fee), exactly as a block producer makes one.
fn empty_package(net: &Devnet, index: u64) -> PendingTx {
    let state = net.state();
    let ctx = RelationContext {
        anchors: &state.anchors,
        tree_depth: net.chain.params.commitment_tree_depth,
    };
    let (anchor, _) = state.anchors.latest().unwrap();
    let (slot, proof, fee) = dummy_slot(&MockProver, &ctx, anchor, &Digest([0x77; 32]), index);
    let nonce = net.tx_pow().solve(&proof.slot_id);
    PendingTx {
        slot,
        proof,
        fee,
        nonce,
    }
}

#[test]
fn a_transaction_without_its_anti_spam_work_is_rejected() {
    let mut net = Devnet::new(Config::default());
    let good = payment(&mut net, "alice", false);
    let pow = net.tx_pow();
    assert!(pow.check(&good.proof.slot_id, good.nonce));
    let mut bad = good.clone();
    bad.nonce = (0..u64::MAX)
        .find(|&n| !pow.check(&good.proof.slot_id, n))
        .unwrap();
    let mut p = pool(&net);
    assert_eq!(submit(&mut p, &net, bad), Err(MempoolError::BadPow));
    assert!(p.is_empty());
    assert_eq!(submit(&mut p, &net, good.clone()), Ok(None));
    // The nonce is bound to the slot: another slot's nonce does not carry over.
    let other = payment(&mut net, "bob", false);
    let mut moved = other.clone();
    moved.nonce = good.nonce;
    assert!(!pow.check(&other.proof.slot_id, good.nonce) || submit(&mut p, &net, moved).is_ok());
}

#[test]
fn each_peer_may_pool_a_bounded_number_of_transactions() {
    let mut net = Devnet::new(Config::default());
    let mut p = Mempool::new(16, 2, net.tx_pow(), Arc::new(MockProver));
    let peer_a = Some(Digest([0xa; 32]));
    let peer_b = Some(Digest([0xb; 32]));
    let txs: Vec<PendingTx> = ["alice", "bob", "carol", "alice", "bob"]
        .iter()
        .map(|w| payment(&mut net, w, false))
        .collect();
    assert_eq!(
        p.submit(net.state(), txs[0].clone(), peer_a).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        p.submit(net.state(), txs[1].clone(), peer_a).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        p.submit(net.state(), txs[2].clone(), peer_a).map(|_| ()),
        Err(MempoolError::PeerLimit)
    );
    // At its limit, a peer is turned away before its transaction is looked
    // at: even junk gets PeerLimit, not an invalid-transaction verdict.
    let mut junk = txs[2].clone();
    junk.nonce = 0;
    junk.proof.binding = Digest([0; 32]);
    assert_eq!(
        p.submit(net.state(), junk, peer_a).map(|_| ()),
        Err(MempoolError::PeerLimit)
    );
    // Another peer, and this node itself, are not held back by a's share.
    assert_eq!(
        p.submit(net.state(), txs[2].clone(), peer_b).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        p.submit(net.state(), txs[3].clone(), None).map(|_| ()),
        Ok(())
    );
    // A transaction leaving the pool frees its peer's share.
    assert_eq!(p.take(1).len(), 1);
    assert_eq!(
        p.submit(net.state(), txs[4].clone(), peer_a).map(|_| ()),
        Ok(())
    );
    assert_eq!(p.len(), 4);
}

#[test]
fn zero_fee_slots_are_rejected() {
    let net = Devnet::new(Config::default());
    let mut pool = pool(&net);
    for i in 0..3 {
        let tx = empty_package(&net, i);
        assert_eq!(tx.fee.fee, 0);
        assert_eq!(
            admissible(net.state(), &net.tx_pow(), net.system().as_ref(), &tx),
            Err(MempoolError::ZeroFee)
        );
        assert_eq!(submit(&mut pool, &net, tx), Err(MempoolError::ZeroFee));
    }
    assert!(pool.is_empty());
}

/// A second spelling of a spent nullifier would pass a set keyed by bytes, so
/// non-canonical encodings are refused before anything else.
#[test]
fn non_canonical_slots_are_rejected() {
    let mut net = Devnet::new(Config::default());
    let tx = payment(&mut net, "alice", false);
    for (i, edit) in [
        (|t: &mut PendingTx| &mut t.slot.nf[0].0) as fn(&mut PendingTx) -> &mut Digest,
        |t| &mut t.slot.cm[1].0,
    ]
    .into_iter()
    .enumerate()
    {
        let mut bad = tx.clone();
        let d = edit(&mut bad);
        let x = u32::from_le_bytes(d.0[..4].try_into().unwrap());
        d.0[..4].copy_from_slice(&(x + 0x7f00_0001).to_le_bytes());
        assert_eq!(
            admissible(net.state(), &net.tx_pow(), net.system().as_ref(), &bad),
            Err(MempoolError::NonCanonical),
            "case {i}"
        );
    }
    assert_eq!(
        admissible(net.state(), &net.tx_pow(), net.system().as_ref(), &tx).map(|_| ()),
        Ok(())
    );
}

#[test]
fn take_orders_by_tier_then_arrival() {
    let mut net = Devnet::new(Config::default());
    let a = payment(&mut net, "alice", false);
    let b = payment(&mut net, "bob", true);
    let c = payment(&mut net, "carol", false);
    let d = payment(&mut net, "alice", true);
    let mut pool = pool(&net);
    for tx in [&a, &b, &c, &d] {
        assert_eq!(submit(&mut pool, &net, tx.clone()), Ok(None));
    }
    let order: Vec<_> = pool.take(4).iter().map(|t| t.slot.id()).collect();
    let want: Vec<_> = [b, d, a, c].iter().map(|t| t.slot.id()).collect();
    assert_eq!(order, want);
    assert!(pool.is_empty());
}

#[test]
fn take_leaves_the_rest_in_order() {
    let mut net = Devnet::new(Config::default());
    let a = payment(&mut net, "alice", false);
    let b = payment(&mut net, "bob", false);
    let c = payment(&mut net, "carol", true);
    let mut pool = pool(&net);
    for tx in [&a, &b, &c] {
        submit(&mut pool, &net, tx.clone()).unwrap();
    }
    assert_eq!(pool.take(2)[0].slot.id(), c.slot.id());
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.take(5)[0].slot.id(), b.slot.id());
    // Taken transactions no longer block their nullifiers.
    assert_eq!(submit(&mut pool, &net, a), Ok(None));
}

#[test]
fn peek_leaves_the_pool_and_remove_slot_takes_one() {
    let mut net = Devnet::new(Config::default());
    let a = payment(&mut net, "alice", false);
    let b = payment(&mut net, "bob", true);
    let mut pool = pool(&net);
    for tx in [&a, &b] {
        submit(&mut pool, &net, tx.clone()).unwrap();
    }
    let ids = |txs: Vec<PendingTx>| txs.iter().map(|t| t.slot.id()).collect::<Vec<_>>();
    assert_eq!(ids(pool.peek(5)), ids(vec![b.clone(), a.clone()]));
    assert_eq!(pool.len(), 2);
    assert_eq!(
        pool.remove_slot(&b.slot.id()).map(|t| t.slot.id()),
        Some(b.slot.id())
    );
    assert!(pool.remove_slot(&b.slot.id()).is_none());
    assert_eq!(ids(pool.take(5)), ids(vec![a]));
}

#[test]
fn prune_drops_what_the_new_state_no_longer_admits() {
    let mut net = Devnet::new(Config::default());
    let a = payment(&mut net, "alice", false);
    let b = payment(&mut net, "bob", false);
    let mut pool = pool(&net);
    for tx in [&a, &b] {
        submit(&mut pool, &net, tx.clone()).unwrap();
    }
    assert!(pool.prune(net.state()).is_empty());
    // Another node's block spent one of a's inputs.
    let mut later = net.state().clone();
    later.nullifiers.insert(a.slot.nf[1]).unwrap();
    let pruned = pool.prune(&later);
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0].slot.id(), a.slot.id());
    assert_eq!(pool.peek(5)[0].slot.id(), b.slot.id());
    assert_eq!(pool.len(), 1);
}

#[test]
fn full_pool_rejects_same_tier_and_evicts_for_a_higher_tier() {
    let mut net = Devnet::new(Config::default());
    let a = payment(&mut net, "alice", false);
    let b = payment(&mut net, "bob", false);
    let c = payment(&mut net, "carol", false);
    let p = payment(&mut net, "alice", true);
    let q = payment(&mut net, "bob", true);
    let r = payment(&mut net, "carol", true);
    let mut pool = Mempool::new(2, 256, net.tx_pow(), Arc::new(MockProver));
    submit(&mut pool, &net, a.clone()).unwrap();
    submit(&mut pool, &net, b.clone()).unwrap();

    // Same tier: first come, first served; the newcomer is turned away.
    assert_eq!(submit(&mut pool, &net, c), Err(MempoolError::Full));
    // Higher tier: the newest lowest-tier transaction makes room.
    assert_eq!(submit(&mut pool, &net, p.clone()), Ok(Some(b.slot.id())));
    // The evicted transaction's nullifiers are free again: it is turned away for
    // lack of room, not as a conflict.
    assert_eq!(submit(&mut pool, &net, b.clone()), Err(MempoolError::Full));
    assert_eq!(submit(&mut pool, &net, q.clone()), Ok(Some(a.slot.id())));
    // Nothing lower is left to evict.
    assert_eq!(submit(&mut pool, &net, r), Err(MempoolError::Full));
    assert_eq!(pool.len(), 2);
    let order: Vec<_> = pool.take(2).iter().map(|t| t.slot.id()).collect();
    assert_eq!(order, vec![p.slot.id(), q.slot.id()]);
}

#[test]
fn rejected_submission_leaves_the_pool_unchanged() {
    let mut net = Devnet::new(Config::default());
    let a = payment(&mut net, "alice", false);
    let mut pool = Mempool::new(1, 256, net.tx_pow(), Arc::new(MockProver));
    submit(&mut pool, &net, a.clone()).unwrap();
    assert!(matches!(
        submit(&mut pool, &net, a.clone()),
        Err(MempoolError::Conflict(_))
    ));
    assert_eq!(
        submit(&mut pool, &net, empty_package(&net, 0)),
        Err(MempoolError::ZeroFee)
    );
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.take(1)[0].slot.id(), a.slot.id());
}

/// The devnet keeps paying users in front of an attacker: a priority payment
/// still gets in when the pool is full of base-tier transactions, and the
/// evicted payer's inputs are released for another try.
#[test]
fn devnet_releases_inputs_of_evicted_payments() {
    let mut net = Devnet::with_mempool_capacity(Config::default(), 1);
    net.pay("alice", "dave", SIP, false).unwrap();
    net.pay("bob", "dave", SIP, true).unwrap();
    net.mine(1).unwrap();
    assert_eq!(net.balance("dave"), Some(SIP));
    // alice's payment was evicted and its input released: a payment that needs
    // both of her 50 SIP packages goes through.
    net.pay("alice", "dave", 60 * SIP, false).unwrap();
    net.mine(2).unwrap();
    assert_eq!(net.balance("dave"), Some(61 * SIP));
}
