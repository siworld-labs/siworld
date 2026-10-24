//! Devnet end to end: continuous block production, a payment along the way, and
//! the recipient spending the received package.

use siworld_core::issuance::{epoch_of, fee_base, fee_priority};
use siworld_core::params::ATOMS_PER_SI;
use siworld_crypto::SecretSeed;
use siworld_node::wallet::Owned;
use siworld_node::{Config, Devnet, MempoolError, PayError};

const SI: u64 = ATOMS_PER_SI;

fn fee(net: &Devnet) -> u64 {
    fee_base(epoch_of(net.height()))
}

fn owned(net: &Devnet, name: &str) -> Vec<Owned> {
    net.wallets.get(name).unwrap().notes().to_vec()
}

fn spent(net: &Devnet, name: &str, o: &Owned) -> bool {
    let nf = net.wallets.get(name).unwrap().nullifier_of(o);
    net.state().nullifiers.contains(&nf)
}

#[test]
fn twenty_blocks_with_respends() {
    let mut net = Devnet::new(Config::default());
    let total = |net: &Devnet| -> u64 {
        ["alice", "bob", "carol", "dave"]
            .iter()
            .map(|n| net.balance(n).unwrap())
            .sum()
    };
    let total_before = total(&net);
    assert_eq!(net.balance("dave"), Some(0));

    let mut dave_received: Option<Owned> = None;
    let mut dave_change: Option<Owned> = None;
    let mut bob_received: Option<Owned> = None;
    let mut fees = 0;

    for h in 1..=20u64 {
        match h {
            3 => {
                fees += fee(&net);
                net.pay("alice", "dave", 10 * SI, false).unwrap();
            }
            // dave has no genesis funds and can only spend received packages.
            6 => {
                let notes = owned(&net, "dave");
                assert_eq!(notes.len(), 1);
                dave_received = Some(notes[0]);
                fees += fee(&net);
                let paid = fee(&net);
                net.pay("dave", "bob", 4 * SI, false).unwrap();
                // The only package is already reserved by a pending transaction,
                // whose change will cover the next payment.
                assert_eq!(
                    net.pay("dave", "carol", SI, false),
                    Err(PayError::FundsPending {
                        pending: 6 * SI - paid
                    })
                );
            }
            // dave spends the change; bob spends the received 4 SI at the priority
            // tier (it is the smallest package that suffices).
            10 => {
                let notes = owned(&net, "dave");
                assert_eq!(notes.len(), 1, "only the change note is left");
                dave_change = Some(notes[0]);
                bob_received = owned(&net, "bob")
                    .into_iter()
                    .find(|o| o.note.value == 4 * SI);
                assert!(bob_received.is_some(), "bob received dave's payment");
                fees += fee(&net);
                net.pay("dave", "carol", SI, false).unwrap();
                fees += fee_priority(epoch_of(net.height()));
                net.pay("bob", "carol", 3 * SI, true).unwrap();
            }
            _ => {}
        }
        let info = net.mine(h).unwrap();
        assert_eq!(info.height, h);
        assert_eq!(info.hash, net.state().tip);
        assert_eq!(info.state_root, net.state().roots().state_root);
        if h == 3 {
            assert_eq!(net.balance("dave"), Some(10 * SI));
        }
    }
    assert_eq!(net.height(), 20);

    assert!(spent(&net, "dave", &dave_received.unwrap()));
    assert!(spent(&net, "dave", &dave_change.unwrap()));
    assert!(spent(&net, "bob", &bob_received.unwrap()));

    let base = fee_base(0);
    assert_eq!(net.balance("dave"), Some(10 * SI - 4 * SI - SI - 2 * base));
    assert_eq!(net.balance("carol"), Some(100 * SI + SI + 3 * SI));
    assert_eq!(
        net.balance("bob"),
        Some(100 * SI + 4 * SI - 3 * SI - fee_priority(0))
    );
    // Fees went into the miner's fee package, not into any test wallet.
    assert_eq!(total_before - total(&net), fees);
}

#[test]
fn several_payments_fill_one_block() {
    let mut net = Devnet::new(Config::default());
    net.mine(1).unwrap();
    net.pay("alice", "dave", 3 * SI, false).unwrap();
    net.pay("bob", "dave", 2 * SI, true).unwrap();
    net.pay("carol", "dave", SI, false).unwrap();
    net.mine(2).unwrap();
    assert_eq!(net.balance("dave"), Some(6 * SI));
    assert_eq!(owned(&net, "dave").len(), 3);

    // Two inputs spent together: dave pays out the 3 SI and 2 SI packages at once.
    net.pay("dave", "alice", 4 * SI, false).unwrap();
    net.mine(3).unwrap();
    assert_eq!(net.balance("dave"), Some(6 * SI - 4 * SI - fee_base(0)));
}

#[test]
fn rejects_bad_payments_without_side_effects() {
    let mut net = Devnet::new(Config::default());
    assert_eq!(
        net.pay("alice", "mallory", SI, false),
        Err(PayError::UnknownWallet)
    );
    assert_eq!(
        net.pay("alice", "bob", 1, false),
        Err(PayError::AmountTooSmall)
    );
    assert_eq!(
        net.pay("dave", "bob", SI, false),
        Err(PayError::InsufficientFunds)
    );
    assert_eq!(
        net.pay("alice", "bob", 1_000 * SI, false),
        Err(PayError::InsufficientFunds)
    );
    let info = net.mine(1).unwrap();
    assert_eq!(info.height, 1);
    assert_eq!(net.balance("alice"), Some(100 * SI));
}

#[test]
fn mempool_rejects_double_spend() {
    use siworld_node::Mempool;

    let mut net = Devnet::new(Config::default());
    let from = net.wallets.index_of("alice").unwrap();
    let to = net.wallets.get("bob").unwrap().address();
    let state = net.state().clone();
    let params = net.chain.params.clone();
    let (pow, system) = (net.tx_pow(), net.system());
    let tx = net
        .wallets
        .build_payment(&state, &params, &pow, system.as_ref(), from, &to, SI, false)
        .unwrap();
    let mut pool = Mempool::new(16, 16, pow, system);
    pool.submit(&state, tx.clone(), None).unwrap();
    assert!(matches!(
        pool.submit(&state, tx, None),
        Err(MempoolError::Conflict(_))
    ));
    assert_eq!(pool.len(), 1);
}

#[test]
fn stale_clock_still_produces_valid_blocks() {
    // A clock that does not advance (or several blocks in one second) must not
    // stall the devnet: the node lifts the timestamp past the tip's.
    let mut net = Devnet::new(Config {
        genesis_timestamp: 1_000,
        ..Config::default()
    });
    for h in 1..=15 {
        assert_eq!(net.mine(1_000).unwrap().height, h);
    }
    let ts = &net.state().timestamps;
    assert!(ts.windows(2).all(|w| w[0] < w[1]));
}

/// Two nodes started from the same public seed: with OS randomness their
/// payments and block padding share nothing an observer could recompute.
#[test]
fn os_randomness_is_not_derived_from_the_public_seed() {
    let mut a = Devnet::new(Config::default());
    let mut b = Devnet::new(Config::default());
    let pay = |net: &mut Devnet| {
        let state = net.state().clone();
        let params = net.chain.params.clone();
        let (from, to) = (
            net.wallets.index_of("alice").unwrap(),
            net.wallets.get("bob").unwrap().address(),
        );
        let (pow, system) = (net.tx_pow(), net.system());
        net.wallets
            .build_payment(&state, &params, &pow, system.as_ref(), from, &to, SI, false)
            .unwrap()
    };
    let (ta, tb) = (pay(&mut a), pay(&mut b));
    assert_ne!(ta.slot.cm, tb.slot.cm);
    assert_ne!(ta.slot.ct, tb.slot.ct);
    assert_ne!(ta.fee.blind, tb.fee.blind);

    let (ba, bb) = (a.mine(1).unwrap(), b.mine(1).unwrap());
    assert_ne!(ba.state_root, bb.state_root);
}

/// The deterministic constructor reproduces a run exactly, for debugging.
#[test]
fn insecure_deterministic_randomness_reproduces_the_chain() {
    let run = || {
        let mut net = Devnet::new(Config {
            randomness: SecretSeed::insecure_deterministic(siworld_core::Digest([0x11; 32])),
            ..Config::default()
        });
        net.mine(1).unwrap();
        net.pay("alice", "dave", SI, false).unwrap();
        net.mine(2).unwrap();
        net.state().tip
    };
    assert_eq!(run(), run());
}

/// The devnet's development fund pays a test wallet: the direct account's
/// first credit matures 100 blocks after block 1, the payout's package is
/// found by its owner and is spendable at once.
#[test]
fn the_development_fund_pays_a_wallet() {
    use siworld_core::params::COINBASE_MATURITY;
    use siworld_core::DevAccount;
    use siworld_node::PayoutRefused;
    use siworld_state::deposit;

    let mut net = Devnet::new(Config::default());
    assert_eq!(
        net.payout(DevAccount::Direct, "dave", deposit(1)),
        Err(PayoutRefused::Insufficient { spendable: 0 })
    );
    for t in 1..=COINBASE_MATURITY + 1 {
        net.mine(t).unwrap();
    }
    assert_eq!(
        net.payout(DevAccount::Direct, "nobody", deposit(1)),
        Err(PayoutRefused::UnknownWallet)
    );
    assert_eq!(
        net.payout(DevAccount::Direct, "dave", deposit(1) + 1),
        Err(PayoutRefused::Insufficient {
            spendable: deposit(1)
        })
    );
    net.payout(DevAccount::Direct, "dave", deposit(1)).unwrap();
    // Queued payouts count against the balance.
    assert_eq!(
        net.payout(DevAccount::Direct, "dave", 10_000),
        Err(PayoutRefused::Insufficient { spendable: 0 })
    );
    assert_eq!(net.balance("dave"), Some(0));
    net.mine(COINBASE_MATURITY + 2).unwrap();
    assert_eq!(net.balance("dave"), Some(deposit(1)));
    assert_eq!(net.state().dev_fund.payouts(DevAccount::Direct), 1);

    // dave spends it right away.
    let paid = fee(&net);
    net.pay("dave", "alice", deposit(1) - paid, false).unwrap();
    net.mine(COINBASE_MATURITY + 3).unwrap();
    assert_eq!(net.balance("dave"), Some(0));
    assert_eq!(net.balance("alice"), Some(100 * SI + deposit(1) - paid));
}
