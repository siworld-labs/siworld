//! Development-fund payouts (docs/protocol.md, Economics): public, signed entries of a
//! block body that move SIP from a fund account into a shielded package whose
//! plaintext is public, bounded by the account's balance.

mod common;

use common::*;
use siworld_consensus::{transition, BlockError, PayoutError};
use siworld_core::params::{COINBASE_MATURITY, MAX_PAYOUTS_PER_BLOCK, MIN_PACKAGE_DEPOSIT};
use siworld_core::{DevAccount, Digest};
use siworld_crypto::{note_commitment, payout_note, SpendKey};
use siworld_state::{deposit, ChainState};

const SIP: u64 = 100_000_000;

/// A chain of `blocks` empty blocks on the dev-fund parameters, with alice's
/// genesis package, and its state.
fn chain_of(
    blocks: u64,
) -> (
    siworld_consensus::Chain<siworld_circuits::MockVerifier>,
    Owned,
) {
    let p = params_with_dev_fund();
    let (state, owned) = genesis(&p, &[(key(1), SIP, 0)]);
    let mut node = chain(&p, state);
    for h in 1..=blocks {
        let block = build(&node.state, &p, &[], h).unwrap();
        node.apply_block(&block).unwrap();
    }
    (node, owned[0].clone())
}

fn spendable(state: &ChainState, account: DevAccount) -> u64 {
    state.dev_fund.spendable(account)
}

#[test]
fn the_fund_accrues_from_the_coinbase_amounts() {
    let (node, _) = chain_of(COINBASE_MATURITY + 1);
    let s = &node.state;
    // Direct credits mature after 100 blocks; the lock has released a little
    // of every deposit so far, and a payable amount at 60-second blocks.
    assert_eq!(spendable(s, DevAccount::Direct), deposit(1));
    let lock = spendable(s, DevAccount::Lock);
    assert!(lock >= MIN_PACKAGE_DEPOSIT, "{lock}");
    assert!(lock < deposit(1));
}

#[test]
fn a_payout_creates_a_package_the_recipient_spends() {
    let (mut node, _) = chain_of(COINBASE_MATURITY + 1);
    let p = node.params.clone();
    let bob = key(2);
    let direct = spendable(&node.state, DevAccount::Direct);
    let lock = spendable(&node.state, DevAccount::Lock);
    let payouts = [
        payout(DevAccount::Direct, 0, direct, &bob, 1),
        payout(DevAccount::Lock, 0, lock, &bob, 2),
    ];
    let h = COINBASE_MATURITY + 2;
    let block = build_with_payouts(&node.state, &p, &[], &payouts, h).unwrap();
    node.apply_block(&block).unwrap();

    // The packages follow the matured miner package in the tree, with ρ
    // derived from the height and the index.
    let s = &node.state;
    let n = s.commitments.len();
    let notes = [
        payout_note(&payouts[0], h, 0),
        payout_note(&payouts[1], h, 1),
    ];
    assert_eq!(s.commitments.leaf(n - 2), Some(note_commitment(&notes[0])));
    assert_eq!(s.commitments.leaf(n - 1), Some(note_commitment(&notes[1])));
    assert_ne!(notes[0].rho, notes[1].rho);
    assert_eq!(s.dev_fund.payouts(DevAccount::Direct), 1);
    assert_eq!(s.dev_fund.payouts(DevAccount::Lock), 1);
    assert_eq!(spendable(s, DevAccount::Direct), deposit(2));
    assert_eq!(s.dev_fund.paid(DevAccount::Lock), lock);

    // bob spends the direct payout in the next block.
    let fee = fee_now(s);
    let owned = Owned {
        sk: bob,
        note: notes[0],
        index: n - 2,
    };
    let tx = pay(
        s,
        &p,
        [real(s, &owned), dummy(3)],
        &key(3),
        [direct - fee, 0],
        fee,
        4,
    )
    .expect("the payout is spendable");
    let block = build(&node.state, &p, &[tx], h + 1).unwrap();
    node.apply_block(&block).unwrap();
}

/// Each check on a payout, through the same `transition` the producer and
/// the validator run.
#[test]
fn invalid_payouts_are_rejected() {
    let (node, _) = chain_of(COINBASE_MATURITY + 1);
    let p = node.params.clone();
    let s = &node.state;
    let h = COINBASE_MATURITY + 2;
    let direct = spendable(s, DevAccount::Direct);
    let bob = key(2);
    let body_with = |payouts: &[siworld_core::Payout]| {
        build_with_payouts(s, &p, &[], payouts, h)
            .map(|b| b.body)
            .map_err(|e| match e {
                siworld_consensus::BuildError::Invalid(e) => e,
                other => panic!("{other:?}"),
            })
    };
    let check = |payouts: &[siworld_core::Payout]| {
        body_with(payouts).and_then(|b| transition(s, &b, h, &p).map(|_| ()))
    };
    let bad = |index, error| Err(BlockError::BadPayout { index, error });

    // Signed by the other account's key.
    let mut forged = payout(DevAccount::Direct, 0, direct, &bob, 1);
    forged.account = DevAccount::Lock;
    assert_eq!(check(&[forged]), bad(0, PayoutError::Signature));
    // Tampered after signing.
    let mut tampered = payout(DevAccount::Direct, 0, direct, &bob, 1);
    tampered.amount -= 1;
    assert_eq!(check(&[tampered]), bad(0, PayoutError::Signature));
    let mut tampered = payout(DevAccount::Direct, 0, direct, &bob, 1);
    tampered.owner = key(9).owner();
    assert_eq!(check(&[tampered]), bad(0, PayoutError::Signature));

    // Signed for another chain with the same key: not valid here.
    let elsewhere = payout_on(&Digest([0xee; 32]), DevAccount::Direct, 0, direct, &bob, 1);
    assert_eq!(check(&[elsewhere]), bad(0, PayoutError::Signature));

    // Counters: the account's next number, in order within the block.
    assert_eq!(
        check(&[payout(DevAccount::Direct, 1, direct, &bob, 1)]),
        bad(0, PayoutError::Counter)
    );
    let half = direct / 2;
    assert_eq!(
        check(&[
            payout(DevAccount::Direct, 0, half, &bob, 1),
            payout(DevAccount::Direct, 0, half, &bob, 2)
        ]),
        bad(1, PayoutError::Counter)
    );
    assert_eq!(
        check(&[
            payout(DevAccount::Direct, 0, half, &bob, 1),
            payout(DevAccount::Direct, 1, half, &bob, 2)
        ]),
        Ok(())
    );

    // The balance bounds the block's payouts together.
    assert_eq!(
        check(&[payout(DevAccount::Direct, 0, direct + 1, &bob, 1)]),
        Err(BlockError::Overdraft(DevAccount::Direct))
    );
    assert_eq!(
        check(&[
            payout(DevAccount::Direct, 0, direct, &bob, 1),
            payout(DevAccount::Direct, 1, MIN_PACKAGE_DEPOSIT, &bob, 2)
        ]),
        Err(BlockError::Overdraft(DevAccount::Direct))
    );
    // A payout below the minimum package is not a package.
    assert_eq!(
        check(&[payout(
            DevAccount::Direct,
            0,
            MIN_PACKAGE_DEPOSIT - 1,
            &bob,
            1
        )]),
        bad(0, PayoutError::BelowMinimum)
    );
    // Too many in one block, even if each is fine.
    let many: Vec<_> = (0..=MAX_PAYOUTS_PER_BLOCK as u64)
        .map(|i| payout(DevAccount::Direct, i, MIN_PACKAGE_DEPOSIT, &bob, 10 + i))
        .collect();
    assert_eq!(check(&many), Err(BlockError::TooManyPayouts));
    // A non-canonical owner is rejected before anything hashes it.
    let mut odd = payout(DevAccount::Direct, 0, direct, &bob, 1);
    odd.owner = Digest([0xff; 32]);
    assert_eq!(check(&[odd]), Err(BlockError::NonCanonical));

    // A chain without development-fund keys accepts no payout at all.
    let keyless = siworld_core::params::ChainParams {
        dev_fund_keys: None,
        ..p.clone()
    };
    let body = body_with(&[payout(DevAccount::Direct, 0, direct, &bob, 1)]).unwrap();
    assert_eq!(
        transition(s, &body, h, &keyless).map(|_| ()),
        Err(BlockError::BadPayout {
            index: 0,
            error: PayoutError::NoKeys
        })
    );
}

/// A payout accepted once cannot be replayed: its counter is spent.
#[test]
fn a_payout_cannot_be_replayed() {
    let (mut node, _) = chain_of(COINBASE_MATURITY + 2);
    let p = node.params.clone();
    let bob: SpendKey = key(2);
    let half = spendable(&node.state, DevAccount::Direct) / 2;
    let first = payout(DevAccount::Direct, 0, half, &bob, 1);
    let h = COINBASE_MATURITY + 3;
    let block = build_with_payouts(&node.state, &p, &[], &[first], h).unwrap();
    node.apply_block(&block).unwrap();
    // Enough balance remains, but the counter has moved on.
    assert!(spendable(&node.state, DevAccount::Direct) >= half);
    let replay = build_with_payouts(&node.state, &p, &[], &[first], h + 1);
    assert!(matches!(
        replay,
        Err(siworld_consensus::BuildError::Invalid(
            BlockError::BadPayout {
                index: 0,
                error: PayoutError::Counter
            }
        ))
    ));
}
