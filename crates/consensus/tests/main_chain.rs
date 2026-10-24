//! The main chain a node reports to peers: which block is at each height, how
//! the tip moved, and which blocks a lagging or forked peer is missing.

mod common;

use common::*;
use siworld_circuits::MockVerifier;
use siworld_consensus::{Chain, TipChange};
use siworld_core::{Block, Digest};

/// Extends `node`'s tip with `n` empty blocks on schedule; returns them.
fn extend(node: &mut Chain<MockVerifier>, n: u64, tag: u64) -> Vec<Block> {
    (0..n)
        .map(|i| {
            let block = build(&node.state, &node.params, &[], tag + i).unwrap();
            assert_eq!(node.accept(&block).unwrap().tip, TipChange::Extended);
            block
        })
        .collect()
}

fn hashes<'a>(blocks: impl IntoIterator<Item = &'a Block>) -> Vec<Digest> {
    blocks.into_iter().map(|b| b.header.hash()).collect()
}

#[test]
fn extending_the_tip_records_each_height() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut a = chain(&p, state.clone());
    let blocks = extend(&mut a, 3, 1);
    assert_eq!(a.main_hash(0), Some(state.tip));
    for b in &blocks {
        let hash = b.header.hash();
        assert_eq!(a.main_hash(b.header.height), Some(hash));
        assert_eq!(a.block(&hash), Some(b));
    }
    assert_eq!(a.main_hash(4), None);
    assert_eq!(a.block(&state.tip), None, "the base has no block");
}

#[test]
fn a_heavier_branch_reports_its_fork_point_and_replaces_the_heights() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state);
    let shared = extend(&mut a, 2, 1);
    for block in &shared {
        b.accept(block).unwrap();
    }
    let own = extend(&mut a, 1, 10);
    let rival = extend(&mut b, 2, 100);

    assert_eq!(a.accept(&rival[0]).unwrap().tip, TipChange::None);
    assert_eq!(a.main_hash(3), Some(own[0].header.hash()));
    assert_eq!(
        a.accept(&rival[1]).unwrap().tip,
        TipChange::Reorg { fork: 2 }
    );
    for h in 0..=4 {
        assert_eq!(a.main_hash(h), b.main_hash(h), "height {h}");
    }
    assert_eq!(a.main_hash(5), None);
    // The abandoned block stays known.
    assert_eq!(a.block(&own[0].header.hash()), Some(&own[0]));
}

#[test]
fn locator_starts_at_the_tip_and_ends_at_the_base() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut a = chain(&p, state.clone());
    let blocks = extend(&mut a, 40, 1);
    let loc = a.locator();
    assert_eq!(loc.first(), Some(&blocks[39].header.hash()));
    assert_eq!(loc.last(), Some(&state.tip));
    // Dense near the tip, then exponentially sparse.
    assert_eq!(&loc[..10], &hashes(blocks[30..].iter().rev())[..]);
    assert!(loc.len() < 20);
    assert_eq!(chain(&p, state.clone()).locator(), vec![state.tip]);
}

#[test]
fn blocks_after_serve_a_lagging_or_forked_peer() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state.clone());
    let blocks = extend(&mut a, 30, 1);
    for block in &blocks[..10] {
        b.accept(block).unwrap();
    }
    // A lagging peer gets the rest, at most `max` at a time.
    assert_eq!(
        hashes(a.blocks_after(&b.locator(), 100)),
        hashes(&blocks[10..])
    );
    assert_eq!(
        hashes(a.blocks_after(&b.locator(), 5)),
        hashes(&blocks[10..15])
    );

    // A peer on a fork gets the blocks after the last height they share.
    extend(&mut b, 3, 500);
    assert_eq!(
        hashes(a.blocks_after(&b.locator(), 100)),
        hashes(&blocks[10..])
    );
    // A locator with nothing in common starts after the base; one at the tip
    // gets nothing.
    assert_eq!(
        hashes(a.blocks_after(&[Digest([9; 32])], 3)),
        hashes(&blocks[..3])
    );
    assert!(a.blocks_after(&a.locator(), 100).is_empty());
}
