//! Applying a block changes the state in place: the roots the validator checks
//! the header against are exactly the roots the state reaches.

mod common;

use common::*;
use siworld_core::params::ChainParams;

#[test]
fn applied_state_reaches_the_checked_roots_past_the_anchor_window() {
    let p = ChainParams {
        anchor_window: 2,
        ..params()
    };
    let (state, _) = genesis(&p, &[]);
    let mut node = chain(&p, state);
    for tag in 1..=5 {
        let parent_anchors = node.state.anchors.accumulator_root();
        let block = build(&node.state, &p, &[], tag).unwrap();
        let roots = node.apply_block(&block).unwrap();
        assert_eq!(node.state.roots(), roots);
        assert_eq!(node.state.height, tag);
        assert_eq!(node.state.tip, block.header.hash());
        assert_eq!(node.state.prev_anchors_root, Some(parent_anchors));
        assert_eq!(node.state.anchors.latest().map(|(_, h)| h), Some(tag));
        assert_eq!(
            node.state.commitments.len(),
            tag * (2 * u64::from(p.container_size) + 1)
        );
    }
}
