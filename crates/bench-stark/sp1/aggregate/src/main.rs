//! Binary aggregation guest: verifies the left and right child proofs inside the zkVM and outputs
//!   leaf_vk (32 B) ‖ child_vk (32 B) ‖ left payload ‖ right payload
//! - Level 1 (children are slot proofs): leaf_vk = the vk used for this verification (the slot
//!   program), child_vk = the aggregation-program vk given as input (unchecked here; checked by
//!   the next level up or by the root verifier), payload = the child public values.
//! - Higher levels (children are aggregation proofs): both children must have the same leaf_vk,
//!   and their child_vk must equal the vk used for this verification; payload = the child public
//!   values without their first 64 bytes.
//! The root verifier checks: root vk = aggregation-program vk, child_vk in the output =
//! aggregation-program vk, and leaf_vk = slot-program vk. Hence every node at level 2 and above
//! verifies its children with the aggregation-program vk, and every level-1 node verifies its
//! leaves with the slot-program vk.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

fn vk_bytes(vk: &[u32; 8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, w) in vk.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    b
}

pub fn main() {
    let vkey: [u32; 8] = sp1_zkvm::io::read();
    let children_are_leaves: bool = sp1_zkvm::io::read();
    let agg_vk: [u32; 8] = sp1_zkvm::io::read();
    let left: Vec<u8> = sp1_zkvm::io::read();
    let right: Vec<u8> = sp1_zkvm::io::read();
    for pv in [&left, &right] {
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &Sha256::digest(pv).into());
    }
    let vk = vk_bytes(&vkey);
    let mut out = Vec::with_capacity(64 + left.len() + right.len());
    if children_are_leaves {
        out.extend_from_slice(&vk);
        out.extend_from_slice(&vk_bytes(&agg_vk));
        out.extend_from_slice(&left);
        out.extend_from_slice(&right);
    } else {
        assert!(left.len() >= 64 && right.len() >= 64);
        assert_eq!(left[..32], right[..32], "children have different leaf vks");
        assert_eq!(left[32..64], vk, "left child was not aggregated with this vk");
        assert_eq!(right[32..64], vk, "right child was not aggregated with this vk");
        out.extend_from_slice(&left[..32]);
        out.extend_from_slice(&vk);
        out.extend_from_slice(&left[64..]);
        out.extend_from_slice(&right[64..]);
    }
    sp1_zkvm::io::commit_slice(&out);
}
