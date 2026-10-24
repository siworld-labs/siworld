//! Single-slot guest: reads the witness word stream, runs the native relation check, and commits
//! 48 public field elements (little-endian u32, 192 bytes).
//! Poseidon2 (KoalaBear) is implemented purely in software inside the zkVM; there is no precompile.
#![no_main]
sp1_zkvm::entrypoint!(main);

use siworld_bench_common::{Hasher, SlotWitness};

pub fn main() {
    let words: Vec<u32> = sp1_zkvm::io::read();
    let w = SlotWitness::from_words(&words).expect("witness encoding");
    let pi = w.check(&Hasher::new()).expect("slot relation");
    let bytes: Vec<u8> = pi.to_u32s().iter().flat_map(|x| x.to_le_bytes()).collect();
    sp1_zkvm::io::commit_slice(&bytes);
}
