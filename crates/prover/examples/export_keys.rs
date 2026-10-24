//! Writes the root verifying key of each container size named on the command
//! line to `crates/prover/keys/root-n{N}.bin`, at the decided FRI parameters,
//! by building the aggregation circuits as a miner does. Where a key is
//! already pinned, the build fails unless it reproduces the same bytes.
//!
//! ```text
//! cargo run --release -p siworld-prover --example export_keys -- 2 4 8
//! ```

use std::path::Path;
use std::time::Instant;

use siworld_core::params::ChainParams;
use siworld_prover::{pinned_root_key, Plonky3System};

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("keys");
    for arg in std::env::args().skip(1) {
        let n: u32 = arg.parse().expect("a container size");
        let params = ChainParams {
            container_size: n,
            ..ChainParams::mainnet()
        };
        let started = Instant::now();
        let system = Plonky3System::for_miner(&params).expect("setup");
        let path = dir.join(format!("root-n{n}.bin"));
        match pinned_root_key(n) {
            Some(pinned) => {
                assert_eq!(pinned, system.root_key());
                println!(
                    "N = {n}: rebuilt the pinned key in {} s",
                    started.elapsed().as_secs()
                );
            }
            None => {
                std::fs::write(&path, system.root_key()).expect("write key");
                println!(
                    "N = {n}: wrote {} ({} B) in {} s",
                    path.display(),
                    system.root_key().len(),
                    started.elapsed().as_secs()
                );
            }
        }
    }
}
