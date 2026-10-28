//! Public integer subsidy audit over the same native transition used by nodes.
//!
//! This verifies every supplied transaction and settlement proof. It audits SI
//! creation and the two credited fund counters, without disclosing fee openings.
//! Native engineering blocks do not yet carry asset issuance or fund payouts;
//! this report must not be described as an audit of those unimplemented paths.
use crate::state::{BlockVerifier, Config, State, subsidy_split};
use crate::wire::{Block, Hash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeightIssuance {
    pub height: u64,
    pub block_id: Hash,
    pub subsidy: u64,
    pub miner_subsidy: u64,
    pub fund_direct: u64,
    pub fund_locked: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    pub network: Hash,
    pub height: u64,
    pub tip: Hash,
    pub fingerprint: Hash,
    pub total_subsidy: u128,
    pub miner_subsidy: u128,
    pub fund_direct: u128,
    pub fund_locked: u128,
    pub heights: Vec<HeightIssuance>,
    pub asset_issuance_supported: bool,
    pub fund_spending_supported: bool,
}
impl AuditReport {
    /// Bind an independently replayed report to the exact accepted chain head.
    pub fn check_head(&self, height: u64, tip: Hash, fingerprint: Hash) -> Result<(), String> {
        if (self.height, self.tip, self.fingerprint) != (height, tip, fingerprint) {
            return Err("issuance audit does not match the accepted state".into());
        }
        Ok(())
    }
}

/// Replay a complete canonical engineering history from the immutable genesis.
/// Callers choose the canonical chain; this function neither selects a fork nor
/// authenticates a downloaded checkpoint. Replaying the replacement chain from
/// genesis naturally removes every orphan subsidy and fund credit.
pub fn replay_chain(
    config: Config,
    blocks: &[Block],
    verifier: &impl BlockVerifier,
) -> Result<(State, AuditReport), String> {
    replay_blocks(config, blocks.iter().cloned().map(Ok), verifier)
}

/// Stream one canonical proof-carrying block at a time. Proof bodies are dropped
/// after each transition; the report retains only public per-height counters.
/// A source read failure aborts instead of producing a partial success report.
pub fn replay_blocks(
    config: Config,
    blocks: impl IntoIterator<Item = Result<Block, String>>,
    verifier: &impl BlockVerifier,
) -> Result<(State, AuditReport), String> {
    let mut state = State::new(config)?;
    let mut heights = Vec::new();
    let mut miner_total = 0u128;
    let mut direct_total = 0u128;
    let mut locked_total = 0u128;
    let mut subsidy_total = 0u128;
    for block in blocks {
        let block = block?;
        state.apply(&block, verifier)?;
        let subsidy =
            siworld_core::issuance::block_reward(siworld_core::issuance::epoch_of(block.height));
        let (miner, direct, locked) = subsidy_split(block.height);
        if u128::from(miner) + u128::from(direct) + u128::from(locked) != u128::from(subsidy) {
            return Err("subsidy split differs from the issuance curve".into());
        }
        subsidy_total = subsidy_total
            .checked_add(u128::from(subsidy))
            .ok_or("subsidy audit overflow")?;
        miner_total = miner_total
            .checked_add(u128::from(miner))
            .ok_or("miner audit overflow")?;
        direct_total = direct_total
            .checked_add(u128::from(direct))
            .ok_or("direct fund audit overflow")?;
        locked_total = locked_total
            .checked_add(u128::from(locked))
            .ok_or("locked fund audit overflow")?;
        if (state.total_subsidy, state.fund_direct, state.fund_locked)
            != (subsidy_total, direct_total, locked_total)
        {
            return Err("accepted issuance counters differ from the integer audit".into());
        }
        heights.push(HeightIssuance {
            height: block.height,
            block_id: state.tip,
            subsidy,
            miner_subsidy: miner,
            fund_direct: direct,
            fund_locked: locked,
        });
    }
    let report = AuditReport {
        network: state.config.network,
        height: state.height,
        tip: state.tip,
        fingerprint: state.fingerprint(),
        total_subsidy: subsidy_total,
        miner_subsidy: miner_total,
        fund_direct: direct_total,
        fund_locked: locked_total,
        heights,
        asset_issuance_supported: false,
        fund_spending_supported: false,
    };
    Ok((state, report))
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::fixtures::{TestVerifier, candidate};

    #[test]
    fn streaming_and_slice_audits_agree_on_the_exact_chain() {
        let config = Config::development([73; 32], 0).unwrap();
        let mut state = State::new(config.clone()).unwrap();
        let first = candidate(&state, 1);
        state.apply(&first, &TestVerifier).unwrap();
        let second = candidate(&state, 100_000);
        let blocks = [first, second];
        let (_, slice_report) = replay_chain(config.clone(), &blocks, &TestVerifier).unwrap();
        let (stream_state, stream_report) =
            replay_blocks(config, blocks.into_iter().map(Ok), &TestVerifier).unwrap();
        assert_eq!(stream_report, slice_report);
        stream_report
            .check_head(
                stream_state.height,
                stream_state.tip,
                stream_state.fingerprint(),
            )
            .unwrap();
    }
    #[test]
    fn streaming_source_failure_aborts_without_consuming_further_blocks() {
        let config = Config::development([74; 32], 0).unwrap();
        let state = State::new(config.clone()).unwrap();
        let first = candidate(&state, 1);
        let source = std::iter::once(Ok(first))
            .chain(std::iter::once(Err("source unavailable".to_owned())))
            .chain(std::iter::from_fn(|| -> Option<Result<Block, String>> {
                panic!("source was consumed after its first failure")
            }));
        assert!(
            matches!(replay_blocks(config, source, &TestVerifier), Err(reason) if reason == "source unavailable")
        );
    }
}
