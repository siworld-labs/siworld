//! Private aggregation scheduling for bounded proving workers.
//!
//! Consensus still uses the pinned binary proof tree.  This schedule limits
//! how many recursive nodes are proved concurrently and keeps all intermediate
//! artifacts private to the producer.  It controls concurrent binary proofs only;
//! it does not implement an eight-input batch circuit or create a
//! new wire format or verifying key.

pub const PRIVATE_WORKER_BATCHES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedAggregationSchedule {
    pub container_size: u32,
    pub worker_batches: usize,
    pub root_outputs: usize,
    pub dummy_fill_required: bool,
}

impl FixedAggregationSchedule {
    pub fn for_container(container_size: u32) -> Option<Self> {
        if !(2..=128).contains(&container_size) || !container_size.is_power_of_two() {
            return None;
        }
        Some(Self {
            container_size,
            worker_batches: PRIVATE_WORKER_BATCHES.min(container_size as usize),
            root_outputs: 1,
            dummy_fill_required: true,
        })
    }

    pub fn validate_leaf_count(self, leaves: usize) -> bool {
        self.container_size as usize == leaves
            && leaves.is_power_of_two()
            && leaves >= 2
            && self.root_outputs == 1
            && self.dummy_fill_required
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_schedule_covers_supported_sizes_and_requires_dummy_fill() {
        for n in [2, 4, 8, 16, 32, 64, 128] {
            let schedule = FixedAggregationSchedule::for_container(n).unwrap();
            assert_eq!(schedule.worker_batches, 2.min(n as usize));
            assert!(schedule.validate_leaf_count(n as usize));
            assert!(!schedule.validate_leaf_count(n as usize - 1));
        }
        assert!(FixedAggregationSchedule::for_container(3).is_none());
        assert!(FixedAggregationSchedule::for_container(256).is_none());
    }
}
