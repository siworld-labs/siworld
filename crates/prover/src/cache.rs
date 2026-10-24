//! One in-memory tree of completed non-root proofs. No production telemetry.

use std::collections::BTreeMap;
use std::sync::Arc;

use siworld_core::Digest;
use siworld_crypto::domain_hash;

pub(crate) struct TreeCache<T> {
    leaves: Vec<Digest>,
    levels: Vec<Vec<(Digest, Arc<T>)>>,
}

impl<T> Default for TreeCache<T> {
    fn default() -> Self {
        Self {
            leaves: Vec::new(),
            levels: Vec::new(),
        }
    }
}

pub(crate) struct Plan {
    pub order: Vec<usize>,
    pub keys: Vec<Vec<Digest>>,
    leaves: Vec<Digest>,
}

impl<T> TreeCache<T> {
    pub fn plan(&self, ids: &[Digest], anchor: Digest) -> Option<Plan> {
        if ids.len() < 2 || !ids.len().is_power_of_two() {
            return None;
        }
        let mut remaining: BTreeMap<_, _> =
            ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        if remaining.len() != ids.len() {
            return None;
        }
        // Wire slots are sorted, but recursive aggregation is order independent.
        // Preserve surviving positions so one insertion does not shift the tree.
        let mut positions = vec![None; ids.len()];
        if self.leaves.len() == ids.len() {
            for (position, old) in self.leaves.iter().enumerate() {
                positions[position] = remaining.remove(old);
            }
        }
        let mut vacancies = remaining.into_values();
        let order: Vec<_> = positions
            .into_iter()
            .map(|p| p.unwrap_or_else(|| vacancies.next().expect("one vacancy per new leaf")))
            .collect();
        let leaves: Vec<_> = order.iter().map(|&i| ids[i]).collect();
        let mut current = leaves.clone();
        let mut keys = Vec::new();
        // The root binds height/miner data and is always freshly proved.
        while current.len() > 2 {
            current = current
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| {
                    domain_hash(
                        "siworld local aggregate cache node v1",
                        &[
                            anchor.as_bytes(),
                            &(keys.len() as u32).to_le_bytes(),
                            p[0].as_bytes(),
                            p[1].as_bytes(),
                        ],
                    )
                })
                .collect();
            keys.push(current.clone());
        }
        Some(Plan {
            order,
            keys,
            leaves,
        })
    }

    pub fn get(&self, level: usize, position: usize, key: Digest) -> Option<Arc<T>> {
        let (old, value) = self.levels.get(level)?.get(position)?;
        (*old == key).then(|| value.clone())
    }

    pub fn commit(&mut self, plan: Plan, levels: Vec<Vec<Arc<T>>>) {
        debug_assert_eq!(plan.keys.len(), levels.len());
        self.leaves = plan.leaves;
        self.levels = plan
            .keys
            .into_iter()
            .zip(levels)
            .map(|(keys, nodes)| keys.into_iter().zip(nodes).collect())
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<Digest> {
        (1..=32).map(|i| Digest([i; 32])).collect()
    }
    fn populate(cache: &mut TreeCache<usize>, ids: &[Digest], anchor: Digest) {
        let p = cache.plan(ids, anchor).unwrap();
        let levels = p
            .keys
            .iter()
            .map(|keys| keys.iter().map(|_| Arc::new(1)).collect())
            .collect();
        cache.commit(p, levels);
    }
    fn misses(cache: &TreeCache<usize>, ids: &[Digest], anchor: Digest) -> usize {
        let plan = cache.plan(ids, anchor).unwrap();
        1 + plan
            .keys
            .iter()
            .enumerate()
            .map(|(level, keys)| {
                keys.iter()
                    .enumerate()
                    .filter(|&(i, k)| cache.get(level, i, *k).is_none())
                    .count()
            })
            .sum::<usize>()
    }

    #[test]
    fn n32_one_replacement_reproves_five_nodes_despite_wire_reordering() {
        let mut cache = TreeCache::default();
        let mut leaves = ids();
        let anchor = Digest([99; 32]);
        assert_eq!(misses(&cache, &leaves, anchor), 31);
        populate(&mut cache, &leaves, anchor);
        assert_eq!(misses(&cache, &leaves, anchor), 1);
        leaves[3] = Digest([80; 32]);
        leaves.reverse();
        assert_eq!(misses(&cache, &leaves, anchor), 5);
        assert_eq!(misses(&cache, &leaves, Digest([98; 32])), 31);
    }

    #[test]
    fn duplicate_leaves_and_bad_shapes_are_refused_without_mutation() {
        let mut cache = TreeCache::default();
        let leaves = ids();
        let anchor = Digest([99; 32]);
        populate(&mut cache, &leaves, anchor);
        assert!(cache.plan(&[leaves[0], leaves[0]], anchor).is_none());
        assert!(cache.plan(&leaves[..3], anchor).is_none());
        assert_eq!(misses(&cache, &leaves, anchor), 1);
        assert_eq!(cache.levels.iter().map(Vec::len).sum::<usize>(), 30);
    }
}
