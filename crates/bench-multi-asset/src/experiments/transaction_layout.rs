//! Unreferenced layout prototype for the native multi-asset transaction AIR.
//!
//! This module is deliberately absent from `lib.rs` and the proof scanner. It
//! transforms trace coordinates, not constraints, and cannot produce or verify
//! a proof. The corresponding AIR and adversarial tests are required before use.
//!
//! Structural tests can run independently with `rustc --test`.

use std::collections::BTreeSet;
use std::ops::Range;

pub const BASELINE_MAIN_WIDTH: usize = 1420;
pub const SLOT_MAIN_WIDTH: usize = 1067;
pub const PRIVATE_STATEMENT_WIDTH: usize = 97;
pub const PERMUTATION_WIDTH: usize = 239;
pub const SLOT_HASH_ROWS: usize = 132;
pub const RANGE_ROWS: usize = 168;
pub const RECENT_ROOT_DEPTH: usize = 12;
pub const BASE_HEIGHT: usize = 256;
pub const PATH_START: usize = SLOT_MAIN_WIDTH + PRIVATE_STATEMENT_WIDTH;
pub const BIT: usize = PERMUTATION_WIDTH;
pub const RANGE_VALUE: usize = BIT + 1;
pub const RANGE_BITS: usize = RANGE_VALUE + 1;
pub const ANCHOR_HEIGHT_LOW: usize = 1011;
pub const ASSET_MATCH_START: usize = 642;
pub const ASSET_MATCH_CELL: usize = 17;
pub const UNUSED_FEE_CARRIES: Range<usize> = 621..630;

/// One of the three references is compared with each of the five notes.
/// Input reference 0/1 aliases note 0/1. Reference 2 is the all-zero SIP ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetRef {
    Note(usize),
    Sip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EqualityBinding {
    EqualToSelf,
    /// An unordered pair has one equality flag and one inequality certificate.
    Cell(AssetRef, AssetRef),
}

pub fn equality_binding(group: usize, note: usize) -> EqualityBinding {
    assert!(group < 3 && note < 5);
    let a = if group < 2 {
        AssetRef::Note(group)
    } else {
        AssetRef::Sip
    };
    let b = AssetRef::Note(note);
    if a == b {
        EqualityBinding::EqualToSelf
    } else if a < b {
        EqualityBinding::Cell(a, b)
    } else {
        EqualityBinding::Cell(b, a)
    }
}

#[derive(Clone, Debug)]
pub struct LayoutPlan {
    pub height: usize,
    pub path_rows: Range<usize>,
    /// Retained baseline columns in their new order. Reused permutation/range
    /// cells are overwritten only on newly scheduled recent-root path rows.
    pub retained_columns: Vec<usize>,
}

impl LayoutPlan {
    pub fn new(height: usize) -> Result<Self, &'static str> {
        if !height.is_power_of_two() {
            return Err("trace height is not a power of two");
        }
        let start = SLOT_HASH_ROWS.max(RANGE_ROWS);
        if height < start + RECENT_ROOT_DEPTH {
            return Err("recent-root path overlaps live hash or range rows");
        }
        // The canonical pair (input 0, input 1) is retained at group 0/note 1.
        // Remove the reverse pair and both tautological self-comparisons.
        let redundant_cells = [(0, 0), (1, 0), (1, 1)];
        let removed_match_columns: BTreeSet<_> = redundant_cells
            .into_iter()
            .flat_map(|(group, note)| {
                let start = ASSET_MATCH_START + (group * 5 + note) * ASSET_MATCH_CELL;
                start..start + ASSET_MATCH_CELL
            })
            .collect();
        let retained_columns = (0..PATH_START)
            .filter(|col| !UNUSED_FEE_CARRIES.contains(col) && !removed_match_columns.contains(col))
            .collect();
        Ok(Self {
            height,
            path_rows: start..start + RECENT_ROOT_DEPTH,
            retained_columns,
        })
    }

    pub fn main_width(&self) -> usize {
        self.retained_columns.len()
    }

    /// Repack a reference trace's encoded cells. Values here are canonical test
    /// coordinates, not Montgomery representations or a proof serialization.
    /// This does not validate Poseidon2, integer balances or membership.
    pub fn repack(&self, reference: &[u32]) -> Result<Vec<u32>, &'static str> {
        if reference.len() != self.height * BASELINE_MAIN_WIDTH {
            return Err("reference trace dimensions differ from the layout");
        }
        let anchor_low = reference[ANCHOR_HEIGHT_LOW];
        if anchor_low > u16::MAX.into() {
            return Err("anchor low limb is not a canonical u16");
        }
        let mut packed = Vec::with_capacity(self.height * self.main_width());
        for row in 0..self.height {
            let base = row * BASELINE_MAIN_WIDTH;
            packed.extend(
                self.retained_columns
                    .iter()
                    .map(|&col| reference[base + col]),
            );
            if self.path_rows.contains(&row) {
                let level = row - self.path_rows.start;
                let old_path = level * BASELINE_MAIN_WIDTH + PATH_START;
                let target = row * self.main_width();
                packed[target..target + PERMUTATION_WIDTH]
                    .copy_from_slice(&reference[old_path..old_path + PERMUTATION_WIDTH]);
                // These cells are not register columns. The reference range
                // schedule no longer selects a limb on any of these rows.
                let index = anchor_low >> level;
                packed[target + BIT] = index & 1;
                packed[target + RANGE_VALUE] = index;
                for bit in 0..16 {
                    packed[target + RANGE_BITS + bit] = (index >> bit) & 1;
                }
            }
        }
        Ok(packed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_schedule_preserves_hash_and_range_coverage_without_height_growth() {
        let plan = LayoutPlan::new(BASE_HEIGHT).unwrap();
        assert_eq!(plan.path_rows, 168..180);
        assert!(plan.path_rows.start >= SLOT_HASH_ROWS);
        assert!(plan.path_rows.start >= RANGE_ROWS);
        assert!(plan.path_rows.end <= BASE_HEIGHT);
        assert_eq!(plan.main_width(), 1104);
        assert_eq!(BASELINE_MAIN_WIDTH - plan.main_width(), 316);
        assert!(LayoutPlan::new(128).is_err());
        assert!(LayoutPlan::new(255).is_err());
    }

    #[test]
    fn relocated_path_keeps_every_reference_permutation_cell() {
        let plan = LayoutPlan::new(BASE_HEIGHT).unwrap();
        let mut reference: Vec<u32> = (0..BASE_HEIGHT * BASELINE_MAIN_WIDTH)
            .map(|i| u32::try_from(i).unwrap())
            .collect();
        reference[ANCHOR_HEIGHT_LOW] = 0xa53c;
        let packed = plan.repack(&reference).unwrap();
        for row in 0..SLOT_HASH_ROWS {
            let old = row * BASELINE_MAIN_WIDTH;
            let new = row * plan.main_width();
            assert_eq!(
                &packed[new..new + PERMUTATION_WIDTH],
                &reference[old..old + PERMUTATION_WIDTH]
            );
        }
        for (level, row) in plan.path_rows.clone().enumerate() {
            let old = level * BASELINE_MAIN_WIDTH + PATH_START;
            let new = row * plan.main_width();
            assert_eq!(
                &packed[new..new + PERMUTATION_WIDTH],
                &reference[old..old + PERMUTATION_WIDTH]
            );
            let index = 0xa53c >> level;
            assert_eq!(packed[new + BIT], index & 1);
            assert_eq!(packed[new + RANGE_VALUE], index);
        }
        assert!(plan.repack(&reference[..reference.len() - 1]).is_err());
        reference[ANCHOR_HEIGHT_LOW] = 65536;
        assert!(plan.repack(&reference).is_err());
    }

    #[test]
    fn retained_columns_are_unique_and_no_live_hash_cell_is_removed() {
        let plan = LayoutPlan::new(BASE_HEIGHT).unwrap();
        let set: BTreeSet<_> = plan.retained_columns.iter().copied().collect();
        assert_eq!(set.len(), plan.main_width());
        for column in 0..PERMUTATION_WIDTH {
            assert_eq!(plan.retained_columns[column], column);
        }
        assert!(set.is_disjoint(&UNUSED_FEE_CARRIES.collect()));
        for column in SLOT_MAIN_WIDTH..PATH_START {
            assert!(set.contains(&column));
        }
    }

    #[test]
    fn equality_aliases_preserve_exact_full_identifier_comparison() {
        let mut cells = BTreeSet::new();
        for group in 0..3 {
            for note in 0..5 {
                if let EqualityBinding::Cell(a, b) = equality_binding(group, note) {
                    cells.insert((a, b));
                }
            }
        }
        assert_eq!(cells.len(), 12);
        assert_eq!(equality_binding(0, 0), EqualityBinding::EqualToSelf);
        assert_eq!(equality_binding(1, 1), EqualityBinding::EqualToSelf);
        assert_eq!(equality_binding(0, 1), equality_binding(1, 0));

        // Every limb can be the sole distinguishing limb. No compressed hash
        // replaces exact equality of the sixteen canonical limbs.
        for differing_limb in 0..16 {
            let mut ids = [[0u16; 16]; 5];
            for (note, id) in ids.iter_mut().enumerate() {
                id[differing_limb] = [0, 1, 1, 65535, 32768][note];
            }
            for group in 0..3 {
                for note in 0..5 {
                    let reference = if group < 2 { ids[group] } else { [0; 16] };
                    let actual = match equality_binding(group, note) {
                        EqualityBinding::EqualToSelf => true,
                        EqualityBinding::Cell(a, b) => {
                            let value = |r| match r {
                                AssetRef::Note(i) => ids[i],
                                AssetRef::Sip => [0; 16],
                            };
                            value(a) == value(b)
                        }
                    };
                    assert_eq!(actual, reference == ids[note]);
                }
            }
        }
    }

    #[test]
    fn reused_range_cells_bind_path_directions_for_all_low_height_limbs() {
        for low in 0..=u16::MAX {
            let mut index = u32::from(low);
            for level in 0..RECENT_ROOT_DEPTH {
                let bits: [u32; 16] = std::array::from_fn(|i| (index >> i) & 1);
                let recomposed: u32 = bits.iter().enumerate().map(|(i, &b)| b << i).sum();
                assert_eq!(recomposed, index);
                assert_eq!(bits[0], (u32::from(low) >> level) & 1);
                let next = index >> 1;
                assert_eq!(2 * next + bits[0], index);
                index = next;
            }
        }
    }
}
