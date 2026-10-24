//! Text representation of SI amounts. Integer arithmetic only: 1 SI = 10^8 atom.

use siworld_core::params::ATOMS_PER_SI;

const DECIMALS: usize = 8;

/// Parses decimal SI amounts such as `"12"`, `"0.5"`, or `"1.00000001"` into atoms.
/// Returns `None` for more than 8 decimal places, an empty string, or overflow.
pub fn parse_si(s: &str) -> Option<u64> {
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    if frac.len() > DECIMALS || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut frac_atoms: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    for _ in frac.len()..DECIMALS {
        frac_atoms *= 10;
    }
    whole.checked_mul(ATOMS_PER_SI)?.checked_add(frac_atoms)
}

/// atom → `"<integer>.<up to 8 decimals>"`, with trailing zeros removed.
pub fn format_si(atoms: u64) -> String {
    let whole = atoms / ATOMS_PER_SI;
    let frac = atoms % ATOMS_PER_SI;
    if frac == 0 {
        return whole.to_string();
    }
    let digits = format!("{frac:08}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_si() {
        assert_eq!(parse_si("1"), Some(ATOMS_PER_SI));
        assert_eq!(parse_si("0.5"), Some(ATOMS_PER_SI / 2));
        assert_eq!(parse_si(".25"), Some(ATOMS_PER_SI / 4));
        assert_eq!(parse_si("1.00000001"), Some(ATOMS_PER_SI + 1));
        assert_eq!(parse_si("3."), Some(3 * ATOMS_PER_SI));
    }

    #[test]
    fn rejects_bad_amounts() {
        for s in ["", ".", "1.000000001", "-1", "1e3", "abc", "184467440738"] {
            assert_eq!(parse_si(s), None, "{s}");
        }
    }

    #[test]
    fn formats_round_trip() {
        for a in [0, 1, 10_000, ATOMS_PER_SI, ATOMS_PER_SI * 7 / 4, u64::MAX] {
            assert_eq!(parse_si(&format_si(a)), Some(a));
        }
        assert_eq!(format_si(ATOMS_PER_SI * 3 / 2), "1.5");
    }
}
