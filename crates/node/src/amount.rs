//! Text representation of SIP amounts. Integer arithmetic only: 1 SIP = 10^8 atom.

use siworld_core::params::ATOMS_PER_SIP;

const DECIMALS: usize = 8;

/// Parses decimal SIP amounts such as `"12"`, `"0.5"`, or `"1.00000001"` into atoms.
/// Returns `None` for more than 8 decimal places, an empty string, or overflow.
pub fn parse_sip(s: &str) -> Option<u64> {
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
    whole.checked_mul(ATOMS_PER_SIP)?.checked_add(frac_atoms)
}

/// atom → `"<integer>.<up to 8 decimals>"`, with trailing zeros removed.
pub fn format_sip(atoms: u64) -> String {
    let whole = atoms / ATOMS_PER_SIP;
    let frac = atoms % ATOMS_PER_SIP;
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
    fn parses_decimal_sip() {
        assert_eq!(parse_sip("1"), Some(ATOMS_PER_SIP));
        assert_eq!(parse_sip("0.5"), Some(ATOMS_PER_SIP / 2));
        assert_eq!(parse_sip(".25"), Some(ATOMS_PER_SIP / 4));
        assert_eq!(parse_sip("1.00000001"), Some(ATOMS_PER_SIP + 1));
        assert_eq!(parse_sip("3."), Some(3 * ATOMS_PER_SIP));
    }

    #[test]
    fn rejects_bad_amounts() {
        for s in ["", ".", "1.000000001", "-1", "1e3", "abc", "184467440738"] {
            assert_eq!(parse_sip(s), None, "{s}");
        }
    }

    #[test]
    fn formats_round_trip() {
        for a in [0, 1, 10_000, ATOMS_PER_SIP, ATOMS_PER_SIP * 7 / 4, u64::MAX] {
            assert_eq!(parse_sip(&format_sip(a)), Some(a));
        }
        assert_eq!(format_sip(ATOMS_PER_SIP * 3 / 2), "1.5");
    }
}
