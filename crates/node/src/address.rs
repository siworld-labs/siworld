//! Address strings, format v1 (docs/protocol.md, Wallets and addresses).
//!
//! An address is the owner digest and the 1,184-byte ML-KEM-768 encapsulation
//! key. Its string is a human-readable part (`si` on mainnet, `tsi` on a
//! testnet), the separator `1`, and the base32 (Bech32 alphabet) of
//! `owner ‖ key ‖ checksum`, where the checksum is the first 5 bytes of
//! `BLAKE3-derive_key("siworld address v1", hrp ‖ owner ‖ key)`: 1,958
//! characters on a testnet. A 40-bit checksum, rather than Bech32's BCH code,
//! because the payload is far past the 90 characters that code protects; it
//! rejects a mistyped, truncated or mis-prefixed address with probability
//! 1 − 2^-40 instead of locking funds to a key nobody holds. Lowercase is
//! canonical; an all-uppercase string (as QR codes prefer) is accepted; mixed
//! case is not.

use siworld_core::Digest;
use siworld_crypto::{domain_hash, Address, ENCAPSULATION_KEY_LEN};

/// Which network an address string names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "si",
            Self::Testnet => "tsi",
        }
    }
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHECKSUM_LEN: usize = 5;
const BODY_LEN: usize = 32 + ENCAPSULATION_KEY_LEN;
/// Characters after the separator: ⌈(BODY_LEN + CHECKSUM_LEN) · 8 / 5⌉.
const DATA_CHARS: usize = ((BODY_LEN + CHECKSUM_LEN) * 8).div_ceil(5);

fn checksum(hrp: &str, body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let d = domain_hash("siworld address v1", &[hrp.as_bytes(), body]);
    d.as_bytes()[..CHECKSUM_LEN]
        .try_into()
        .expect("digest is longer")
}

fn base32_encode(bytes: &[u8], out: &mut String) {
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CHARSET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CHARSET[((acc << (5 - bits)) & 31) as usize] as char);
    }
}

/// Decodes `chars`, which must be lowercase, into exactly `n` bytes; `None` on
/// a character outside the alphabet, a length that does not hold `n` bytes,
/// or non-zero padding bits.
fn base32_decode(chars: &[u8], n: usize) -> Option<Vec<u8>> {
    if chars.len() != (n * 8).div_ceil(5) {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in chars {
        let v = CHARSET.iter().position(|&x| x == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // The leftover bits are padding and must be zero.
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

pub fn encode_address_for(network: Network, address: &Address) -> String {
    let hrp = network.hrp();
    let mut body = Vec::with_capacity(BODY_LEN + CHECKSUM_LEN);
    body.extend_from_slice(address.owner().as_bytes());
    body.extend_from_slice(address.encapsulation_key());
    let sum = checksum(hrp, &body);
    body.extend_from_slice(&sum);
    let mut out = String::with_capacity(hrp.len() + 1 + DATA_CHARS);
    out.push_str(hrp);
    out.push('1');
    base32_encode(&body, &mut out);
    out
}

/// Parses an address string of `network`; `None` if it is malformed, names
/// another network, fails its checksum, or its key fails [`Address::new`]'s
/// checks.
pub fn parse_address_for(network: Network, s: &str) -> Option<Address> {
    let s = s.trim();
    if !s.is_ascii() {
        return None;
    }
    let lower = if s.bytes().any(|b| b.is_ascii_uppercase()) {
        if s.bytes().any(|b| b.is_ascii_lowercase()) {
            return None;
        }
        s.to_ascii_lowercase()
    } else {
        s.to_string()
    };
    let hrp = network.hrp();
    let data = lower
        .strip_prefix(hrp)
        .and_then(|rest| rest.strip_prefix('1'))?;
    let bytes = base32_decode(data.as_bytes(), BODY_LEN + CHECKSUM_LEN)?;
    let (body, sum) = bytes.split_at(BODY_LEN);
    if checksum(hrp, body) != sum {
        return None;
    }
    let owner = Digest(body[..32].try_into().expect("32 bytes"));
    let ek: [u8; ENCAPSULATION_KEY_LEN] = body[32..].try_into().ok()?;
    Address::new(owner, ek)
}

/// The testnet string of an address.
pub fn encode_address(address: &Address) -> String {
    encode_address_for(Network::Testnet, address)
}

/// Parses a testnet address string (see [`parse_address_for`]).
pub fn parse_address(s: &str) -> Option<Address> {
    parse_address_for(Network::Testnet, s)
}

#[cfg(test)]
mod tests {
    use siworld_crypto::SpendKey;

    use super::*;

    fn address() -> Address {
        SpendKey::from_digest(Digest([1; 32])).address()
    }

    #[test]
    fn addresses_round_trip_in_either_case() {
        let s = encode_address(&address());
        assert!(s.starts_with("tsi1"));
        assert_eq!(s.len(), 4 + DATA_CHARS);
        assert_eq!(s.len(), 1_958);
        assert!(s[4..].bytes().all(|b| CHARSET.contains(&b)));
        assert_eq!(parse_address(&s), Some(address()));
        assert_eq!(parse_address(&s.to_ascii_uppercase()), Some(address()));
        assert_eq!(parse_address(&format!("  {s}\n")), Some(address()));

        let m = encode_address_for(Network::Mainnet, &address());
        assert!(m.starts_with("si1"));
        assert_eq!(parse_address_for(Network::Mainnet, &m), Some(address()));
        // The checksum covers the prefix: a mainnet string is not a testnet one.
        assert_eq!(parse_address(&m), None);
        assert_eq!(parse_address(&format!("t{m}")), None);
        assert_eq!(parse_address_for(Network::Mainnet, &s), None);
    }

    #[test]
    fn typos_truncations_and_mixed_case_are_rejected() {
        let s = encode_address(&address());
        assert_eq!(parse_address(&s[..s.len() - 1]), None);
        assert_eq!(parse_address(&s[1..]), None);
        assert_eq!(parse_address(&format!("{s}q")), None);
        assert_eq!(parse_address("tsi1"), None);
        assert_eq!(parse_address("tsi00"), None);
        let mut mixed = s.clone().into_bytes();
        mixed[10] = mixed[10].to_ascii_uppercase();
        assert_eq!(parse_address(std::str::from_utf8(&mixed).unwrap()), None);
        // Every position: one character changed to another of the alphabet.
        let bytes = s.as_bytes();
        for i in (4..s.len()).step_by(97).chain([s.len() - 1]) {
            let mut typo = bytes.to_vec();
            let other = CHARSET.iter().find(|&&c| c != bytes[i]).copied().unwrap();
            typo[i] = other;
            assert_eq!(
                parse_address(std::str::from_utf8(&typo).unwrap()),
                None,
                "{i}"
            );
        }
        // Two characters swapped.
        let mut swapped = bytes.to_vec();
        let (i, j) = (100, 101);
        if swapped[i] != swapped[j] {
            swapped.swap(i, j);
            assert_eq!(parse_address(std::str::from_utf8(&swapped).unwrap()), None);
        }
        // A character outside the alphabet.
        let mut bad = bytes.to_vec();
        bad[50] = b'b';
        assert_eq!(parse_address(std::str::from_utf8(&bad).unwrap()), None);
    }

    #[test]
    fn base32_rejects_non_zero_padding() {
        let mut out = String::new();
        base32_encode(&[0xff; 3], &mut out);
        assert_eq!(out.len(), 5);
        assert_eq!(base32_decode(out.as_bytes(), 3), Some(vec![0xff; 3]));
        // 3 bytes are 24 bits in 5 characters: the last character's low bit is
        // padding and must be zero.
        let mut chars = out.into_bytes();
        let last = CHARSET.iter().position(|&c| c == chars[4]).unwrap();
        chars[4] = CHARSET[last | 1];
        assert_eq!(base32_decode(&chars, 3), None);
    }
}
