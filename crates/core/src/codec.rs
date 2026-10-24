//! Byte encoding of blocks for storage and relay.
//!
//! Every field is fixed-length and little-endian, in declaration order, as the
//! hashing encodings already lay them out. The only variable parts of a block
//! are the slot count and the proof length, each a u32 before its data. A
//! decoder accepts exactly one encoding of each block: it rejects short input,
//! trailing bytes, and lengths beyond the relay limits below.

use crate::params::{CONTAINER_SIZE_STEPS, MAX_PAYOUTS_PER_BLOCK, SLOT_INPUTS, SLOT_OUTPUTS};
use crate::types::*;

/// Most slots a decoded block may carry: the largest container size.
pub const MAX_SLOTS: usize = CONTAINER_SIZE_STEPS[CONTAINER_SIZE_STEPS.len() - 1] as usize;

/// Longest container proof a node decodes. A relay limit, not a validity rule:
/// the header does not commit to the proof, so a block refused for a long proof
/// is still valid with a shorter one. Provisional until the proof size is
/// measured (docs/security-model.md).
pub const MAX_PROOF_LEN: usize = 4 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The input ends inside a field.
    Truncated,
    /// Bytes remain after the value.
    TrailingBytes,
    /// A length exceeds its limit.
    TooLong,
    /// A byte is not one of an enumeration's values.
    BadValue,
}

/// Reads fixed-length fields from the front of a byte string.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("took N bytes"))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn digest(&mut self) -> Result<Digest, DecodeError> {
        Ok(Digest(self.array()?))
    }

    /// A u32 length, checked against `max`.
    pub fn length(&mut self, max: usize) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(DecodeError::TooLong);
        }
        Ok(n)
    }

    /// Ends decoding; fails if bytes remain.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Decodes a whole byte string with `f`, rejecting trailing bytes.
pub fn decode_all<T>(
    bytes: &[u8],
    f: impl FnOnce(&mut Reader) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(bytes);
    let value = f(&mut r)?;
    r.finish()?;
    Ok(value)
}

impl Header {
    pub const ENCODED_LEN: usize = 4 + 8 + 32 + 8 + 32 + 4 * 32 + 4 + 8;

    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            version: r.u32()?,
            height: r.u64()?,
            parent: r.digest()?,
            timestamp: r.u64()?,
            target: r.array()?,
            state_root: r.digest()?,
            commitment_root: r.digest()?,
            nullifier_root: r.digest()?,
            body_root: r.digest()?,
            container_size: r.u32()?,
            nonce: r.u64()?,
        })
    }
}

impl Slot {
    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let mut nf = [Nullifier(Digest::ZERO); SLOT_INPUTS];
        for x in &mut nf {
            *x = Nullifier(r.digest()?);
        }
        let mut cm = [Commitment(Digest::ZERO); SLOT_OUTPUTS];
        for x in &mut cm {
            *x = Commitment(r.digest()?);
        }
        let mut ct = [Ciphertext([0; CIPHERTEXT_LEN]); SLOT_OUTPUTS];
        for x in &mut ct {
            *x = Ciphertext(r.array()?);
        }
        Ok(Self {
            nf,
            cm,
            ct,
            tag: r.array()?,
        })
    }
}

impl Coinbase {
    pub const ENCODED_LEN: usize = 32 + 3 * 8 + 32 + CIPHERTEXT_LEN + 1;

    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            committee_key: r.digest()?,
            miner_amount: r.u64()?,
            dev_direct_amount: r.u64()?,
            dev_lock_amount: r.u64()?,
            miner_note_cm: Commitment(r.digest()?),
            miner_note_ct: Ciphertext(r.array()?),
            miner_note_tag: r.u8()?,
        })
    }
}

impl Payout {
    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            account: DevAccount::from_byte(r.u8()?).ok_or(DecodeError::BadValue)?,
            counter: r.u64()?,
            amount: r.u64()?,
            owner: r.digest()?,
            rseed: r.digest()?,
            signature: PayoutSignature(r.array()?),
        })
    }
}

impl Block {
    /// `header ‖ coinbase ‖ u32 payout count ‖ payouts ‖ u32 slot count ‖ slots
    /// ‖ u32 proof length ‖ proof`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            Header::ENCODED_LEN
                + Coinbase::ENCODED_LEN
                + 12
                + self.body.payouts.len() * Payout::ENCODED_LEN
                + self.body.slots.len() * Slot::ENCODED_LEN
                + self.proof.0.len(),
        );
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.body.coinbase.encode());
        out.extend_from_slice(&(self.body.payouts.len() as u32).to_le_bytes());
        for payout in &self.body.payouts {
            out.extend_from_slice(&payout.encode());
        }
        out.extend_from_slice(&(self.body.slots.len() as u32).to_le_bytes());
        for slot in &self.body.slots {
            out.extend_from_slice(&slot.encode());
        }
        out.extend_from_slice(&(self.proof.0.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof.0);
        out
    }

    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let header = Header::read(r)?;
        let coinbase = Coinbase::read(r)?;
        let n = r.length(MAX_PAYOUTS_PER_BLOCK)?;
        let payouts = (0..n).map(|_| Payout::read(r)).collect::<Result<_, _>>()?;
        let n = r.length(MAX_SLOTS)?;
        let slots = (0..n).map(|_| Slot::read(r)).collect::<Result<_, _>>()?;
        let proof_len = r.length(MAX_PROOF_LEN)?;
        let proof = ContainerProof(r.take(proof_len)?.to_vec());
        Ok(Self {
            header,
            body: BlockBody {
                coinbase,
                payouts,
                slots,
            },
            proof,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_all(bytes, Self::read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SIGNATURE_LEN;

    fn payout(i: u8) -> Payout {
        Payout {
            account: if i.is_multiple_of(2) {
                DevAccount::Direct
            } else {
                DevAccount::Lock
            },
            counter: u64::from(i),
            amount: u64::from(i) * 1_000,
            owner: Digest([i; 32]),
            rseed: Digest([i + 1; 32]),
            signature: PayoutSignature([i + 4; SIGNATURE_LEN]),
        }
    }

    fn block(slots: usize, proof: usize) -> Block {
        block_with(slots, proof, 0)
    }

    fn block_with(slots: usize, proof: usize, payouts: usize) -> Block {
        let slot = |i: u8| Slot {
            nf: [Nullifier(Digest([i; 32])), Nullifier(Digest([i + 1; 32]))],
            cm: [
                Commitment(Digest([i + 2; 32])),
                Commitment(Digest([i + 3; 32])),
            ],
            ct: [
                Ciphertext([i + 4; CIPHERTEXT_LEN]),
                Ciphertext([i + 5; CIPHERTEXT_LEN]),
            ],
            tag: [i + 6, i + 7],
        };
        Block {
            header: Header {
                version: 1,
                height: 2,
                parent: Digest([3; 32]),
                timestamp: 4,
                target: [5; 32],
                nonce: 6,
                state_root: Digest([7; 32]),
                commitment_root: Digest([8; 32]),
                nullifier_root: Digest([9; 32]),
                body_root: Digest([10; 32]),
                container_size: 11,
            },
            body: BlockBody {
                coinbase: Coinbase {
                    committee_key: Digest([12; 32]),
                    miner_amount: 13,
                    dev_direct_amount: 14,
                    dev_lock_amount: 15,
                    miner_note_cm: Commitment(Digest([16; 32])),
                    miner_note_ct: Ciphertext([17; CIPHERTEXT_LEN]),
                    miner_note_tag: 18,
                },
                payouts: (0..payouts).map(|i| payout(i as u8)).collect(),
                slots: (0..slots).map(|i| slot(20 + 10 * i as u8)).collect(),
            },
            proof: ContainerProof((0..proof).map(|i| i as u8).collect()),
        }
    }

    #[test]
    fn blocks_round_trip() {
        for (slots, proof, payouts) in [(0, 0, 0), (1, 32, 1), (4, 1000, 0), (2, 7, 8)] {
            let b = block_with(slots, proof, payouts);
            let bytes = b.encode();
            assert_eq!(
                bytes.len(),
                Header::ENCODED_LEN
                    + Coinbase::ENCODED_LEN
                    + 12
                    + payouts * Payout::ENCODED_LEN
                    + slots * Slot::ENCODED_LEN
                    + proof
            );
            assert_eq!(Block::decode(&bytes), Ok(b));
        }
    }

    #[test]
    fn a_payout_with_an_unknown_account_is_rejected() {
        let mut bytes = block_with(0, 0, 1).encode();
        let at = Header::ENCODED_LEN + Coinbase::ENCODED_LEN + 4;
        assert_eq!(bytes[at], 0);
        bytes[at] = 2;
        assert_eq!(Block::decode(&bytes), Err(DecodeError::BadValue));
    }

    #[test]
    fn header_and_coinbase_lengths_match_their_encodings() {
        let b = block(0, 0);
        assert_eq!(b.header.encode().len(), Header::ENCODED_LEN);
        assert_eq!(b.body.coinbase.encode().len(), Coinbase::ENCODED_LEN);
    }

    #[test]
    fn every_truncation_and_any_trailing_byte_is_rejected() {
        let bytes = block_with(2, 5, 1).encode();
        for n in 0..bytes.len() {
            assert_eq!(
                Block::decode(&bytes[..n]),
                Err(DecodeError::Truncated),
                "{n}"
            );
        }
        let mut long = bytes;
        long.push(0);
        assert_eq!(Block::decode(&long), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn lengths_beyond_the_limits_are_rejected_before_reading() {
        let at = Header::ENCODED_LEN + Coinbase::ENCODED_LEN;
        let mut bytes = block(0, 0).encode();
        bytes[at..at + 4].copy_from_slice(&(MAX_PAYOUTS_PER_BLOCK as u32 + 1).to_le_bytes());
        assert_eq!(Block::decode(&bytes), Err(DecodeError::TooLong));

        let mut bytes = block(0, 0).encode();
        bytes[at + 4..at + 8].copy_from_slice(&(MAX_SLOTS as u32 + 1).to_le_bytes());
        assert_eq!(Block::decode(&bytes), Err(DecodeError::TooLong));

        let mut bytes = block(0, 0).encode();
        bytes[at + 8..at + 12].copy_from_slice(&(MAX_PROOF_LEN as u32 + 1).to_le_bytes());
        assert_eq!(Block::decode(&bytes), Err(DecodeError::TooLong));
    }
}
