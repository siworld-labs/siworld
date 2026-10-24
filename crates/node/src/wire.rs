//! Byte encoding of relayed transactions.
//!
//! A pending transaction travels as its slot, the slot proof, the fee opening
//! any producer needs to include it (the fee tier is visible to relays, an
//! accepted leak; docs/protocol.md), and its anti-spam nonce. Fixed-length fields,
//! little-endian, in declaration order.

use siworld_circuits::{FeeOpening, SlotProof};
use siworld_consensus::PendingTx;
use siworld_core::codec::{decode_all, DecodeError, Reader};
use siworld_core::Slot;

/// Longest leaf proof body a node decodes: a Plonky3 accumulator leaf proof is
/// about 160 KiB with its statement (docs/benchmarks.md). Relay policy.
pub const MAX_LEAF_PROOF_LEN: usize = 512 << 10;
/// The fixed part of an encoded transaction: slot, the proof's four digests,
/// the fee opening, the nonce and the body length.
pub const TX_FIXED_LEN: usize = Slot::ENCODED_LEN + 4 * 32 + 8 + 32 + 8 + 4;
/// Longest encoded transaction.
pub const TX_MAX_LEN: usize = TX_FIXED_LEN + MAX_LEAF_PROOF_LEN;

pub fn encode_tx(tx: &PendingTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(TX_FIXED_LEN + tx.proof.body.len());
    out.extend_from_slice(&tx.slot.encode());
    for d in [
        &tx.proof.slot_id,
        &tx.proof.fee_commit,
        &tx.proof.anchor,
        &tx.proof.binding,
    ] {
        out.extend_from_slice(d.as_bytes());
    }
    out.extend_from_slice(&tx.fee.fee.to_le_bytes());
    out.extend_from_slice(tx.fee.blind.as_bytes());
    out.extend_from_slice(&tx.nonce.to_le_bytes());
    out.extend_from_slice(&(tx.proof.body.len() as u32).to_le_bytes());
    out.extend_from_slice(&tx.proof.body);
    out
}

pub fn decode_tx(bytes: &[u8]) -> Result<PendingTx, DecodeError> {
    decode_all(bytes, |r: &mut Reader| {
        let slot = Slot::read(r)?;
        let (slot_id, fee_commit, anchor, binding) =
            (r.digest()?, r.digest()?, r.digest()?, r.digest()?);
        let fee = FeeOpening {
            fee: r.u64()?,
            blind: r.digest()?,
        };
        let nonce = r.u64()?;
        let len = r.length(MAX_LEAF_PROOF_LEN)?;
        let body = r.take(len)?.to_vec();
        Ok(PendingTx {
            slot,
            proof: SlotProof {
                slot_id,
                fee_commit,
                anchor,
                binding,
                body,
            },
            fee,
            nonce,
        })
    })
}

#[cfg(test)]
mod tests {
    use siworld_core::{Ciphertext, Commitment, Digest, Nullifier, CIPHERTEXT_LEN};

    use super::*;

    fn tx() -> PendingTx {
        PendingTx {
            slot: Slot {
                nf: [Nullifier(Digest([1; 32])), Nullifier(Digest([2; 32]))],
                cm: [Commitment(Digest([3; 32])), Commitment(Digest([4; 32]))],
                ct: [
                    Ciphertext([5; CIPHERTEXT_LEN]),
                    Ciphertext([6; CIPHERTEXT_LEN]),
                ],
                tag: [7, 8],
            },
            proof: SlotProof {
                slot_id: Digest([9; 32]),
                fee_commit: Digest([10; 32]),
                anchor: Digest([11; 32]),
                binding: Digest([12; 32]),
                body: vec![16; 1000],
            },
            fee: FeeOpening {
                fee: 13,
                blind: Digest([14; 32]),
            },
            nonce: 15,
        }
    }

    #[test]
    fn transactions_round_trip_and_reject_other_lengths() {
        let bytes = encode_tx(&tx());
        assert_eq!(bytes.len(), TX_FIXED_LEN + 1000);
        let back = decode_tx(&bytes).unwrap();
        assert_eq!(encode_tx(&back), bytes);
        let mut empty = tx();
        empty.proof.body.clear();
        assert_eq!(encode_tx(&empty).len(), TX_FIXED_LEN);
        assert_eq!(
            decode_tx(&encode_tx(&empty)).map(|t| t.proof.body),
            Ok(vec![])
        );
        // A body longer than the relay limit is refused before it is read.
        let mut long = tx();
        long.proof.body = vec![0; MAX_LEAF_PROOF_LEN + 1];
        assert_eq!(
            decode_tx(&encode_tx(&long)).map(|_| ()),
            Err(DecodeError::TooLong)
        );
        assert_eq!(
            decode_tx(&bytes[..bytes.len() - 1]).map(|_| ()),
            Err(DecodeError::Truncated)
        );
        let mut long = bytes;
        long.push(0);
        assert_eq!(
            decode_tx(&long).map(|_| ()),
            Err(DecodeError::TrailingBytes)
        );
    }
}
