//! Local block preparation for a disposable native engineering network.
//! Candidate blocks still require the shared durable state transition.

use crate::pool::Padding;
use crate::proofs::NativeProver;
use crate::state::{State, base_fee, subsidy_split, tail_slots};
use crate::wire::{Block, GROUP, MAX_SLOTS, MIN_SLOTS, PublicRecord, RewardRecord, Transaction};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::{FeeOpening, SettlementSlot};
use native::encryption::{
    EncryptionContext, PaymentAddress, PaymentCiphertext, PaymentEncryptionOpening,
    RecipientViewKey, SenderChangeSecret, decrypt_change_at, encrypt_change_at,
    encrypt_payment_with_opening,
};
use native::multi_asset::{
    AccWitness, AnchorTree, F, Hasher, InputWitness, Note, OutputWitness, SI_ASSET_ID, SlotWitness,
    TREE_DEPTH,
};
use native::settlement::FixedSettlementWitness;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub const REWARD_SECRET_BYTES: usize = 4 + 2 + 32 + 8 + 48 + 48 + 48 + 1184 + 32;
const REWARD_SECRET_MAGIC: &[u8; 4] = b"SWRM";
const REWARD_SECRET_VERSION: u16 = 1;

pub struct ProducedBlock {
    pub block: Block,
    /// Private engineering-wallet recovery material. Never log or relay it.
    pub reward_secret: Zeroizing<Vec<u8>>,
}

struct PreparedTransaction {
    witness: AccWitness,
    public: PublicTransaction,
    record: PublicRecord,
    opening: FeeOpening,
}
#[cfg(test)]
impl PreparedTransaction {
    fn opening_commitment(&self) -> native::multi_asset::Digest {
        Hasher::new().fee_commit(self.opening.fee, &self.opening.blind)
    }
}

struct PreparedReward {
    record: RewardRecord,
    note: Note,
    secret: Zeroizing<Vec<u8>>,
}

fn fields_from_entropy<const N: usize>(
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<[F; N], String> {
    let mut out = [F::ZERO; N];
    let mut filled = 0;
    let mut entropy = Zeroizing::new([0u8; 64]);
    while filled < N {
        fill(entropy.as_mut())?;
        for word in entropy.as_chunks::<4>().0 {
            let raw = u32::from_le_bytes(*word);
            if raw < F::ORDER_U32 {
                out[filled] = F::from_u32(raw);
                filled += 1;
                if filled == N {
                    break;
                }
            }
        }
    }
    Ok(out)
}

fn random_fields<const N: usize>() -> Result<[F; N], String> {
    fields_from_entropy(&mut |bytes| {
        getrandom::fill(bytes).map_err(|_| "operating-system randomness unavailable".to_owned())
    })
}

fn context(state: &State) -> ProofContext {
    let snapshot = state.tip_snapshot().selector;
    ProofContext::for_snapshot(state.config.network, snapshot.height, snapshot.block_id)
}

fn same_note(left: &Note, right: &Note) -> bool {
    left.asset_id == right.asset_id
        && left.owner == right.owner
        && left.value == right.value
        && left.unlock_height == right.unlock_height
        && left.rho == right.rho
        && left.rseed == right.rseed
}

fn check_count(count: usize) -> Result<(), String> {
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
        return Err("engineering block positions must be 64 through 576 in groups of 16".into());
    }
    Ok(())
}

/// Prepare an empty position against the actual canonical tip. Both zero-value
/// inputs still get fresh independent nullifiers; all outputs use the complete
/// native encryption format and are locally decrypted before proof generation.
fn prepare_empty(state: &State, roots: &AnchorTree) -> Result<PreparedTransaction, String> {
    let h = Hasher::new();
    let snapshot = state.tip_snapshot();
    if encode_digest(&roots.root()) != snapshot.recent_root {
        return Err("local recent-root tree does not match the canonical tip snapshot".into());
    }
    let anchor =
        decode_digest(&snapshot.commitment_root).map_err(|_| "invalid local commitment root")?;
    let input = || -> Result<InputWitness, String> {
        Ok(InputWitness {
            asset_id: SI_ASSET_ID,
            nk: random_fields()?,
            rho: random_fields()?,
            rseed: random_fields()?,
            value: 0,
            unlock_height: 0,
            dummy: true,
            path: vec![([F::ZERO; 12], false); TREE_DEPTH],
        })
    };
    let output = || -> Result<OutputWitness, String> {
        Ok(OutputWitness {
            asset_id: SI_ASSET_ID,
            owner: h.owner(&random_fields()?),
            value: 0,
            unlock_height: 0,
            rseed: random_fields()?,
        })
    };
    let blind = random_fields()?;
    let mut witness = AccWitness {
        slot: SlotWitness {
            anchor,
            inputs: [input()?, input()?],
            outputs: [output()?, output()?, output()?],
            fee: 0,
            fee_blind: blind,
            fee_is_priority: false,
        },
        d_ct: [0; 32],
        anchor_height: snapshot.selector.height,
        base_fee: base_fee(snapshot.selector.height),
        anchor_path: roots.path(snapshot.selector.height),
    };
    let fields = witness.slot.public_inputs(&h);
    let notes: [Note; 3] = core::array::from_fn(|i| witness.slot.output_note(&h, &fields.nf, i));
    let recipient = RecipientViewKey::generate(notes[0].owner)
        .map_err(|_| "empty-output KEM key generation failed")?;
    let change_secret =
        SenderChangeSecret::generate().map_err(|_| "empty-output change key generation failed")?;
    let ec = EncryptionContext::new(state.config.network);
    let (payment, opening) = encrypt_payment_with_opening(&recipient.address(), &notes[0], &ec)
        .map_err(|_| "empty-output payment encryption failed")?;
    let public = PublicTransaction {
        nf: fields.nf,
        cm: fields.cm_out,
        payment,
        change: [
            encrypt_change_at(&change_secret, &notes[1], &ec, 1)
                .map_err(|_| "empty-output change encryption failed")?,
            encrypt_change_at(&change_secret, &notes[2], &ec, 2)
                .map_err(|_| "empty-output change encryption failed")?,
        ],
    };
    let decoded = recipient
        .decrypt_payment(&public.cm[0], &public.payment, &ec)
        .map_err(|_| "empty-output payment self-check failed")?;
    let receipt = opening
        .verify_payment(&recipient.address(), &public.cm[0], &public.payment, &ec)
        .map_err(|_| "empty-output receipt self-check failed")?;
    if !same_note(&decoded, &notes[0]) || !same_note(&receipt, &notes[0]) {
        return Err("empty-output payment note self-check failed".into());
    }
    for i in 0..2 {
        let decoded = decrypt_change_at(
            &change_secret,
            notes[i + 1].owner,
            &public.cm[i + 1],
            &public.change[i],
            &ec,
            (i + 1) as u8,
        )
        .map_err(|_| "empty-output change self-check failed")?;
        if !same_note(&decoded, &notes[i + 1]) {
            return Err("empty-output change note self-check failed".into());
        }
    }
    witness = public
        .bind_witness(&witness, &context(state))
        .map_err(|_| "empty-position statement binding failed")?;
    witness.check(&h, &roots.root()).map_err(str::to_owned)?;
    let record = PublicRecord::new(
        snapshot.selector,
        public.encode(),
        encode_digest(&fields.fee_commit),
    )?;
    Ok(PreparedTransaction {
        witness,
        public,
        record,
        opening: FeeOpening::dummy(blind),
    })
}

fn encode_payment(payment: &PaymentCiphertext) -> [u8; 1313] {
    let mut out = [0; 1313];
    out[..1088].copy_from_slice(&payment.kem_ciphertext);
    out[1088..1296].copy_from_slice(&payment.body);
    out[1296..1312].copy_from_slice(&payment.tag);
    out[1312] = payment.view_tag;
    out
}

fn decode_payment(bytes: &[u8; 1313]) -> PaymentCiphertext {
    PaymentCiphertext {
        kem_ciphertext: bytes[..1088].try_into().expect("fixed KEM ciphertext"),
        body: bytes[1088..1296].try_into().expect("fixed encrypted note"),
        tag: bytes[1296..1312]
            .try_into()
            .expect("fixed authentication tag"),
        view_tag: bytes[1312],
    }
}

fn prepare_reward(state: &State) -> Result<PreparedReward, String> {
    let height = state
        .height
        .checked_add(1)
        .ok_or("engineering block height exhausted")?;
    let unlock_height = height
        .checked_add(native::multi_asset::COINBASE_MATURITY)
        .ok_or("engineering reward maturity height overflows")?;
    let h = Hasher::new();
    let nk = random_fields()?;
    let note = Note {
        asset_id: SI_ASSET_ID,
        owner: h.owner(&nk),
        value: subsidy_split(height).0,
        unlock_height,
        rho: h.miner_rho(height),
        rseed: random_fields()?,
    };
    let recipient =
        RecipientViewKey::generate(note.owner).map_err(|_| "reward KEM key generation failed")?;
    let address = recipient.address();
    let ec = EncryptionContext::new(state.config.network);
    let (payment, opening) = encrypt_payment_with_opening(&address, &note, &ec)
        .map_err(|_| "reward encryption failed")?;
    let commitment = h.note_cm(&note);
    let checked = recipient
        .decrypt_payment(&commitment, &payment, &ec)
        .map_err(|_| "reward payment self-check failed")?;
    if !same_note(&checked, &note) {
        return Err("reward note self-check failed".into());
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(REWARD_SECRET_BYTES));
    secret.extend_from_slice(REWARD_SECRET_MAGIC);
    secret.extend_from_slice(&REWARD_SECRET_VERSION.to_le_bytes());
    secret.extend_from_slice(&state.config.network);
    secret.extend_from_slice(&height.to_le_bytes());
    secret.extend_from_slice(&encode_digest(&commitment));
    secret.extend_from_slice(&encode_digest(&nk));
    secret.extend_from_slice(&encode_digest(&note.rseed));
    secret.extend_from_slice(address.encapsulation_key());
    secret.extend_from_slice(opening.expose_encapsulation_coins());
    Ok(PreparedReward {
        record: RewardRecord {
            commitment: encode_digest(&commitment),
            ciphertext: encode_payment(&payment),
        },
        note,
        secret,
    })
}

/// Authenticate the fixed local recovery record against a block's encrypted
/// reward. This is receipt-based engineering recovery, not wallet scanning.
/// The returned/temporary native field copies are outside byte-buffer erasure.
pub fn validate_reward_secret(block: &Block, secret: &[u8]) -> Result<(), String> {
    if secret.len() != REWARD_SECRET_BYTES
        || &secret[..4] != REWARD_SECRET_MAGIC
        || secret[4..6] != REWARD_SECRET_VERSION.to_le_bytes()
        || secret[6..38] != block.network
        || secret[38..46] != block.height.to_le_bytes()
        || secret[46..94] != block.reward.commitment
    {
        return Err("local reward recovery record binding mismatch".into());
    }
    let digest = |offset| {
        decode_digest(
            secret[offset..offset + 48]
                .try_into()
                .expect("fixed recovery digest"),
        )
        .map_err(|_| "noncanonical private reward digest".to_owned())
    };
    let nk = digest(94)?;
    let rseed = digest(142)?;
    let h = Hasher::new();
    let owner = h.owner(&nk);
    let address = PaymentAddress::new(
        owner,
        secret[190..1374].try_into().expect("fixed KEM public key"),
    )
    .map_err(|_| "invalid reward recovery address")?;
    let opening = PaymentEncryptionOpening::from_encapsulation_coins(
        secret[1374..1406]
            .try_into()
            .expect("fixed encapsulation opening"),
    );
    let commitment =
        decode_digest(&block.reward.commitment).map_err(|_| "invalid reward commitment")?;
    let note = opening
        .verify_payment(
            &address,
            &commitment,
            &decode_payment(&block.reward.ciphertext),
            &EncryptionContext::new(block.network),
        )
        .map_err(|_| "reward recovery authentication failed")?;
    if note.owner != owner
        || note.rseed != rseed
        || note.asset_id != SI_ASSET_ID
        || block
            .height
            .checked_add(native::multi_asset::COINBASE_MATURITY)
            != Some(note.unlock_height)
        || note.rho != h.miner_rho(block.height)
    {
        return Err("reward recovery note mismatch".into());
    }
    Ok(())
}

/// Generate one complete native proof with fresh OS entropy and real output
/// encryption. The caller must independently verify it before queue admission.
pub fn prepare_padding(state: &State, prover: &NativeProver) -> Result<Padding, String> {
    let roots = state.recent_roots()?.tree(&Hasher::new());
    let prepared = prepare_empty(state, &roots)?;
    let proof = prover.transaction(&prepared.witness, &prepared.public, &context(state))?;
    Ok(Padding {
        transaction: Transaction {
            record: prepared.record,
            proof,
        },
        opening: prepared.opening,
    })
}

/// Assemble current-height settlement around previously verified, move-only
/// positions. Transaction proofs and snapshot identities are preserved.
pub fn assemble(
    state: &State,
    prover: &NativeProver,
    mut positions: Vec<Padding>,
    timestamp: u64,
) -> Result<ProducedBlock, String> {
    check_count(positions.len())?;
    if timestamp <= state.median_time_past() {
        return Err("candidate timestamp must exceed median time past".into());
    }
    let height = state
        .height
        .checked_add(1)
        .ok_or("engineering block height exhausted")?;
    let count = positions.len();
    let h = Hasher::new();
    positions
        .sort_unstable_by_key(|value| value.transaction.record.statement_id(&state.config.network));
    let mut spends = BTreeSet::new();
    let mut commitments = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut slots = Vec::with_capacity(MAX_SLOTS);
    let mut transactions = Vec::with_capacity(count);
    for value in positions {
        state.snapshot(value.transaction.record.snapshot)?;
        let public = PublicTransaction::decode(&value.transaction.record.body)
            .map_err(|_| "invalid prepared transaction public fields")?;
        for nf in public.nf {
            let nf = encode_digest(&nf);
            if state.spent.contains(&nf) || !spends.insert(nf) {
                return Err("prepared position nullifier collision".into());
            }
        }
        for cm in public.cm {
            let cm = encode_digest(&cm);
            if state.commitments.contains(&cm) || !commitments.insert(cm) {
                return Err("prepared position output collision".into());
            }
        }
        if !identities.insert(value.transaction.record.statement_id(&state.config.network)) {
            return Err("prepared position identity collision".into());
        }
        let commitment = h.fee_commit(value.opening.fee, &value.opening.blind);
        if value.opening.fee != 0
            || !value.opening.dummy
            || value.opening.priority
            || encode_digest(&commitment) != value.transaction.record.fee_commit
        {
            return Err("prepared position opening mismatch".into());
        }
        slots.push(SettlementSlot {
            commitment,
            opening: value.opening,
        });
        transactions.push(value.transaction);
    }
    slots.extend(tail_slots(state.config.network, height, count)?);
    let reward = prepare_reward(state)?;
    let mut block = Block {
        network: state.config.network,
        height,
        parent: state.tip,
        timestamp,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward: reward.record,
        settlement_proof: Vec::new(),
    };
    let witness = FixedSettlementWitness {
        issuance_reward: subsidy_split(height).0,
        miner_amount: reward.note.value,
        miner_asset_id: SI_ASSET_ID,
        block_height: height,
        network: block.network,
        transaction_list_digest: block.list_digest(),
        miner_owner: reward.note.owner,
        miner_rseed: reward.note.rseed,
        slots,
    };
    block.settlement_proof = prover.settlement(&witness)?;
    block.validate_shape()?;
    validate_reward_secret(&block, &reward.secret)?;
    Ok(ProducedBlock {
        block,
        reward_secret: reward.secret,
    })
}

/// One-shot fixture/engineering operation. Continuous production instead reuses
/// a resident prover and queue and exports work progress while hashing.
pub fn produce(
    state: &State,
    prover: &NativeProver,
    count: usize,
) -> Result<ProducedBlock, String> {
    check_count(count)?;
    let mut prepared = Vec::with_capacity(count);
    for _ in 0..count {
        prepared.push(prepare_padding(state, prover)?);
    }
    let timestamp = if state.config.fixture {
        state
            .timestamp()
            .checked_add(1)
            .ok_or("engineering timestamp exhausted")?
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock precedes epoch")?
            .as_secs()
            .max(
                state
                    .median_time_past()
                    .checked_add(1)
                    .ok_or("engineering timestamp exhausted")?,
            )
    };
    let mut produced = assemble(state, prover, prepared, timestamp)?;
    let seed = produced.block.pow_seed()?;
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, produced.block.nonce, state.config.pow_iterations),
        &produced.block.target,
    ) {
        produced.block.nonce = produced
            .block
            .nonce
            .checked_add(1)
            .ok_or("engineering nonce space exhausted")?;
    }
    Ok(produced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Config;

    #[test]
    fn entropy_sampling_rejects_out_of_field_words_without_reduction() {
        let mut calls = 0;
        let fields = fields_from_entropy::<2>(&mut |bytes| {
            calls += 1;
            bytes.fill(0xff);
            if calls == 2 {
                bytes[..4].copy_from_slice(&0u32.to_le_bytes());
                bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(fields, [F::ZERO, F::ONE]);
    }

    #[test]
    fn prepared_zero_transactions_have_valid_distinct_locally_bound_witnesses() {
        let state = State::new(Config::development([31; 32], 0).unwrap()).unwrap();
        let h = Hasher::new();
        let roots = state.recent_roots().unwrap().tree(&h);
        let first = prepare_empty(&state, &roots).unwrap();
        let second = prepare_empty(&state, &roots).unwrap();
        for tx in [&first, &second] {
            tx.witness.check(&h, &roots.root()).unwrap();
            assert_eq!(tx.record.snapshot, state.tip_snapshot().selector);
            assert_eq!(tx.public.encode(), tx.record.body);
            assert_eq!(tx.witness.slot.fee, 0);
            assert_eq!(tx.witness.slot.inputs.len(), 2);
            assert_eq!(tx.witness.slot.outputs.len(), 3);
            assert!(
                tx.witness
                    .slot
                    .inputs
                    .iter()
                    .all(|input| input.dummy && input.value == 0)
            );
            assert_eq!(
                tx.public
                    .statement(&context(&state), &tx.opening_commitment(), &roots.root(),),
                native::multi_asset_transaction::statement_for(
                    &tx.public.nf,
                    &tx.public.cm,
                    &tx.witness.d_ct,
                    &tx.opening_commitment(),
                    &roots.root(),
                )
            );
        }
        assert_ne!(first.public.nf, second.public.nf);
        assert_ne!(first.public.cm, second.public.cm);
        assert_ne!(
            first.public.payment.kem_ciphertext,
            second.public.payment.kem_ciphertext
        );
        assert_ne!(
            first.record.statement_id(&state.config.network),
            second.record.statement_id(&state.config.network)
        );
    }

    #[test]
    fn reward_material_restores_and_rejects_every_binding_mutation() {
        let state = State::new(Config::development([32; 32], 0).unwrap()).unwrap();
        let reward = prepare_reward(&state).unwrap();
        let block = Block {
            network: state.config.network,
            height: 1,
            parent: state.tip,
            timestamp: state.timestamp() + 1,
            target: state.next_target(),
            nonce: 0,
            transactions: Vec::new(),
            reward: reward.record,
            settlement_proof: Vec::new(),
        };
        validate_reward_secret(&block, &reward.secret).unwrap();
        for offset in [0, 4, 6, 38, 46, 94, 142, 190, REWARD_SECRET_BYTES - 1] {
            let mut invalid = reward.secret.to_vec();
            invalid[offset] ^= 1;
            assert!(
                validate_reward_secret(&block, &invalid).is_err(),
                "field offset {offset}"
            );
        }
        assert!(validate_reward_secret(&block, &reward.secret[..REWARD_SECRET_BYTES - 1]).is_err());
        let mut changed = block;
        changed.reward.ciphertext[0] ^= 1;
        assert!(validate_reward_secret(&changed, &reward.secret).is_err());
    }

    #[test]
    fn invalid_position_counts_are_rejected_before_preparation_or_proving() {
        for count in [0, 63, 65, 577, usize::MAX] {
            assert!(check_count(count).is_err());
        }
        for count in [64, 80, 576] {
            check_count(count).unwrap();
        }
    }

    #[test]
    #[ignore = "explicit actual native block persistence and recovery check"]
    fn actual_block_persists_replays_and_recovers_the_reward() {
        use crate::{local, proofs::NativeVerifier, store::Store};
        struct FreshDirectory(std::path::PathBuf);
        impl Drop for FreshDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).unwrap();
        let path = std::env::temp_dir()
            .join(format!("siworld-native-proof-e2e-{}", local::hex(&entropy),));
        let config = local::initialize(&path, 0).unwrap();
        let directory = FreshDirectory(path);
        let verifier = NativeVerifier::new().unwrap();
        let mut store =
            Store::open(directory.0.join("chain.redb"), config.clone(), &verifier).unwrap();
        let prover = NativeProver::new().unwrap();
        let produced = produce(store.state(), &prover, 64).unwrap();
        let id = produced.block.id().unwrap();
        validate_reward_secret(&produced.block, &produced.reward_secret).unwrap();
        local::save_reward(&directory.0, &id, &produced.reward_secret).unwrap();
        store.append(&produced.block, &verifier).unwrap();
        let fingerprint = store.state().fingerprint();
        assert_eq!(store.state().height, 1);
        assert_eq!(store.state().tree.count, 64 * 3 + 1);
        drop(produced);
        drop(prover);
        drop(store);
        let loaded = local::load(&directory.0).unwrap();
        assert_eq!(loaded, config);
        let restarted =
            Store::open_existing(directory.0.join("chain.redb"), loaded, &verifier).unwrap();
        assert_eq!(restarted.state().fingerprint(), fingerprint);
        let accepted = restarted.block(1).unwrap();
        assert_eq!(accepted.id().unwrap(), id);
        let recovered = local::read_reward(&directory.0, &id).unwrap();
        validate_reward_secret(&accepted, &recovered).unwrap();
        let mut changed = accepted;
        changed.reward.ciphertext[0] ^= 1;
        assert!(validate_reward_secret(&changed, &recovered).is_err());
        drop(restarted);
    }
}
