//! Offline, independently signed local custody changes; never a consensus rule.
use super::*;
use crate::fund_approval::{self as signing, ChangeRequest, SignedChange, SigningContext};
use crate::fund_keys::FundBudget;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChangeRecord {
    pub signed: SignedChange,
    pub sequence: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Governance {
    pub key: String,
    pub changes: Vec<ChangeRecord>,
}
fn identity(g: &Genesis) -> String {
    signing::hash("siworld independent fund custody identity v1", &context(g))
}
impl Governance {
    fn key(&self) -> Result<VerifyingKey, String> {
        crate::parse_hex(&self.key)
            .filter(|_| self.key.to_lowercase() == self.key)
            .map(VerifyingKey)
            .ok_or_else(|| "invalid trusted approval key".into())
    }
    fn at(&self, sequence: u64) -> Option<&ChangeRecord> {
        self.changes.iter().rev().find(|c| c.sequence <= sequence)
    }
    fn signing_context(&self, g: &Genesis, at: &ChangeRecord) -> Result<SigningContext, String> {
        Ok(SigningContext {
            version: 1,
            genesis: crate::hex(&g.id),
            fund_id: identity(g),
            key_id: signing::key_id(&self.key()?),
            revision: at.signed.request.revision,
            policy_hash: signing::policy_hash(&at.signed.request.policy),
            revision_hash: at.signed.hash(),
        })
    }
}
pub(super) fn current_policy(c: &budget::Custody) -> &FundBudget {
    c.governance
        .as_ref()
        .and_then(|v| v.changes.last())
        .map_or(&c.policy, |r| &r.signed.request.policy)
}
pub(super) fn current_context(
    c: &budget::Custody,
    g: &Genesis,
) -> Result<Option<SigningContext>, String> {
    c.governance
        .as_ref()
        .map(|v| v.signing_context(g, v.changes.last().ok_or("missing signing enrollment")?))
        .transpose()
}
fn independent(key: &VerifyingKey, g: &Genesis) -> Result<(), String> {
    let funds = g
        .params
        .dev_fund_keys
        .as_ref()
        .ok_or("fund keys required")?;
    if key.0 == funds.direct || key.0 == funds.lock {
        return Err("independent approval key must differ from fund signing keys".into());
    }
    Ok(())
}
pub(super) fn validate(c: &budget::Custody, data: &Data, g: &Genesis) -> Result<(), String> {
    let Some(v) = &c.governance else {
        return Ok(());
    };
    let key = v.key()?;
    independent(&key, g)?;
    if v.changes.is_empty() || v.changes.len() > 4097 {
        return Err("invalid budget revision history length".into());
    }
    let mut ids = BTreeSet::new();
    let mut previous: Option<&ChangeRecord> = None;
    for (index, r) in v.changes.iter().enumerate() {
        let q = &r.signed.request;
        r.signed.verify(&key)?;
        if q.genesis != crate::hex(&g.id)
            || q.fund_id != identity(g)
            || q.policy.id != c.policy.id
            || q.revision != index as u64
            || q.expected_sequence.checked_add(1) != Some(r.sequence)
            || r.sequence < c.enrolled_sequence
            || r.sequence > data.sequence
            || !ids.insert(&q.change_id)
            || c.approvals.iter().any(|a| a.sequence == r.sequence)
            || previous.is_some_and(|p| p.sequence >= r.sequence)
            || q.previous_revision != previous.map(|p| p.signed.hash())
            || q.previous_policy != previous.map(|p| signing::policy_hash(&p.signed.request.policy))
            || (index == 0 && q.policy != c.policy)
        {
            return Err("invalid budget revision lineage".into());
        }
        let l = q.policy.validate()?;
        if q.reserved_atoms[0] > l.accounts[0]
            || q.reserved_atoms[1] > l.accounts[1]
            || q.reserved_atoms[0]
                .checked_add(q.reserved_atoms[1])
                .is_none_or(|n| n > l.total)
        {
            return Err("revision does not cover its retained reservations".into());
        }
        previous = Some(r);
    }
    let l = current_policy(c).validate()?;
    if data
        .records
        .iter()
        .any(|r| r.artifact.is_none() && r.amount > l.max)
    {
        return Err("revision would strand an unsigned payout intent".into());
    }
    Ok(())
}
pub(super) fn verify_grant(
    c: &budget::Custody,
    grant: &crate::fund_keys::FundGrant,
    sequence: u64,
    g: &Genesis,
) -> Result<(), String> {
    let at = c.governance.as_ref().and_then(|v| v.at(sequence));
    let policy = at.map_or(&c.policy, |r| &r.signed.request.policy);
    if &grant.budget != policy {
        return Err("fund authorization budget revision mismatch".into());
    }
    match (at, &grant.approval) {
        (Some(r), Some(proof)) => {
            let v = c.governance.as_ref().expect("governance");
            proof.verify(grant, &v.key()?, &v.signing_context(g, r)?)
        }
        (None, None) if grant.version == 2 => Ok(()),
        _ => Err("independent signed fund authorization required".into()),
    }
}
pub(super) fn preserves(n: &budget::Custody, o: &budget::Custody) -> bool {
    match (&n.governance, &o.governance) {
        (Some(n), Some(o)) => n.key == o.key && n.changes.starts_with(&o.changes),
        (_, None) => true,
        (None, Some(_)) => false,
    }
}
/// All three files have independent roles: encrypted custody, external witness,
/// and an independently current checkpoint pin. Key/journal/witness locks apply.
pub struct GovernanceFiles<'a> {
    pub key: &'a Path,
    pub witness: &'a Path,
    pub checkpoint: &'a Path,
}
#[derive(Serialize)]
pub struct ChangeReview {
    pub committed: bool,
    pub already_applied: bool,
    pub change_id: String,
    pub revision: u64,
    pub policy_hash: String,
    pub reserved_atoms: [u64; 2],
    pub checkpoint: backup::Checkpoint,
}
impl GovernanceFiles<'_> {
    fn open(&self, password: &str, g: &Genesis) -> Result<FundJournal, String> {
        let (_, j) = backup::open(self.key, self.witness, password, g)?;
        if j.data.recovery.is_some() {
            return Err("fund recovery reconciliation required before budget changes".into());
        }
        j.witness
            .as_ref()
            .ok_or("external fund witness required")?
            .verify_pin(self.checkpoint, backup::fund_dir(self.key))?;
        Ok(j)
    }
    pub fn propose(
        &self,
        password: &str,
        g: &Genesis,
        policy: &FundBudget,
        trusted: Option<&VerifyingKey>,
        reason: &str,
    ) -> Result<ChangeRequest, String> {
        let _lock = crate::fund_keys::lock_file(self.key)?;
        let j = self.open(password, g)?;
        request(&j, g, policy, trusted, reason)
    }
    pub fn apply(
        &self,
        password: &str,
        g: &Genesis,
        signed: &SignedChange,
        trusted: Option<&VerifyingKey>,
        commit: bool,
    ) -> Result<ChangeReview, String> {
        let _lock = crate::fund_keys::lock_file(self.key)?;
        let mut j = self.open(password, g)?;
        apply(&mut j, g, signed, trusted, commit)
    }
}
fn request(
    j: &FundJournal,
    g: &Genesis,
    policy: &FundBudget,
    trusted: Option<&VerifyingKey>,
    reason: &str,
) -> Result<ChangeRequest, String> {
    let governance = j.data.custody.as_ref().and_then(|c| c.governance.as_ref());
    let last = governance.and_then(|v| v.changes.last());
    let key = if let Some(v) = governance {
        let key = v.key()?;
        if trusted.is_some_and(|k| k != &key) {
            return Err("trusted approval key mismatch".into());
        }
        key
    } else {
        *trusted.ok_or("independently trusted approval public key required for enrollment")?
    };
    independent(&key, g)?;
    if last.is_none() && j.data.custody.as_ref().is_some_and(|c| &c.policy != policy) {
        return Err("enrollment must preserve the existing base policy".into());
    }
    if j.data
        .custody
        .as_ref()
        .is_some_and(|c| c.policy.id != policy.id)
    {
        return Err("budget amendments must preserve policy identity".into());
    }
    let mut random = [0; 32];
    getrandom::fill(&mut random).map_err(|_| "OS randomness unavailable")?;
    let q = ChangeRequest {
        version: 1,
        genesis: crate::hex(&g.id),
        fund_id: identity(g),
        key_id: signing::key_id(&key),
        change_id: crate::hex(&Digest(random)),
        revision: last.map_or(0, |r| r.signed.request.revision + 1),
        previous_revision: last.map(|r| r.signed.hash()),
        previous_policy: last.map(|r| signing::policy_hash(&r.signed.request.policy)),
        expected_sequence: j.data.sequence,
        expected_state: crate::hex(&Digest(j.head)),
        reserved_atoms: budget::totals(&j.data).map_err(|e| e.to_string())?.0,
        policy: policy.clone(),
        reason: reason.into(),
    };
    q.validate()?;
    let l = policy.validate()?;
    let (used, total) = budget::totals(&j.data).map_err(|e| e.to_string())?;
    if used[0] > l.accounts[0]
        || used[1] > l.accounts[1]
        || total > l.total
        || j.data
            .records
            .iter()
            .any(|r| r.artifact.is_none() && r.amount > l.max)
    {
        return Err("budget must cover all retained reservations and unsigned intents".into());
    }
    Ok(q)
}
fn apply(
    j: &mut FundJournal,
    g: &Genesis,
    signed: &SignedChange,
    trusted: Option<&VerifyingKey>,
    commit: bool,
) -> Result<ChangeReview, String> {
    let q = &signed.request;
    let existing = j.data.custody.as_ref().and_then(|c| c.governance.as_ref());
    let key = existing
        .map(|v| v.key())
        .transpose()?
        .or(trusted.copied())
        .ok_or("independently trusted approval public key required")?;
    if trusted.is_some_and(|t| t != &key) {
        return Err("trusted approval key mismatch".into());
    }
    signed.verify(&key)?;
    let found = existing.and_then(|v| {
        v.changes
            .iter()
            .find(|r| r.signed.request.change_id == q.change_id)
    });
    let already = if let Some(r) = found {
        if &r.signed != signed {
            return Err("budget change ID already used for a different document".into());
        }
        true
    } else {
        false
    };
    if !already {
        let mut expected = request(j, g, &q.policy, Some(&key), &q.reason)?;
        expected.change_id = q.change_id.clone();
        if &expected != q {
            return Err(
                "stale or mismatched budget change; obtain a fresh current checkpoint and proposal"
                    .into(),
            );
        }
        let mut candidate = j.data.clone();
        let sequence = candidate
            .sequence
            .checked_add(1)
            .ok_or("fund sequence exhausted")?;
        let c = candidate.custody.get_or_insert_with(|| budget::Custody {
            policy: q.policy.clone(),
            enrolled_sequence: sequence,
            legacy_ids: j.data.records.iter().map(|r| r.id.clone()).collect(),
            approvals: vec![],
            governance: None,
        });
        let v = c.governance.get_or_insert_with(|| Governance {
            key: crate::genesis::hex_bytes(&key.0),
            changes: vec![],
        });
        v.changes.push(ChangeRecord {
            signed: signed.clone(),
            sequence,
        });
        candidate.version = 3;
        candidate.sequence = sequence;
        super::validate(&candidate, g)
            .map_err(|_| "signed budget change violates custody history")?;
        if commit {
            candidate.sequence = j.data.sequence;
            j.data = candidate;
            j.persist().map_err(|e| e.to_string())?;
        }
    }
    Ok(ChangeReview {
        committed: commit,
        already_applied: already,
        change_id: q.change_id.clone(),
        revision: q.revision,
        policy_hash: signing::policy_hash(&q.policy),
        reserved_atoms: budget::totals(&j.data).map_err(|e| e.to_string())?.0,
        checkpoint: j
            .witness
            .as_ref()
            .expect("witnessed operation")
            .checkpoint()
            .clone(),
    })
}
#[derive(Serialize)]
pub struct History {
    pub trusted_key: Option<String>,
    pub signing_context: Option<SigningContext>,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub change_count: usize,
    pub changes: Vec<HistoryEntry>,
}
#[derive(Serialize)]
pub struct HistoryEntry {
    pub sequence: u64,
    pub hash: String,
    pub signed: SignedChange,
}
impl Node {
    pub fn fund_budget_history(
        &mut self,
        offset: usize,
        limit: usize,
    ) -> Result<History, PayoutRefused> {
        self.expire_fund(Instant::now());
        let j = self
            .fund_journal
            .as_ref()
            .ok_or(PayoutRefused::JournalRequired)?;
        j.healthy()?;
        let c = j.data.custody.as_ref();
        let v = c.and_then(|c| c.governance.as_ref());
        let count = v.map_or(0, |v| v.changes.len());
        if !(1..=4).contains(&limit) || offset > count {
            return Err(PayoutRefused::Authorization);
        }
        Ok(History {
            trusted_key: v.map(|v| v.key.clone()),
            signing_context: c
                .map(|c| current_context(c, &self.genesis))
                .transpose()
                .map_err(|_| PayoutRefused::Journal)?
                .flatten(),
            offset,
            next_offset: (offset + limit < count).then_some(offset + limit),
            change_count: count,
            changes: v
                .into_iter()
                .flat_map(|v| &v.changes)
                .skip(offset)
                .take(limit)
                .map(|r| HistoryEntry {
                    sequence: r.sequence,
                    hash: r.signed.hash(),
                    signed: r.signed.clone(),
                })
                .collect(),
        })
    }
}
