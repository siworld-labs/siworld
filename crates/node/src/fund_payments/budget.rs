//! Private custody policy and approval audit, authenticated with the payout journal.
use super::*;
use crate::fund_keys::{FundBudget, FundGrant};
const MAX_APPROVALS: usize = 4096;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approval {
    pub(super) grant: FundGrant,
    pub(super) sequence: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Custody {
    pub(super) policy: FundBudget,
    pub(super) enrolled_sequence: u64,
    pub(super) legacy_ids: Vec<String>,
    pub(super) approvals: Vec<Approval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) governance: Option<governance::Governance>,
}
#[derive(Serialize)]
pub struct ApprovalAudit {
    pub grant: FundGrant,
    pub grant_hash: String,
    pub sequence: u64,
    /// Conservative authorization usage, including resumed unsigned intents.
    pub authorized_atoms: [u64; 2],
    pub orders: usize,
}
#[derive(Serialize)]
pub struct BudgetAudit {
    pub signing_context: Option<crate::fund_approval::SigningContext>,
    pub policy: Option<FundBudget>,
    pub enrolled_sequence: Option<u64>,
    pub sequence: u64,
    /// All retained intents, counted once, regardless of inclusion or signatures.
    pub reserved_atoms: [u64; 2],
    pub remaining_atoms: Option<[u64; 2]>,
    pub total_remaining_atoms: Option<u64>,
    pub approval_count: usize,
    pub active_approval_id: Option<String>,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub approvals: Vec<ApprovalAudit>,
}

pub(super) fn totals(data: &Data) -> Result<([u64; 2], u64), PayoutRefused> {
    let mut accounts = [0u64; 2];
    let mut total = 0u64;
    for r in &data.records {
        let a = accounts
            .get_mut(r.account as usize)
            .ok_or(PayoutRefused::Journal)?;
        *a = a.checked_add(r.amount).ok_or(PayoutRefused::Journal)?;
        total = total.checked_add(r.amount).ok_or(PayoutRefused::Journal)?;
    }
    Ok((accounts, total))
}
pub(super) fn validate(data: &Data, genesis: &Genesis) -> Result<(), PayoutRefused> {
    let Some(c) = &data.custody else {
        return if data.records.iter().all(|r| r.approvals.is_empty()) {
            Ok(())
        } else {
            Err(PayoutRefused::Journal)
        };
    };
    governance::validate(c, data, genesis).map_err(|_| PayoutRefused::Journal)?;
    let limits = governance::current_policy(c)
        .validate()
        .map_err(|_| PayoutRefused::Journal)?;
    let (used, total) = totals(data)?;
    if c.enrolled_sequence == 0
        || c.enrolled_sequence > data.sequence
        || (c.approvals.is_empty() && c.governance.is_none())
        || c.approvals.len() > MAX_APPROVALS
        || used.iter().zip(limits.accounts).any(|(u, l)| *u > l)
        || total > limits.total
    {
        return Err(PayoutRefused::Journal);
    }
    let legacy: BTreeSet<_> = c.legacy_ids.iter().collect();
    if legacy.len() != c.legacy_ids.len()
        || legacy
            .iter()
            .any(|id| !data.records.iter().any(|r| &r.id == *id))
    {
        return Err(PayoutRefused::Journal);
    }
    let mut approvals = BTreeMap::new();
    let mut prior = c.enrolled_sequence - 1;
    for a in &c.approvals {
        let auth = a
            .grant
            .validate(&genesis.id)
            .map_err(|_| PayoutRefused::Journal)?;
        if governance::verify_grant(c, &a.grant, a.sequence, genesis).is_err()
            || a.sequence <= prior
            || a.sequence > data.sequence
            || approvals
                .insert(a.grant.approval_id.as_str(), (a, auth, [0u64; 2]))
                .is_some()
        {
            return Err(PayoutRefused::Journal);
        }
        prior = a.sequence;
    }
    if c.governance
        .as_ref()
        .is_none_or(|v| v.changes[0].sequence != c.enrolled_sequence)
        && c.approvals
            .first()
            .is_none_or(|a| a.sequence != c.enrolled_sequence)
    {
        return Err(PayoutRefused::Journal);
    }
    for r in &data.records {
        if !legacy.contains(&r.id) && r.approvals.is_empty() {
            return Err(PayoutRefused::Journal);
        }
        let to = parse_address(&r.to).ok_or(PayoutRefused::Journal)?;
        let mut previous = 0;
        for id in &r.approvals {
            let (approval, auth, used) = approvals
                .get_mut(id.as_str())
                .ok_or(PayoutRefused::Journal)?;
            if approval.sequence <= previous || !auth.permits(r.account(), &to.owner(), r.amount) {
                return Err(PayoutRefused::Journal);
            }
            previous = approval.sequence;
            let i = r.account as usize;
            used[i] = used[i]
                .checked_add(r.amount)
                .ok_or(PayoutRefused::Journal)?;
            if used[i] > auth.remaining[i] {
                return Err(PayoutRefused::Journal);
            }
        }
    }
    Ok(())
}
pub(super) fn allows(
    data: &Data,
    account: DevAccount,
    amount: u64,
    new: bool,
) -> Result<(), PayoutRefused> {
    let c = data.custody.as_ref().ok_or(PayoutRefused::Authorization)?;
    let l = governance::current_policy(c)
        .validate()
        .map_err(|_| PayoutRefused::Journal)?;
    let (used, total) = totals(data)?;
    if amount > l.max
        || (new
            && (amount
                > l.accounts[account.to_byte() as usize]
                    .saturating_sub(used[account.to_byte() as usize])
                || amount > l.total.saturating_sub(total)))
    {
        return Err(PayoutRefused::Authorization);
    }
    Ok(())
}
pub(super) fn preserves(new: &Data, old: &Data) -> bool {
    if new.version < old.version {
        return false;
    }
    match (&new.custody, &old.custody) {
        (Some(n), Some(o)) => {
            n.policy == o.policy
                && n.enrolled_sequence == o.enrolled_sequence
                && n.legacy_ids == o.legacy_ids
                && n.approvals.starts_with(&o.approvals)
                && governance::preserves(n, o)
        }
        (_, None) => true,
        (None, Some(_)) => false,
    }
}
impl Node {
    pub(crate) fn record_fund_approval(&mut self, grant: &FundGrant) -> Result<(), String> {
        // Enrollment must not conceal canonical payouts omitted from the journal.
        let canonical = self.canonical_fund_payouts();
        let j = self.fund_journal.as_mut().ok_or("fund journal required")?;
        j.healthy().map_err(|e| e.to_string())?;
        let sequence = j
            .data
            .sequence
            .checked_add(1)
            .ok_or("fund journal sequence exhausted")?;
        let mut candidate = j.data.clone();
        if candidate.custody.is_none() {
            if canonical.values().any(|(p, _)| {
                !candidate
                    .records
                    .iter()
                    .any(|r| r.payout().ok().flatten() == Some(*p))
            }) {
                return Err(
                    "canonical fund history missing; cumulative policy not enrolled".into(),
                );
            }
            candidate.version = 2;
            candidate.custody = Some(Custody {
                policy: grant.budget.clone(),
                enrolled_sequence: sequence,
                legacy_ids: candidate.records.iter().map(|r| r.id.clone()).collect(),
                approvals: vec![],
                governance: None,
            });
        }
        let c = candidate.custody.as_mut().expect("enrolled");
        governance::verify_grant(c, grant, sequence, &self.genesis)?;
        if c.approvals
            .iter()
            .any(|a| a.grant.approval_id == grant.approval_id)
        {
            return Err("fund approval ID already recorded; inspect fundapprovals and use a new approval ID".into());
        }
        if c.approvals.len() >= MAX_APPROVALS {
            return Err("fund approval capacity reached; retain history".into());
        }
        c.approvals.push(Approval {
            grant: grant.clone(),
            sequence,
        });
        candidate.sequence = sequence;
        validate(&candidate, &self.genesis)
            .map_err(|_| "fund policy does not cover retained history or invalid approval")?;
        candidate.sequence = j.data.sequence;
        j.data = candidate;
        j.persist().map_err(|e| e.to_string())
    }
    /// Fund-capability-only private audit. Pagination bounds response size.
    pub fn fund_approvals(
        &mut self,
        offset: usize,
        limit: usize,
    ) -> Result<BudgetAudit, PayoutRefused> {
        self.expire_fund(Instant::now());
        let j = self
            .fund_journal
            .as_ref()
            .ok_or(PayoutRefused::JournalRequired)?;
        j.healthy()?;
        if !(1..=16).contains(&limit) {
            return Err(PayoutRefused::Authorization);
        }
        let c = j.data.custody.as_ref();
        let count = c.map_or(0, |c| c.approvals.len());
        if offset > count {
            return Err(PayoutRefused::Authorization);
        }
        let (used, total) = totals(&j.data)?;
        let limits = c
            .map(|c| governance::current_policy(c).validate())
            .transpose()
            .map_err(|_| PayoutRefused::Journal)?;
        let approvals = c
            .into_iter()
            .flat_map(|c| &c.approvals)
            .skip(offset)
            .take(limit)
            .map(|a| {
                let records: Vec<_> = j
                    .data
                    .records
                    .iter()
                    .filter(|r| r.approvals.contains(&a.grant.approval_id))
                    .collect();
                let mut authorized = [0; 2];
                for r in &records {
                    authorized[r.account as usize] += r.amount;
                }
                let mut hash = blake3::Hasher::new_derive_key("siworld fund approval audit v1");
                hash.update(&serde_json::to_vec(&a.grant).expect("grant serialization"));
                ApprovalAudit {
                    grant: a.grant.clone(),
                    grant_hash: hash.finalize().to_hex().to_string(),
                    sequence: a.sequence,
                    authorized_atoms: authorized,
                    orders: records.len(),
                }
            })
            .collect();
        Ok(BudgetAudit {
            signing_context: c
                .map(|c| governance::current_context(c, &self.genesis))
                .transpose()
                .map_err(|_| PayoutRefused::Journal)?
                .flatten(),
            policy: c.map(|c| governance::current_policy(c).clone()),
            enrolled_sequence: c.map(|c| c.enrolled_sequence),
            sequence: j.data.sequence,
            reserved_atoms: used,
            remaining_atoms: limits
                .as_ref()
                .map(|l| [l.accounts[0] - used[0], l.accounts[1] - used[1]]),
            total_remaining_atoms: limits.map(|l| l.total - total),
            approval_count: count,
            active_approval_id: self
                .fund_protection
                .as_ref()
                .and_then(|p| p.authorization.as_ref())
                .map(|a| a.id.clone()),
            offset,
            next_offset: (offset + limit < count).then_some(offset + limit),
            approvals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fund_payments::tests::{id, open, recipient, setup, unlock, Temp, PASSWORD};
    fn fixture() -> (Temp, Genesis, FundKeystore, Node) {
        let t = Temp::new();
        let (g, store) = setup();
        initialize(&t.0, &store, PASSWORD, &g).unwrap();
        let mut n = open(&g, &t.0);
        n.protect_dev_fund(store.clone(), PASSWORD, &t.0).unwrap();
        unlock(&mut n);
        (t, g, store, n)
    }
    #[test]
    fn metadata_tampering_and_history_truncation_are_rejected() {
        let (_t, g, _store, mut n) = fixture();
        n.payout(id(), DevAccount::Direct, &recipient(), 10_000)
            .unwrap();
        let data = n.fund_journal.as_ref().unwrap().data.clone();
        for case in 0..15 {
            let mut bad = data.clone();
            let c = bad.custody.as_mut().unwrap();
            match case {
                0 => c.approvals.clear(),
                1 => c.approvals.push(c.approvals[0].clone()),
                2 => c.approvals[0].sequence = 0,
                3 => c.approvals[0].sequence = bad.sequence + 1,
                4 => c.approvals[0].grant.direct_si = "0.00001".into(),
                5 => c.approvals[0].grant.recipients.clear(),
                6 => c.approvals[0].grant.approval_id = "AA".repeat(32),
                7 => c.legacy_ids.push("ff".repeat(32)),
                8 => bad.records[0].approvals.clear(),
                9 => {
                    let id = bad.records[0].approvals[0].clone();
                    bad.records[0].approvals.push(id);
                }
                10 => bad.records[0].approvals[0] = "ff".repeat(32),
                11 => c.policy.total_si = "0.00001".into(),
                12 => {
                    bad.version = 1;
                    bad.custody = None;
                }
                13 => {
                    let a = c.approvals[0].clone();
                    c.approvals.resize(MAX_APPROVALS + 1, a);
                }
                _ => c.enrolled_sequence = bad.sequence + 1,
            }
            assert!(super::validate(&bad, &g).is_err(), "case {case}");
        }
        let mut truncated = data.clone();
        truncated.custody.as_mut().unwrap().approvals.clear();
        assert!(!preserves(&truncated, &data));
        let mut raised = data.clone();
        raised.custody.as_mut().unwrap().policy.total_si = "3000000000".into();
        assert!(!preserves(&raised, &data));
        let mut lowered = data.clone();
        lowered.version = 1;
        lowered.custody = None;
        assert!(!preserves(&lowered, &data));
        let mut detached = data.clone();
        detached.records[0].approvals.clear();
        assert!(!backup::preserves(&detached, &data));
    }
    #[test]
    fn explicit_legacy_upgrade_imports_usage_and_rejects_insufficient_caps() {
        let (t, g, store, mut n) = fixture();
        let p = n
            .payout(id(), DevAccount::Direct, &recipient(), 10_000)
            .unwrap();
        let mut grant = n.fund_approvals(0, 16).unwrap().approvals.remove(0).grant;
        // Produce an authenticated version-1 fixture, as retained by older nodes.
        let j = n.fund_journal.as_mut().unwrap();
        j.data.version = 1;
        j.data.custody = None;
        j.data.records[0].approvals.clear();
        j.persist().unwrap();
        drop(n);
        let mut n = open(&g, &t.0);
        n.protect_dev_fund(store, PASSWORD, &t.0).unwrap();
        assert!(n.fund_approvals(0, 16).unwrap().policy.is_none());
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 10_000)
                .unwrap(),
            p
        );
        grant.approval_id = "fe".repeat(32);
        let mut insufficient = grant.clone();
        insufficient.budget.total_si = "0.00005".into();
        assert!(n.unlock_fund(PASSWORD, &insufficient).is_err());
        assert!(n.fund_status().locked);
        assert!(n.fund_approvals(0, 16).unwrap().policy.is_none());
        n.unlock_fund(PASSWORD, &grant).unwrap();
        let audit = n.fund_approvals(0, 16).unwrap();
        assert_eq!(audit.reserved_atoms, [10_000, 0]);
        assert_eq!(audit.approval_count, 1);
        assert_eq!(audit.approvals[0].authorized_atoms, [0, 0]);
        assert_eq!(
            n.fund_journal
                .as_ref()
                .unwrap()
                .data
                .custody
                .as_ref()
                .unwrap()
                .legacy_ids,
            vec![id().to_string()]
        );
        super::super::validate(&n.fund_journal.as_ref().unwrap().data, &g).unwrap();
    }
    #[test]
    fn ambiguous_approval_publication_never_exposes_a_signer_or_reactivates_a_durable_id() {
        for fault in [1, 2] {
            let (t, g, store, mut n) = fixture();
            let mut grant = n.fund_approvals(0, 16).unwrap().approvals.remove(0).grant;
            grant.approval_id = "fe".repeat(32);
            n.lock_fund();
            n.fund_journal.as_mut().unwrap().fault = Some(fault);
            assert!(n.unlock_fund(PASSWORD, &grant).is_err());
            assert!(n.fund_status().locked);
            assert!(n.dev_fund.is_none());
            assert!(n.fund_journal.as_ref().unwrap().key.is_none());
            drop(n);
            let mut n = open(&g, &t.0);
            n.protect_dev_fund(store, PASSWORD, &t.0).unwrap();
            let audit = n.fund_approvals(0, 16).unwrap();
            assert_eq!(audit.approval_count, if fault == 1 { 1 } else { 2 });
            assert_eq!(n.unlock_fund(PASSWORD, &grant).is_ok(), fault == 1);
        }
    }
}
