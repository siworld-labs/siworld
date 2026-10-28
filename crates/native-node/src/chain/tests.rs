use super::*;

#[test]
fn only_strictly_greater_verified_work_selects_a_branch() {
    use siworld_core::pow::Work;
    assert!(!prefer_work(Work::from(9u64), Work::from(8u64)));
    assert!(!prefer_work(Work::from(9u64), Work::from(9u64)));
    assert!(prefer_work(Work::from(9u64), Work::from(10u64)));
}

#[test]
fn depth_23_and_24_preserve_finality_but_25_is_rejected() {
    assert_eq!(check_ancestor(50, 27), Ok(()));
    assert_eq!(check_ancestor(50, 26), Ok(()));
    assert_eq!(check_ancestor(50, 25), Err(ChainError::ReorganizationLimit));
    assert!(matches!(
        check_ancestor(50, 51),
        Err(ChainError::Invalid(_))
    ));
    assert_eq!(finalized_height(50), 26);
    assert_eq!(finalized_height(24), 0);
}

#[test]
fn resource_failures_have_no_invalid_consensus_classification() {
    assert!(!ChainError::ResourceExhausted("candidate bytes").is_invalid());
    assert!(!ChainError::Local("storage unavailable".into()).is_invalid());
    assert!(!ChainError::ReorganizationLimit.is_invalid());
    assert!(ChainError::Invalid("bad proof".into()).is_invalid());
}
