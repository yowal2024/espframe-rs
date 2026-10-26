use espframe::monarch::svc_timing::{GuestCounterValue, SvcExceptionTicks};
use espframe::monarch::syncsource_policy::*;
use espframe::monarch::transaction::*;

#[test]
fn transaction_vectors_preserve_rollbacks_cohorts_and_retry_cap() {
    assert_eq!(
        ChooseSideEffectDisposition(&SideEffectDecisionInput {
            clean_return: true,
            fresh_publish: true,
            ..Default::default()
        }),
        SideEffectDisposition::CommitTyped
    );
    assert_eq!(
        ChooseSideEffectDisposition(&SideEffectDecisionInput {
            clean_return: true,
            ..Default::default()
        }),
        SideEffectDisposition::RollbackCall
    );
    assert_eq!(
        ChooseSideEffectDisposition(&SideEffectDecisionInput {
            clean_return: true,
            bootstrap_mode: true,
            ..Default::default()
        }),
        SideEffectDisposition::BootstrapWithoutGenerator
    );
    assert_eq!(
        ChooseSideEffectDisposition(&SideEffectDecisionInput {
            clean_return: true,
            bootstrap_cohort_ready: true,
            ..Default::default()
        }),
        SideEffectDisposition::ReplayKeepGenerator
    );
    assert_eq!(
        ChooseSideEffectDisposition(&SideEffectDecisionInput::default()),
        SideEffectDisposition::RollbackCall
    );
    assert_eq!(
        ChooseRetryBudgetDisposition(true, 3, 4),
        RetryBudgetDisposition::Retry
    );
    assert_eq!(
        ChooseRetryBudgetDisposition(true, 4, 4),
        RetryBudgetDisposition::Stop
    );
    assert_eq!(
        ChooseCallLoopAction(&CallLoopDecisionInput {
            bootstrap_only: true,
            returned: true,
            ..Default::default()
        }),
        CallLoopAction::BootstrapReplay
    );
    assert_eq!(
        ChooseCallLoopAction(&CallLoopDecisionInput {
            gate_bypass: true,
            retries: 4,
            retry_limit: 99,
            ..Default::default()
        }),
        CallLoopAction::Stop
    );
    assert!(GeneratorCohortCommittedThisCall(true, false));
    assert!(IsIncompleteGeneratorCandidate(true, false));
}

#[test]
fn syncsource_and_timing_vectors_match_cpp() {
    let mut calls = 0;
    let selected = SelectVirtualKgslSyncsourceIdWithDiagnostics(&[2], &mut |min| {
        calls += 1;
        Ok((if min == 1 { 2 } else { 3 }, 0x61))
    });
    assert_eq!(selected.kind, KgslSyncsourceSelectionKind::Selected);
    assert_eq!(selected.id, 3);
    assert_eq!(calls, 2);
    assert_eq!(SvcExceptionTicks(172, 172, 29, 7, 11, 13), 11);
    assert_eq!(
        GuestCounterValue(1000, 2600, 7, true, 19_200_000, 2_600_000_000),
        1026
    );
    let failed = SelectVirtualKgslSyncsourceIdWithDiagnostics(&[] as &[u32], &mut |_| {
        Err(ErrWithBackend(-EAGAIN, 0x61))
    });
    assert_eq!(failed.error, EAGAIN);
    assert_eq!(failed.backend, 0x61);
    let max_id = i32::MAX as u32 - 1;
    let full = SelectVirtualKgslSyncsourceIdWithDiagnostics(&[max_id], &mut |_| Ok((max_id, 0x62)));
    assert_eq!(full.kind, KgslSyncsourceSelectionKind::GuestError);
    assert_eq!(full.error, ENOSPC);
    assert_eq!(full.backend, 0x62);
    assert_eq!(
        MakeKernelKgslSyncsourceResult(8, 7).result,
        -(EPROTO as i64)
    );
}
