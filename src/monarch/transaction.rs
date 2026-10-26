#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideEffectDisposition {
    CommitTyped,
    RollbackCall,
    ReplayKeepGenerator,
    BootstrapWithoutGenerator,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryBudgetDisposition {
    Stop,
    Retry,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallLoopAction {
    Stop,
    BootstrapReplay,
    Retry,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallLoopDecisionInput {
    pub bootstrap_only: bool,
    pub returned: bool,
    pub ok: bool,
    pub gate_bypass: bool,
    pub target_state_changed: bool,
    pub retries: u32,
    pub retry_limit: u32,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SideEffectDecisionInput {
    pub clean_return: bool,
    pub fresh_publish: bool,
    pub bootstrap_mode: bool,
    pub bootstrap_cohort_ready: bool,
    pub successor_cohort_ready: bool,
}
pub fn GeneratorCohortCommittedThisCall(
    static_cohort_committed: bool,
    dynamic_cohort_committed: bool,
) -> bool {
    static_cohort_committed || dynamic_cohort_committed
}
pub fn IsIncompleteGeneratorCandidate(candidate_observed: bool, cohort_committed: bool) -> bool {
    candidate_observed && !cohort_committed
}
pub fn ChooseRetryBudgetDisposition(
    retryable: bool,
    retries: u32,
    retry_limit: u32,
) -> RetryBudgetDisposition {
    if retryable && retries < retry_limit {
        RetryBudgetDisposition::Retry
    } else {
        RetryBudgetDisposition::Stop
    }
}
pub fn ChooseCallLoopAction(i: &CallLoopDecisionInput) -> CallLoopAction {
    if i.bootstrap_only && i.returned {
        return CallLoopAction::BootstrapReplay;
    }
    if i.ok {
        return CallLoopAction::Stop;
    }
    let limit = i.retry_limit.min(4);
    if (i.gate_bypass || i.target_state_changed) && i.retries < limit {
        CallLoopAction::Retry
    } else {
        CallLoopAction::Stop
    }
}
pub fn ChooseSideEffectDisposition(i: &SideEffectDecisionInput) -> SideEffectDisposition {
    if !i.clean_return {
        SideEffectDisposition::RollbackCall
    } else if i.bootstrap_cohort_ready || i.successor_cohort_ready {
        SideEffectDisposition::ReplayKeepGenerator
    } else if i.bootstrap_mode {
        SideEffectDisposition::BootstrapWithoutGenerator
    } else if !i.fresh_publish {
        SideEffectDisposition::RollbackCall
    } else {
        SideEffectDisposition::CommitTyped
    }
}
