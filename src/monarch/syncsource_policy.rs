#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgslSyncsourceSelectionKind {
    Selected,
    GuestError,
    InfrastructureError,
}

pub fn SelectVirtualKgslSyncsourceIdWithDiagnostics<F>(
    local_ids: &[u32],
    peek: &mut F,
) -> KgslSyncsourceSelection
where
    F: FnMut(u32) -> Result<(u32, u32), SyncsourceError>,
{
    let max_id = i32::MAX as u32 - 1;
    let mut min_id = 1;
    for _ in 0..=local_ids.len() {
        let mut response = Err(ErrWithBackend(-EAGAIN, 0));
        for _ in 0..3 {
            response = peek(min_id);
            if !matches!(response, Err(SyncsourceError { code, .. }) if code == -EAGAIN) {
                break;
            }
        }
        match response {
            Err(error) => {
                let code = if error.code < 0 && error.code >= -(max_id as i32) {
                    -error.code
                } else {
                    EIO
                };
                return KgslSyncsourceSelection {
                    kind: if code == EBADF || code == ENOSPC {
                        KgslSyncsourceSelectionKind::GuestError
                    } else {
                        KgslSyncsourceSelectionKind::InfrastructureError
                    },
                    id: 0,
                    error: code,
                    backend: error.backend,
                };
            }
            Ok((candidate, backend)) => {
                if candidate < min_id || candidate > max_id {
                    return KgslSyncsourceSelection {
                        kind: KgslSyncsourceSelectionKind::InfrastructureError,
                        id: 0,
                        error: EPROTO,
                        backend,
                    };
                }
                if !local_ids.contains(&candidate) {
                    return KgslSyncsourceSelection {
                        kind: KgslSyncsourceSelectionKind::Selected,
                        id: candidate,
                        error: 0,
                        backend,
                    };
                }
                if candidate == max_id {
                    return KgslSyncsourceSelection {
                        kind: KgslSyncsourceSelectionKind::GuestError,
                        id: 0,
                        error: ENOSPC,
                        backend,
                    };
                }
                min_id = candidate + 1;
            }
        }
    }
    KgslSyncsourceSelection {
        kind: KgslSyncsourceSelectionKind::InfrastructureError,
        id: 0,
        error: ELOOP,
        backend: 0,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KgslSyncsourceSelection {
    pub kind: KgslSyncsourceSelectionKind,
    pub id: u32,
    pub error: i32,
    pub backend: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncsourceError {
    pub code: i32,
    pub backend: u32,
}
pub fn ErrWithBackend(code: i32, backend: u32) -> SyncsourceError {
    SyncsourceError { code, backend }
}
pub const EAGAIN: i32 = 11;
pub const EBADF: i32 = 9;
pub const ENOSPC: i32 = 28;
pub const EPROTO: i32 = 71;
pub const ELOOP: i32 = 40;
pub const EIO: i32 = 5;
pub const KGSL_SYNCSOURCE_KERNEL_PEEK_BACKEND_V1: u32 = 0x4B53_4934;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KgslSyncsourceQueryResult {
    pub completed: bool,
    pub result: i64,
    pub next_id: u32,
    pub backend: u32,
}

pub const fn MakeKernelKgslSyncsourceResult(
    min_id: u32,
    kernel_result: i64,
) -> KgslSyncsourceQueryResult {
    if kernel_result < 0 {
        return KgslSyncsourceQueryResult {
            completed: true,
            result: kernel_result,
            next_id: 0,
            backend: KGSL_SYNCSOURCE_KERNEL_PEEK_BACKEND_V1,
        };
    }
    let invalid = (min_id == 0 && kernel_result != 0)
        || (min_id != 0 && (kernel_result < min_id as i64 || kernel_result > i32::MAX as i64));
    if invalid {
        KgslSyncsourceQueryResult {
            completed: true,
            result: -(EPROTO as i64),
            next_id: 0,
            backend: KGSL_SYNCSOURCE_KERNEL_PEEK_BACKEND_V1,
        }
    } else {
        KgslSyncsourceQueryResult {
            completed: true,
            result: 0,
            next_id: kernel_result as u32,
            backend: KGSL_SYNCSOURCE_KERNEL_PEEK_BACKEND_V1,
        }
    }
}
