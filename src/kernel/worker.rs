//! Initialize the custom syscall path on a newly created payload worker.
//! Older drivers dispatch from syscall_trace_exit. A native service without
//! seccomp does not enter that path, unlike zygote-created Android apps.
//! Never call this on an existing SurfaceFlinger/RenderEngine/Binder thread.

#[cfg(target_os = "android")]
pub fn prepare_current_worker(scno: i32, option: u64) -> Result<(), String> {
    use super::{abi::CMD_IS_ENABLE_SU, KernelTransport, SyscallTransport};
    if scno <= 0 || option == 0 || option > u32::MAX as u64 {
        return Err("invalid kernel worker ABI".into());
    }
    let activated = ensure_dispatch(
        || unsafe { SyscallTransport.Invoke(scno, option, CMD_IS_ENABLE_SU, [0; 5]) },
        || {
            let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
            if mode < 0 {
                Err(format!(
                    "query worker seccomp: {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(mode)
            }
        },
        activate_current_worker,
    )?;
    crate::espframe_log!(
        "kernel.worker.ready",
        "tid={} activated_trace_path={}",
        unsafe { libc::syscall(libc::SYS_gettid) },
        activated
    );
    Ok(())
}

#[cfg(target_os = "android")]
fn activate_current_worker() -> Result<(), String> {
    // A one-instruction ALLOW filter enables the kernel's syscall-work path.
    // It cannot relax any existing policy; mode != 0 is rejected beforehand.
    // No TSYNC: SF/main and all existing service threads stay untouched. New
    // payload children inherit this filter and no_new_privs from their parent.
    let mut instruction = libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K, linux/filter.h
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    };
    let program = libc::sock_fprog {
        len: 1,
        filter: &mut instruction,
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "set worker no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program,
            0,
            0,
        )
    } != 0
    {
        return Err(format!(
            "enable worker syscall tracing: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// Probe only a read-only boolean command. Never retry a mutating driver call.
fn ensure_dispatch(
    mut probe: impl FnMut() -> isize,
    mode: impl FnOnce() -> Result<i32, String>,
    activate: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    let result = probe();
    if matches!(result, 0 | 1) {
        return Ok(false);
    }
    if result != -38 {
        return Err(format!("kernel worker probe failed: {result}"));
    }
    let mode = mode()?;
    if mode != 0 {
        return Err(format!(
            "kernel syscall unavailable (-38) with seccomp mode {mode}"
        ));
    }
    activate()?;
    let result = probe();
    if matches!(result, 0 | 1) {
        Ok(true)
    } else {
        Err(format!(
            "kernel worker probe after tracing failed: {result}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn working_driver_preserves_the_thread_environment() {
        for value in [0, 1] {
            assert_eq!(
                ensure_dispatch(
                    || value,
                    || panic!("unneeded mode query"),
                    || panic!("unneeded filter")
                ),
                Ok(false)
            );
        }
    }
    #[test]
    fn enosys_activates_once_then_requires_a_successful_probe() {
        let mut results = [-38, 1].into_iter();
        let mut activations = 0;
        assert_eq!(
            ensure_dispatch(
                || results.next().unwrap(),
                || Ok(0),
                || {
                    activations += 1;
                    Ok(())
                }
            ),
            Ok(true)
        );
        assert_eq!(activations, 1);
        assert!(results.next().is_none());
    }
    #[test]
    fn existing_seccomp_is_never_modified() {
        for mode in [1, 2] {
            assert!(ensure_dispatch(|| -38, || Ok(mode), || panic!("existing policy")).is_err());
        }
    }
    #[test]
    fn non_enosys_errors_do_not_change_the_thread() {
        for value in [-1, -13, 2] {
            assert!(ensure_dispatch(
                || value,
                || panic!("unexpected mode query"),
                || panic!("unexpected filter")
            )
            .is_err());
        }
    }
    #[test]
    fn failed_activation_or_probe_is_terminal() {
        assert_eq!(
            ensure_dispatch(|| -38, || Ok(0), || Err("filter denied".into())),
            Err("filter denied".into())
        );
        assert!(ensure_dispatch(|| -38, || Ok(0), || Ok(()))
            .unwrap_err()
            .contains("after tracing"));
        assert_eq!(
            ensure_dispatch(|| -38, || Err("mode denied".into()), || panic!()),
            Err("mode denied".into())
        );
    }
}
