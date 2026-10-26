//! Explicit scheduling for threads created by the payload, never borrowed SF threads.
#[derive(Clone, Copy, Debug)]
pub enum WorkerRole {
    Service,
    Interactive,
}

/// SCHED_OTHER prevents inheriting SurfaceFlinger's FIFO/RR policy. Interactive
/// work uses Android's foreground nice value (-4); service work uses nice 0.
/// This does not acquire a wake lock or disable intentional blocking waits.
pub fn configure_current(role: WorkerRole) -> std::io::Result<()> {
    #[cfg(target_os = "android")]
    unsafe {
        let param = libc::sched_param { sched_priority: 0 };
        if libc::sched_setscheduler(0, libc::SCHED_NORMAL, &param) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let nice = match role {
            WorkerRole::Service => 0,
            WorkerRole::Interactive => -4,
        };
        if libc::setpriority(libc::PRIO_PROCESS, 0, nice) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let policy = libc::sched_getscheduler(0);
        if policy == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let mut actual_param = libc::sched_param { sched_priority: 0 };
        if libc::sched_getparam(0, &mut actual_param) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // -1 is also a valid nice value; errno distinguishes a failed read.
        *libc::__errno() = 0;
        let actual_nice = libc::getpriority(libc::PRIO_PROCESS, 0);
        if actual_nice == -1 && *libc::__errno() != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if policy != libc::SCHED_NORMAL || actual_param.sched_priority != 0 || actual_nice != nice {
            return Err(std::io::Error::other(format!(
                "worker scheduling mismatch: policy={policy} priority={} nice={actual_nice}, expected SCHED_OTHER/0 nice={nice}",
                actual_param.sched_priority,
            )));
        }
        crate::espframe_log!(
            "payload.thread.scheduling.verified",
            "tid={} role={:?} policy={} priority={} nice={}",
            libc::gettid(),
            role,
            policy,
            actual_param.sched_priority,
            actual_nice
        );
    }
    #[cfg(not(target_os = "android"))]
    let _ = role;
    Ok(())
}

/// Best effort for shared components that also run in an unprivileged manager.
/// A denied priority raise is recorded and the worker keeps its normal policy.
pub fn enter(name: &'static str, role: WorkerRole) {
    #[cfg(target_os = "android")]
    crate::espframe_log!(
        "payload.thread.start",
        "worker={} tid={}",
        name,
        unsafe { libc::gettid() }
    );
    if let Err(error) = configure_current(role) {
        crate::espframe_log!(
            "payload.thread.scheduling.error",
            "worker={} role={:?} error={}",
            name,
            role,
            error
        );
    }
}
