#![allow(non_snake_case)]

mod arg;
mod injector;
mod remote_process;

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard};

thread_local! {
    static INJECTION_DRIVER_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct InjectionDriverLock {
    lock: Mutex<()>,
}

pub(crate) struct InjectionDriverGuard {
    guard: Option<MutexGuard<'static, ()>>,
}

impl InjectionDriverLock {
    const fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }

    pub(crate) fn lock(&'static self) -> InjectionDriverGuard {
        INJECTION_DRIVER_LOCK_DEPTH.with(|depth| {
            let current = depth.get();
            if current != 0 {
                depth.set(
                    current
                        .checked_add(1)
                        .expect("injection lock depth overflow"),
                );
                return InjectionDriverGuard { guard: None };
            }

            let guard = self
                .lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            depth.set(1);
            InjectionDriverGuard { guard: Some(guard) }
        })
    }
}

impl Drop for InjectionDriverGuard {
    fn drop(&mut self) {
        INJECTION_DRIVER_LOCK_DEPTH.with(|depth| {
            let remaining = depth
                .get()
                .checked_sub(1)
                .expect("unbalanced injection lock guard");
            depth.set(remaining);
            if remaining == 0 {
                drop(self.guard.take());
            }
        });
    }
}

pub(crate) static INJECTION_DRIVER_LOCK: InjectionDriverLock = InjectionDriverLock::new();

pub use arg::{Fixup, RemoteArg};
pub use injector::{
    canonical_pointer_return, InjectError, InjectRequest, InjectResult, PtraceInjector,
};
pub use remote_process::{KernelRemoteMemory, RemoteError, RemoteProcess, TargetMemory};

#[cfg(target_os = "android")]
pub use remote_process::AndroidRemoteProcess;

#[cfg(test)]
mod tests {
    #[test]
    fn coordination_lock_can_be_reentered_by_nested_remote_calls() {
        let outer = super::INJECTION_DRIVER_LOCK.lock();
        let inner = super::INJECTION_DRIVER_LOCK.lock();
        drop(inner);
        drop(outer);
    }
}
