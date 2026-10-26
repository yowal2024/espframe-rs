//! Payload-local rendezvous. A dedicated worker parks SF/main and RE only at
//! their libc wait syscalls before modifying executable instructions.
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

const IDLE: u32 = 0;
const REQUESTED: u32 = 1;
const PARKED: u32 = 2;
const REJECTED: u32 = 3;
const CANCELLED: u32 = 4;
const RELEASED: u32 = 5;
const MAX_RENDER_THREADS: usize = 16;
const MAX_PARTICIPANTS: usize = 1 + MAX_RENDER_THREADS;

// Slot zero always belongs to SF/main (epoll); every other slot belongs to a
// RenderEngine worker (futex). Keep the handler's storage bounded and resident.
fn participants(
    main: i32,
    current: i32,
    render: &[i32],
    synchronous: bool,
) -> Result<Vec<i32>, String> {
    if render.is_empty() && !synchronous {
        return Err("RenderEngine worker unavailable".into());
    }
    if render.len() > MAX_RENDER_THREADS {
        return Err(format!("too many RenderEngine workers: {}", render.len()));
    }
    let mut tids = Vec::with_capacity(1 + render.len());
    tids.push(main);
    tids.extend_from_slice(render);
    tids[1..].sort_unstable();
    if main <= 0
        || render.iter().any(|&tid| tid <= 0 || tid == main)
        || tids[1..].windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err("invalid Skia rendezvous thread set".into());
    }
    if tids.contains(&current) {
        return Err("Skia setup requires a payload worker".into());
    }
    Ok(tids)
}

// Android ARM64's signal frame reserves 128 bytes for the signal mask.
// libc 0.2.186's Android ucontext_t omits this padding (its sigset_t is 8
// bytes), so casting to that type reads PC and x8 from the wrong offsets.
// Only model the header we read; the kernel's extended contexts follow it.
#[repr(C, align(16))]
struct Arm64MachineContextHeader {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[repr(C)]
struct Arm64SignalContextHeader {
    flags: u64,
    link: u64,
    stack_sp: u64,
    stack_flags: i32,
    stack_padding: u32,
    stack_size: u64,
    signal_mask_reserved: [u8; 128],
    machine: Arm64MachineContextHeader,
}

const _: () = assert!(core::mem::offset_of!(Arm64SignalContextHeader, machine) == 176);

struct Slot {
    tid: AtomicI32,
    state: AtomicU32,
}
impl Slot {
    const fn new() -> Self {
        Self {
            tid: AtomicI32::new(0),
            state: AtomicU32::new(IDLE),
        }
    }
    fn release(&self) {
        // A cancelled but undelivered signal keeps its slot until acknowledged.
        // A retry must never mistake that pending signal for a fresh rendezvous.
        loop {
            let old = self.state.load(Ordering::Acquire);
            let new = match old {
                REQUESTED => CANCELLED,
                PARKED => RELEASED,
                REJECTED => IDLE,
                _ => return,
            };
            if self
                .state
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
    fn arrive(&self, idle: bool) -> bool {
        let next = if idle { PARKED } else { REJECTED };
        if self
            .state
            .compare_exchange(REQUESTED, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return idle;
        }
        let _ = self
            .state
            .compare_exchange(CANCELLED, IDLE, Ordering::AcqRel, Ordering::Acquire);
        false
    }
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use core::ffi::c_void;
    use std::{
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    };

    static LOCK: Mutex<()> = Mutex::new(());
    static SLOTS: [Slot; MAX_PARTICIPANTS] = [const { Slot::new() }; MAX_PARTICIPANTS];
    static TEXT_START: AtomicUsize = AtomicUsize::new(0);
    static TEXT_END: AtomicUsize = AtomicUsize::new(0);
    static SIGNAL: OnceLock<Result<i32, String>> = OnceLock::new();

    unsafe extern "C" fn rendezvous(_: i32, _: *mut libc::siginfo_t, context: *mut c_void) {
        let errno = *libc::__errno();
        let tid = libc::syscall(libc::SYS_gettid) as i32;
        for (index, slot) in SLOTS.iter().enumerate() {
            if slot.tid.load(Ordering::Acquire) != tid {
                continue;
            }
            if slot
                .state
                .compare_exchange(CANCELLED, IDLE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
            if slot.state.load(Ordering::Acquire) != REQUESTED || context.is_null() {
                break;
            }
            let regs = &(*(context.cast::<Arm64SignalContextHeader>())).machine;
            let pc = regs.pc as usize;
            let start = TEXT_START.load(Ordering::Acquire);
            let end = TEXT_END.load(Ordering::Acquire);
            // A signal interrupted an actual svc instruction, not merely some
            // unrelated libc function with a stale syscall number in x8.
            let at_svc = pc >= start.saturating_add(4)
                && pc <= end.saturating_sub(4)
                && (core::ptr::read(pc as *const u32) == 0xd4000001
                    || core::ptr::read((pc - 4) as *const u32) == 0xd4000001);
            let idle = at_svc
                && if index == 0 {
                    matches!(regs.regs[8], 22 | 441) // epoll_pwait / epoll_pwait2
                } else {
                    regs.regs[8] == 98 && matches!(regs.regs[1] & 0x7f, 0 | 9) // futex WAIT[_BITSET]
                };
            if slot.arrive(idle) {
                // Only signal-safe syscalls and lock-free atomics in this handler.
                while slot.state.load(Ordering::Acquire) == PARKED {
                    let timeout = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 20_000_000,
                    };
                    libc::syscall(
                        libc::SYS_futex,
                        slot.state.as_ptr(),
                        libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                        PARKED,
                        &timeout,
                    );
                }
                slot.state.store(IDLE, Ordering::Release);
            }
            break;
        }
        *libc::__errno() = errno;
    }

    fn reserve_signal() -> Result<i32, String> {
        SIGNAL
            .get_or_init(|| unsafe {
                // Keep this handler resident with the payload, including on timeout:
                // a blocked/queued signal must never revert to a terminating default.
                for signal in ((libc::SIGRTMIN() + 8)..=libc::SIGRTMAX()).rev() {
                    let mut old: libc::sigaction = core::mem::zeroed();
                    if libc::sigaction(signal, core::ptr::null(), &mut old) != 0
                        || old.sa_sigaction != libc::SIG_DFL
                    {
                        continue;
                    }
                    let mut action: libc::sigaction = core::mem::zeroed();
                    action.sa_sigaction = rendezvous as *const () as usize;
                    action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
                    libc::sigemptyset(&mut action.sa_mask);
                    let mut replaced: libc::sigaction = core::mem::zeroed();
                    if libc::sigaction(signal, &action, &mut replaced) != 0 {
                        continue;
                    }
                    if replaced.sa_sigaction != libc::SIG_DFL {
                        libc::sigaction(signal, &replaced, core::ptr::null_mut());
                        return Err("signal handler changed during Skia setup".into());
                    }
                    return Ok(signal);
                }
                Err("no unused realtime signal for Skia setup".into())
            })
            .clone()
    }

    struct Resume;
    impl Drop for Resume {
        fn drop(&mut self) {
            for slot in &SLOTS {
                slot.release();
                unsafe {
                    libc::syscall(
                        libc::SYS_futex,
                        slot.state.as_ptr(),
                        libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                        1,
                    );
                }
            }
        }
    }

    fn render_threads() -> Result<Vec<i32>, String> {
        let mut render = Vec::new();
        for entry in std::fs::read_dir("/proc/self/task").map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = match std::fs::read_to_string(entry.path().join("comm")) {
                Ok(name) => name,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("Skia thread discovery: {error}")),
            };
            if name.trim() == "RenderEngine" {
                let tid = entry
                    .file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .map_err(|e| e.to_string())?;
                render.push(tid);
            }
        }
        Ok(render)
    }

    /// Caller must be a new payload worker, never SF/main, RE or a loader callback.
    pub fn with_idle_threads<T>(install: impl FnOnce() -> T) -> Result<T, String> {
        let _lock = LOCK.lock().map_err(|_| "Skia rendezvous lock poisoned")?;
        let main = unsafe { libc::getpid() };
        let current = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
        // Android 12 also has synchronous SKIA_GL on SF/main. Newer versions
        // still require dedicated workers; park all of them, including vendor
        // multi-display pools, before changing their shared executable code.
        let synchronous = matches!(crate::xdl::lzma::android_api_level(), 31 | 32);
        participants(main, current, &render_threads()?, synchronous)?;
        let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| e.to_string())?;
        let line = maps
            .lines()
            .find(|l| l.contains("r-xp") && l.ends_with("/libc.so"))
            .ok_or("libc text unavailable")?;
        let (a, b) = line
            .split_whitespace()
            .next()
            .and_then(|v| v.split_once('-'))
            .ok_or("invalid libc text range")?;
        TEXT_START.store(
            usize::from_str_radix(a, 16).map_err(|e| e.to_string())?,
            Ordering::Release,
        );
        TEXT_END.store(
            usize::from_str_radix(b, 16).map_err(|e| e.to_string())?,
            Ordering::Release,
        );
        let signal = reserve_signal()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // The payload entry point starts this worker while the injector still borrows
            // SF/main. Do not signal that thread until the original call detaches.
            let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
            let tracer = status
                .lines()
                .find_map(|line| line.strip_prefix("TracerPid:"))
                .and_then(|s| s.trim().parse::<u32>().ok())
                .ok_or("missing TracerPid")?;
            if tracer != 0 {
                if Instant::now() >= deadline {
                    return Err("Skia setup waiting for injector detach timed out".into());
                }
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            if SLOTS
                .iter()
                .all(|s| s.state.load(Ordering::Acquire) == IDLE)
            {
                let tids = participants(main, current, &render_threads()?, synchronous)?;
                // All previous handlers acknowledged release/cancellation. Clear
                // stale TIDs before assigning a possibly changed worker set.
                for slot in &SLOTS {
                    slot.tid.store(0, Ordering::Release);
                }
                let resume = Resume;
                let mut parked = true;
                for (slot, &tid) in SLOTS.iter().zip(&tids) {
                    slot.tid.store(tid, Ordering::Release);
                    slot.state.store(REQUESTED, Ordering::Release);
                    if unsafe { libc::syscall(libc::SYS_tgkill, main, tid, signal) } != 0 {
                        slot.state.store(IDLE, Ordering::Release);
                        return Err(format!(
                            "Skia rendezvous signal: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    while slot.state.load(Ordering::Acquire) == REQUESTED
                        && Instant::now() < deadline
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    if slot.state.load(Ordering::Acquire) != PARKED {
                        parked = false;
                        break;
                    }
                }
                // A worker created during discovery must also rendezvous. Release
                // and retry instead of installing against an incomplete snapshot.
                if parked && participants(main, current, &render_threads()?, synchronous)? == tids {
                    crate::espframe_log!("skia.rendezvous.ready", "threads={:?}", tids);
                    let result = install();
                    drop(resume);
                    return Ok(result);
                }
                drop(resume);
            }
            if Instant::now() >= deadline {
                return Err("Skia idle-thread rendezvous timed out".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
#[cfg(target_os = "android")]
pub(super) use android::with_idle_threads;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multi_display_workers_all_receive_distinct_slots_after_main() {
        let tids = participants(2191, 9000, &[3536, 2695, 3535], false).unwrap();
        assert_eq!(tids, [2191, 2695, 3535, 3536]);
        assert_eq!(
            tids,
            participants(2191, 9000, &[3535, 3536, 2695], false).unwrap()
        );
        let slots: [Slot; MAX_PARTICIPANTS] = [const { Slot::new() }; MAX_PARTICIPANTS];
        for (slot, &tid) in slots.iter().zip(&tids) {
            slot.tid.store(tid, Ordering::Release);
            slot.state.store(REQUESTED, Ordering::Release);
            assert!(slot.arrive(true));
        }
        assert!(slots[..tids.len()]
            .iter()
            .all(|slot| slot.state.load(Ordering::Acquire) == PARKED));
        for slot in &slots {
            slot.release();
        }
        assert!(slots[..tids.len()]
            .iter()
            .all(|slot| slot.state.load(Ordering::Acquire) == RELEASED));
        assert!(slots[tids.len()..]
            .iter()
            .all(|slot| slot.state.load(Ordering::Acquire) == IDLE));
    }

    #[test]
    fn worker_selection_preserves_legacy_and_rejects_unsafe_sets() {
        assert_eq!(participants(10, 99, &[], true).unwrap(), [10]);
        assert!(participants(10, 99, &[], false).is_err());
        assert_eq!(participants(10, 99, &[20], false).unwrap(), [10, 20]);
        for workers in [&[20, 20][..], &[10], &[0], &[-1], &[20, 99]] {
            assert!(participants(10, 99, workers, false).is_err());
        }
        assert!(participants(10, 10, &[20], false).is_err());
        let workers: Vec<_> = (100..100 + MAX_RENDER_THREADS as i32).collect();
        assert_eq!(
            participants(10, 99, &workers, false).unwrap().len(),
            MAX_PARTICIPANTS
        );
        let mut too_many = workers;
        too_many.push(1000);
        assert!(participants(10, 99, &too_many, false).is_err());
    }

    #[test]
    fn android_arm64_signal_frame_preserves_reserved_mask_space() {
        // Offsets from the NDK sys/ucontext.h and asm/sigcontext.h, including
        // the 128-byte signal-mask reservation and 16-byte mcontext alignment.
        assert_eq!(
            core::mem::offset_of!(Arm64SignalContextHeader, machine),
            176
        );
        assert_eq!(
            core::mem::offset_of!(Arm64SignalContextHeader, machine.regs),
            184
        );
        assert_eq!(
            core::mem::offset_of!(Arm64SignalContextHeader, machine.pc),
            440
        );
    }
    #[test]
    fn cancellation_does_not_reuse_an_undelivered_signal() {
        let slot = Slot::new();
        slot.state.store(REQUESTED, Ordering::Release);
        slot.release();
        assert_eq!(slot.state.load(Ordering::Acquire), CANCELLED);
        slot.release();
        assert_eq!(slot.state.load(Ordering::Acquire), CANCELLED);
        assert!(slot
            .state
            .compare_exchange(REQUESTED, PARKED, Ordering::AcqRel, Ordering::Acquire)
            .is_err());
        assert!(slot
            .state
            .compare_exchange(CANCELLED, IDLE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok());
    }
    #[test]
    fn parked_and_rejected_threads_are_released_on_all_exit_paths() {
        let slot = Slot::new();
        slot.state.store(PARKED, Ordering::Release);
        slot.release();
        assert_eq!(slot.state.load(Ordering::Acquire), RELEASED);
        slot.state.store(REJECTED, Ordering::Release);
        slot.release();
        assert_eq!(slot.state.load(Ordering::Acquire), IDLE);
    }
    #[test]
    fn timeout_racing_signal_arrival_never_leaves_a_thread_parked() {
        use std::sync::{Arc, Barrier};
        use std::time::{Duration, Instant};
        for _ in 0..64 {
            let slot = Arc::new(Slot::new());
            let barrier = Arc::new(Barrier::new(2));
            slot.state.store(REQUESTED, Ordering::Release);
            let worker_slot = slot.clone();
            let worker_barrier = barrier.clone();
            let handler = std::thread::spawn(move || {
                worker_barrier.wait();
                if worker_slot.arrive(true) {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while worker_slot.state.load(Ordering::Acquire) == PARKED {
                        assert!(
                            Instant::now() < deadline,
                            "cancelled setup left a thread parked"
                        );
                        std::thread::yield_now();
                    }
                    worker_slot.state.store(IDLE, Ordering::Release);
                }
            });
            barrier.wait();
            slot.release();
            handler.join().unwrap();
            assert_eq!(slot.state.load(Ordering::Acquire), IDLE);
        }
    }
}
