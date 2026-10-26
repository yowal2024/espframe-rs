use std::ffi::CStr;

use crate::kernel::abi::CallMemoryFlags;
use crate::kernel::{KernelDriver, KernelTransport};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
    #[error("remote operation failed: {0}")]
    OperationFailed(&'static str),
    #[error("remote operation {operation} failed with errno {errno}")]
    Errno { operation: &'static str, errno: i32 },
    #[error("remote symbol was not found")]
    SymbolNotFound,
    #[error("remote address translation failed")]
    AddressTranslation,
    #[error("remote write address overflow")]
    AddressOverflow,
    #[error("remote call timed out")]
    Timeout,
    #[error("remote call stopped unexpectedly with status {status:#x}")]
    UnexpectedStop { status: i32 },
    #[error("ARM64 supports at most 8 register arguments, got {count}")]
    TooManyArguments { count: usize },
    #[error("remote process is not attached")]
    NotAttached,
}

pub trait RemoteProcess {
    fn Attach(&mut self) -> Result<(), RemoteError>;
    fn Detach(&mut self) -> Result<(), RemoteError>;
    fn Alloc(&mut self, len: usize) -> Result<u64, RemoteError>;
    fn Free(&mut self, address: u64) -> Result<(), RemoteError>;
    fn Write(&mut self, address: u64, bytes: &[u8]) -> Result<(), RemoteError>;
    fn CallAddress(&mut self, address: u64, args: &[u64]) -> Result<u64, RemoteError>;
    fn Resolve(&mut self, handle: u64, symbol: &CStr) -> Result<u64, RemoteError>;
}

#[cfg(any(target_os = "android", test))]
trait AttachSyscalls {
    fn AttachRaw(&mut self) -> Result<(), RemoteError>;
    fn WaitForAttachStop(&mut self) -> Result<(), RemoteError>;
    fn StopAndReap(&mut self) -> Result<(), RemoteError>;
    fn DetachRaw(&mut self) -> Result<(), RemoteError>;
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttachOwnership {
    Detached,
    OwnedUnstopped,
    OwnedStopped,
}

#[cfg(any(target_os = "android", test))]
fn attach_owned<S: AttachSyscalls>(
    ownership: &mut AttachOwnership,
    syscalls: &mut S,
) -> Result<(), RemoteError> {
    match *ownership {
        AttachOwnership::Detached => {
            syscalls.AttachRaw()?;
            // PTRACE_ATTACH succeeded, so this process owns the tracee even before waitpid.
            *ownership = AttachOwnership::OwnedUnstopped;
            match syscalls.WaitForAttachStop() {
                Ok(()) => {
                    *ownership = AttachOwnership::OwnedStopped;
                    Ok(())
                }
                Err(wait_error) => match syscalls.StopAndReap() {
                    Err(stop_error) => Err(stop_error),
                    Ok(()) => {
                        *ownership = AttachOwnership::OwnedStopped;
                        match detach_owned(ownership, syscalls) {
                            Err(detach_error) => Err(detach_error),
                            Ok(()) => Err(wait_error),
                        }
                    }
                },
            }
        }
        AttachOwnership::OwnedUnstopped => {
            syscalls.StopAndReap()?;
            *ownership = AttachOwnership::OwnedStopped;
            Ok(())
        }
        AttachOwnership::OwnedStopped => Ok(()),
    }
}

#[cfg(any(target_os = "android", test))]
fn detach_owned<S: AttachSyscalls>(
    ownership: &mut AttachOwnership,
    syscalls: &mut S,
) -> Result<(), RemoteError> {
    if *ownership == AttachOwnership::Detached {
        return Ok(());
    }
    if *ownership == AttachOwnership::OwnedUnstopped {
        syscalls.StopAndReap()?;
        *ownership = AttachOwnership::OwnedStopped;
    }
    syscalls.DetachRaw()?;
    *ownership = AttachOwnership::Detached;
    Ok(())
}

pub trait TargetMemory: Send {
    fn WriteTarget(&mut self, pid: i32, address: u64, bytes: &[u8]) -> Result<(), RemoteError>;

    /// Resolve the base address of a module in the target process. Android's
    /// kernel driver supplies this without requiring access to target
    /// `/proc/<pid>/maps`, which is denied to an untrusted app by SELinux.
    fn ModuleBase(&mut self, _pid: i32, _module_name: &str) -> Result<u64, RemoteError> {
        Err(RemoteError::OperationFailed("target module lookup"))
    }
}

#[allow(dead_code)]
fn rebase_local_address(
    local_address: u64,
    local_bias: u64,
    target_bias: u64,
) -> Result<u64, RemoteError> {
    target_bias
        .checked_add(
            local_address
                .checked_sub(local_bias)
                .ok_or(RemoteError::AddressTranslation)?,
        )
        .ok_or(RemoteError::AddressTranslation)
}

#[cfg(any(target_os = "android", test))]
fn is_direct_local_symbol(symbol: &[u8]) -> bool {
    direct_symbol_module(symbol).is_some()
}

#[cfg(any(target_os = "android", test))]
fn direct_symbol_module(symbol: &[u8]) -> Option<&'static str> {
    match symbol {
        b"malloc" | b"free" | b"write" | b"mmap" | b"munmap" | b"fcntl" | b"close" | b"syscall" => {
            Some("libc.so")
        }
        b"dlsym" | b"android_dlopen_ext" => Some("libdl.so"),
        _ => None,
    }
}

pub struct KernelRemoteMemory<T: KernelTransport> {
    driver: KernelDriver<T>,
}

// The kernel driver's CALL_MEMORY path accepts bounded transfers. Keep this
// aligned with the main-branch upload path, which uses 1 MiB chunks.
const MAX_KERNEL_MEMORY_WRITE: usize = 1024 * 1024;

impl<T: KernelTransport> KernelRemoteMemory<T> {
    pub fn new(driver: KernelDriver<T>) -> Self {
        Self { driver }
    }

    pub fn IntoDriver(self) -> KernelDriver<T> {
        self.driver
    }
}

impl<T: KernelTransport> TargetMemory for KernelRemoteMemory<T> {
    fn WriteTarget(&mut self, pid: i32, address: u64, bytes: &[u8]) -> Result<(), RemoteError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let last_offset =
            u64::try_from(bytes.len() - 1).map_err(|_| RemoteError::AddressOverflow)?;
        address
            .checked_add(last_offset)
            .ok_or(RemoteError::AddressOverflow)?;
        let mut offset = 0usize;
        while offset < bytes.len() {
            let count = (bytes.len() - offset).min(MAX_KERNEL_MEMORY_WRITE);
            let chunk_address = address
                .checked_add(offset as u64)
                .ok_or(RemoteError::AddressOverflow)?;
            let wrote = self.driver.CallMemory_Write(
                pid,
                chunk_address,
                &bytes[offset..offset + count],
                CallMemoryFlags::Write,
            );
            crate::espframe_log!(
                "remote.memory.write",
                "pid={} address={:#x} len={} result={} offset={} flags={:#x}",
                pid,
                chunk_address,
                count,
                wrote,
                offset,
                CallMemoryFlags::Write.Bits()
            );
            if wrote != count as isize {
                return Err(RemoteError::OperationFailed("CallMemory_Write"));
            }
            offset += count;
        }
        Ok(())
    }

    fn ModuleBase(&mut self, pid: i32, module_name: &str) -> Result<u64, RemoteError> {
        match self.driver.ModuleBaseByPidNameTyped(pid, module_name) {
            crate::kernel::ModuleBaseLookup::Ready(base) => Ok(base),
            crate::kernel::ModuleBaseLookup::Missing => {
                Err(RemoteError::OperationFailed("target module missing"))
            }
            crate::kernel::ModuleBaseLookup::IoError(_) => {
                Err(RemoteError::OperationFailed("target module lookup ioctl"))
            }
            crate::kernel::ModuleBaseLookup::Fatal(_) => {
                Err(RemoteError::OperationFailed("target module lookup"))
            }
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use super::{
        attach_owned, detach_owned, AttachOwnership, AttachSyscalls, RemoteError, RemoteProcess,
        TargetMemory,
    };
    use core::ffi::{c_char, c_int, c_void};
    use std::ffi::CStr;
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, Instant};

    const NT_PRSTATUS: usize = 1;
    const RTLD_DEFAULT: *mut c_void = core::ptr::null_mut();
    const RTLD_NOW: c_int = 2;
    const CALL_TIMEOUT: Duration = Duration::from_secs(2);
    const STOP_TIMEOUT: Duration = Duration::from_millis(250);

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct UserPtRegs {
        regs: [u64; 31],
        sp: u64,
        pc: u64,
        pstate: u64,
    }

    #[link(name = "dl")]
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }

    pub struct AndroidRemoteProcess {
        pid: libc::pid_t,
        ownership: AttachOwnership,
        memory: Box<dyn TargetMemory>,
    }

    struct BionicAttachSyscalls {
        pid: libc::pid_t,
    }

    impl BionicAttachSyscalls {
        fn errno(operation: &'static str) -> RemoteError {
            RemoteError::Errno {
                operation,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            }
        }

        fn ptrace(&self, request: libc::c_int, operation: &'static str) -> Result<(), RemoteError> {
            let result = unsafe {
                libc::ptrace(
                    request,
                    self.pid,
                    core::ptr::null_mut::<c_void>(),
                    core::ptr::null_mut::<c_void>(),
                )
            };
            if result == -1 {
                Err(Self::errno(operation))
            } else {
                Ok(())
            }
        }

        fn wait_for_stop(&self, timeout: Duration) -> Result<i32, RemoteError> {
            let deadline = Instant::now() + timeout;
            loop {
                let mut status = 0;
                let waited = unsafe {
                    libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::WUNTRACED)
                };
                if waited == self.pid {
                    return Ok(status);
                }
                if waited == -1 {
                    return Err(Self::errno("waitpid"));
                }
                if Instant::now() >= deadline {
                    return Err(RemoteError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl AttachSyscalls for BionicAttachSyscalls {
        fn AttachRaw(&mut self) -> Result<(), RemoteError> {
            self.ptrace(libc::PTRACE_ATTACH, "ptrace(ATTACH)")
        }

        fn WaitForAttachStop(&mut self) -> Result<(), RemoteError> {
            let status = self.wait_for_stop(CALL_TIMEOUT)?;
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                Ok(())
            } else {
                Err(RemoteError::UnexpectedStop { status })
            }
        }

        fn StopAndReap(&mut self) -> Result<(), RemoteError> {
            if unsafe { libc::kill(self.pid, libc::SIGSTOP) } == -1 {
                return Err(Self::errno("kill(SIGSTOP)"));
            }
            let status = self.wait_for_stop(STOP_TIMEOUT)?;
            if libc::WIFSTOPPED(status) {
                Ok(())
            } else {
                Err(RemoteError::UnexpectedStop { status })
            }
        }

        fn DetachRaw(&mut self) -> Result<(), RemoteError> {
            self.ptrace(libc::PTRACE_DETACH, "ptrace(DETACH)")
        }
    }

    impl AndroidRemoteProcess {
        pub fn new<M: TargetMemory + 'static>(pid: i32, memory: M) -> Result<Self, RemoteError> {
            if pid <= 0 {
                return Err(RemoteError::OperationFailed("pid"));
            }
            Ok(Self {
                pid,
                ownership: AttachOwnership::Detached,
                memory: Box::new(memory),
            })
        }

        fn errno(operation: &'static str) -> RemoteError {
            RemoteError::Errno {
                operation,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            }
        }

        fn ptrace(
            &self,
            request: libc::c_int,
            address: *mut c_void,
            data: *mut c_void,
            operation: &'static str,
        ) -> Result<libc::c_long, RemoteError> {
            let result = unsafe { libc::ptrace(request, self.pid, address, data) };
            if result == -1 {
                Err(Self::errno(operation))
            } else {
                Ok(result)
            }
        }

        fn get_regs(&self) -> Result<UserPtRegs, RemoteError> {
            let mut regs = UserPtRegs::default();
            let mut iov = libc::iovec {
                iov_base: (&mut regs as *mut UserPtRegs).cast(),
                iov_len: core::mem::size_of::<UserPtRegs>(),
            };
            self.ptrace(
                libc::PTRACE_GETREGSET,
                NT_PRSTATUS as *mut c_void,
                (&mut iov as *mut libc::iovec).cast(),
                "ptrace(GETREGSET)",
            )?;
            if iov.iov_len < core::mem::size_of::<UserPtRegs>() {
                return Err(RemoteError::OperationFailed("short ARM64 register set"));
            }
            Ok(regs)
        }

        fn set_regs(&self, regs: &mut UserPtRegs) -> Result<(), RemoteError> {
            let mut iov = libc::iovec {
                iov_base: (regs as *mut UserPtRegs).cast(),
                iov_len: core::mem::size_of::<UserPtRegs>(),
            };
            self.ptrace(
                libc::PTRACE_SETREGSET,
                NT_PRSTATUS as *mut c_void,
                (&mut iov as *mut libc::iovec).cast(),
                "ptrace(SETREGSET)",
            )?;
            Ok(())
        }

        fn fp_regs(&self, request: libc::c_int, regs: &mut [u128; 33]) -> Result<(), RemoteError> {
            let mut iov = libc::iovec {
                iov_base: regs.as_mut_ptr().cast(),
                iov_len: 528,
            };
            self.ptrace(
                request,
                2usize as *mut c_void,
                (&mut iov as *mut libc::iovec).cast(),
                "ptrace(FPREGSET)",
            )?;
            if iov.iov_len != 528 {
                return Err(RemoteError::OperationFailed("short ARM64 FP register set"));
            }
            Ok(())
        }

        fn wait_for_stop(&self, timeout: Duration) -> Result<i32, RemoteError> {
            let deadline = Instant::now() + timeout;
            loop {
                let mut status = 0;
                let waited = unsafe {
                    libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::WUNTRACED)
                };
                if waited == self.pid {
                    return Ok(status);
                }
                if waited == -1 {
                    return Err(Self::errno("waitpid"));
                }
                if Instant::now() >= deadline {
                    return Err(RemoteError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn interrupt_after_timeout(&self) {
            unsafe {
                libc::kill(self.pid, libc::SIGSTOP);
            }
            let _ = self.wait_for_stop(STOP_TIMEOUT);
        }

        fn resolve_local_module_symbol(&mut self, symbol: &CStr) -> Result<u64, RemoteError> {
            let bytes = symbol.to_bytes();
            let direct_module = super::direct_symbol_module(bytes);
            let local = if super::is_direct_local_symbol(bytes) {
                match bytes {
                    b"malloc"
                    | b"free"
                    | b"write"
                    | b"mmap"
                    | b"munmap"
                    | b"fcntl"
                    | b"close"
                    | b"dlsym"
                    | b"syscall"
                    | b"android_dlopen_ext" => {
                        resolve_from_module(direct_module.expect("direct symbol module"), symbol)
                    }
                    _ => unreachable!("direct local symbol list and resolver diverged"),
                }
            } else {
                (unsafe { dlsym(RTLD_DEFAULT, symbol.as_ptr()) }) as u64
            };
            if local == 0 {
                crate::espframe_log!(
                    "remote.resolve.local_fallback",
                    "symbol={}",
                    symbol.to_string_lossy()
                );
                return Err(RemoteError::SymbolNotFound);
            }
            match translate_local_address(self.pid, local, self.memory.as_mut(), direct_module) {
                Ok(address) => Ok(address),
                Err(error) => {
                    crate::espframe_log!(
                        "remote.resolve.translation_error",
                        "symbol={} error={}",
                        symbol.to_string_lossy(),
                        error
                    );
                    Err(error)
                }
            }
        }

        fn remote_dlsym(&mut self, handle: u64, symbol: &CStr) -> Result<u64, RemoteError> {
            crate::espframe_log!(
                "remote.dlsym.begin",
                "symbol={} handle_is_default={}",
                symbol.to_string_lossy(),
                handle == 0
            );
            let dlsym_address = self.resolve_local_module_symbol(c"dlsym")?;
            let malloc_address = self.resolve_local_module_symbol(c"malloc")?;
            let free_address = self.resolve_local_module_symbol(c"free")?;
            let remote_symbol =
                self.CallAddress(malloc_address, &[symbol.to_bytes_with_nul().len() as u64])?;
            if remote_symbol == 0 || remote_symbol == u64::MAX {
                return Err(RemoteError::OperationFailed("malloc"));
            }
            let result = (|| {
                self.Write(remote_symbol, symbol.to_bytes_with_nul())?;
                let address = self.CallAddress(dlsym_address, &[handle, remote_symbol])?;
                if address == 0 {
                    Err(RemoteError::SymbolNotFound)
                } else {
                    Ok(address)
                }
            })();
            let _ = self.CallAddress(free_address, &[remote_symbol]);
            if let Err(error) = &result {
                crate::espframe_log!("remote.dlsym.error", "error={}", error);
            }
            result
        }
    }

    impl RemoteProcess for AndroidRemoteProcess {
        fn Attach(&mut self) -> Result<(), RemoteError> {
            let mut syscalls = BionicAttachSyscalls { pid: self.pid };
            let result = attach_owned(&mut self.ownership, &mut syscalls);
            if let Err(error) = &result {
                crate::espframe_log!("remote.attach.error", "error={}", error);
            } else {
                crate::espframe_log!("remote.attach.ok", "pid={}", self.pid);
            }
            result
        }

        fn Detach(&mut self) -> Result<(), RemoteError> {
            let mut syscalls = BionicAttachSyscalls { pid: self.pid };
            let result = detach_owned(&mut self.ownership, &mut syscalls);
            if let Err(error) = &result {
                crate::espframe_log!("remote.detach.error", "error={}", error);
            }
            result
        }

        fn Alloc(&mut self, len: usize) -> Result<u64, RemoteError> {
            let malloc = self.resolve_local_module_symbol(c"malloc")?;
            let address = self.CallAddress(malloc, &[len as u64])?;
            if address == 0 || address == u64::MAX {
                Err(RemoteError::OperationFailed("malloc"))
            } else {
                Ok(address)
            }
        }

        fn Free(&mut self, address: u64) -> Result<(), RemoteError> {
            let free = self.resolve_local_module_symbol(c"free")?;
            self.CallAddress(free, &[address])?;
            Ok(())
        }

        fn Write(&mut self, address: u64, bytes: &[u8]) -> Result<(), RemoteError> {
            self.memory.WriteTarget(self.pid, address, bytes)
        }

        fn CallAddress(&mut self, address: u64, args: &[u64]) -> Result<u64, RemoteError> {
            if self.ownership != AttachOwnership::OwnedStopped {
                return Err(RemoteError::NotAttached);
            }
            if args.len() > 8 {
                return Err(RemoteError::TooManyArguments { count: args.len() });
            }
            let original = self.get_regs()?;
            let mut fp = [0u128; 33];
            self.fp_regs(libc::PTRACE_GETREGSET, &mut fp)?;
            let mut call_regs = original;
            call_regs.regs[..args.len()].copy_from_slice(args);
            call_regs.regs[30] = 0;
            call_regs.pc = address;
            if let Err(error) = self.set_regs(&mut call_regs) {
                let mut restore = original;
                let _ = self.set_regs(&mut restore);
                return Err(error);
            }

            let call_result = (|| {
                self.ptrace(
                    libc::PTRACE_CONT,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    "ptrace(CONT)",
                )?;
                let deadline = Instant::now() + CALL_TIMEOUT;
                loop {
                    let status = match self
                        .wait_for_stop(deadline.saturating_duration_since(Instant::now()))
                    {
                        Ok(status) => status,
                        Err(RemoteError::Timeout) => {
                            self.interrupt_after_timeout();
                            return Err(RemoteError::Timeout);
                        }
                        Err(error) => return Err(error),
                    };
                    if !libc::WIFSTOPPED(status) {
                        return Err(RemoteError::UnexpectedStop { status });
                    }
                    let signal = libc::WSTOPSIG(status);
                    if (libc::SIGRTMIN()..=libc::SIGRTMAX()).contains(&signal) {
                        // Preserve the payload's local rendezvous if a manager
                        // query overlaps setup. Signal delivery is not a return.
                        self.ptrace(
                            libc::PTRACE_CONT,
                            core::ptr::null_mut(),
                            signal as usize as *mut c_void,
                            "ptrace(CONT signal)",
                        )?;
                        continue;
                    }
                    if signal != libc::SIGSEGV {
                        return Err(RemoteError::UnexpectedStop { status });
                    }
                    let completed = self.get_regs()?;
                    if completed.pc != 0 {
                        return Err(RemoteError::UnexpectedStop { status });
                    }
                    return Ok(completed.regs[0]);
                }
            })();

            let mut restore = original;
            let fp_restore = self.fp_regs(libc::PTRACE_SETREGSET, &mut fp);
            let gp_restore = self.set_regs(&mut restore);
            let restore_result = fp_restore.and(gp_restore);
            let result = match (call_result, restore_result) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => Err(error),
            };
            if let Err(error) = &result {
                crate::espframe_log!("remote.call.error", "error={}", error);
            }
            result
        }

        fn Resolve(&mut self, handle: u64, symbol: &CStr) -> Result<u64, RemoteError> {
            match self.resolve_local_module_symbol(symbol) {
                Ok(address) if handle == 0 => Ok(address),
                _ => self.remote_dlsym(handle, symbol),
            }
        }
    }

    impl Drop for AndroidRemoteProcess {
        fn drop(&mut self) {
            let _ = self.Detach();
        }
    }

    struct MapEntry {
        start: u64,
        end: u64,
        offset: u64,
        path: String,
    }

    fn translate_local_address(
        pid: libc::pid_t,
        local: u64,
        memory: &mut dyn TargetMemory,
        expected_module: Option<&str>,
    ) -> Result<u64, RemoteError> {
        let local_maps = parse_maps("/proc/self/maps").map_err(|error| {
            crate::espframe_log!("remote.maps.local_error", "error={}", error);
            error
        })?;
        let source = local_maps
            .iter()
            .find(|entry| local >= entry.start && local < entry.end && !entry.path.is_empty())
            .ok_or_else(|| {
                crate::espframe_log!("remote.maps.local_address_missing");
                RemoteError::AddressTranslation
            })?;
        let source_name = Path::new(&source.path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                crate::espframe_log!("remote.maps.local_name_missing");
                RemoteError::AddressTranslation
            })?;
        let local_bias = module_bias(&local_maps, &source.path).ok_or_else(|| {
            crate::espframe_log!("remote.maps.local_bias_missing");
            RemoteError::AddressTranslation
        })?;
        let target_module = expected_module.unwrap_or(source_name);
        let target_bias = memory.ModuleBase(pid, target_module).map_err(|error| {
            crate::espframe_log!(
                "remote.maps.target_module_error",
                "module={} error={}",
                target_module,
                error
            );
            error
        })?;
        super::rebase_local_address(local, local_bias, target_bias)
    }

    fn module_bias(entries: &[MapEntry], path: &str) -> Option<u64> {
        entries
            .iter()
            .filter(|entry| entry.path == path)
            .filter_map(|entry| entry.start.checked_sub(entry.offset))
            .min()
    }

    fn parse_maps(path: &str) -> Result<Vec<MapEntry>, RemoteError> {
        let contents =
            fs::read_to_string(path).map_err(|_| RemoteError::OperationFailed("read proc maps"))?;
        let mut entries = Vec::new();
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().ok_or(RemoteError::AddressTranslation)?;
            let _permissions = fields.next().ok_or(RemoteError::AddressTranslation)?;
            let offset = fields.next().ok_or(RemoteError::AddressTranslation)?;
            let _device = fields.next().ok_or(RemoteError::AddressTranslation)?;
            let _inode = fields.next().ok_or(RemoteError::AddressTranslation)?;
            let mapped_path = fields.collect::<Vec<_>>().join(" ");
            let mapped_path = mapped_path
                .strip_suffix(" (deleted)")
                .unwrap_or(&mapped_path);
            let (start, end) = range
                .split_once('-')
                .ok_or(RemoteError::AddressTranslation)?;
            entries.push(MapEntry {
                start: u64::from_str_radix(start, 16)
                    .map_err(|_| RemoteError::AddressTranslation)?,
                end: u64::from_str_radix(end, 16).map_err(|_| RemoteError::AddressTranslation)?,
                offset: u64::from_str_radix(offset, 16)
                    .map_err(|_| RemoteError::AddressTranslation)?,
                path: mapped_path.to_owned(),
            });
        }
        Ok(entries)
    }

    #[allow(dead_code)]
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
        fn malloc(size: usize) -> *mut c_void;
        fn free(pointer: *mut c_void);
        fn write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: libc::off_t,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn android_dlopen_ext(
            filename: *const c_char,
            flags: c_int,
            info: *const c_void,
        ) -> *mut c_void;
        fn syscall(number: libc::c_long, ...) -> libc::c_long;
    }

    fn resolve_from_module(module_name: &str, symbol: &CStr) -> u64 {
        let Ok(module_name) = std::ffi::CString::new(module_name) else {
            return 0;
        };
        let handle = unsafe { dlopen(module_name.as_ptr(), RTLD_NOW) };
        if handle.is_null() {
            return 0;
        }
        let address = unsafe { dlsym(handle, symbol.as_ptr()) } as u64;
        unsafe {
            dlclose(handle);
        }
        address
    }
}

#[cfg(target_os = "android")]
pub use android::AndroidRemoteProcess;

#[cfg(test)]
mod tests {
    use super::{attach_owned, detach_owned, AttachOwnership, AttachSyscalls, RemoteError};

    #[test]
    fn libc_injection_symbols_use_direct_local_resolution() {
        assert!(super::is_direct_local_symbol(b"malloc"));
        assert!(super::is_direct_local_symbol(b"free"));
        assert!(super::is_direct_local_symbol(b"dlsym"));
        assert!(super::is_direct_local_symbol(b"android_dlopen_ext"));
        let payload_symbol = format!("Example_{}{}", "On", "Inject");
        assert!(!super::is_direct_local_symbol(payload_symbol.as_bytes()));
    }

    #[test]
    fn local_function_offset_is_rebased_from_kernel_module_base() {
        assert_eq!(
            super::rebase_local_address(0x1234, 0x1000, 0x9000),
            Ok(0x9234)
        );
        assert_eq!(
            super::rebase_local_address(0x0fff, 0x1000, 0x9000),
            Err(RemoteError::AddressTranslation)
        );
    }

    #[test]
    fn direct_injection_symbols_are_rebased_against_their_real_bionic_modules() {
        assert_eq!(super::direct_symbol_module(b"malloc"), Some("libc.so"));
        assert_eq!(super::direct_symbol_module(b"syscall"), Some("libc.so"));
        assert_eq!(super::direct_symbol_module(b"dlsym"), Some("libdl.so"));
        assert_eq!(
            super::direct_symbol_module(b"android_dlopen_ext"),
            Some("libdl.so")
        );
        let payload_symbol = format!("Example_{}{}", "On", "Inject");
        assert_eq!(super::direct_symbol_module(payload_symbol.as_bytes()), None);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Attach,
        Wait,
        StopAndReap,
        Detach,
    }

    struct FakeSyscalls {
        events: Vec<Event>,
        wait_error: bool,
        stop_error: bool,
        detach_failures: usize,
    }

    impl AttachSyscalls for FakeSyscalls {
        fn AttachRaw(&mut self) -> Result<(), RemoteError> {
            self.events.push(Event::Attach);
            Ok(())
        }

        fn WaitForAttachStop(&mut self) -> Result<(), RemoteError> {
            self.events.push(Event::Wait);
            if self.wait_error {
                Err(RemoteError::OperationFailed("wait"))
            } else {
                Ok(())
            }
        }

        fn StopAndReap(&mut self) -> Result<(), RemoteError> {
            self.events.push(Event::StopAndReap);
            if self.stop_error {
                Err(RemoteError::OperationFailed("stop"))
            } else {
                Ok(())
            }
        }

        fn DetachRaw(&mut self) -> Result<(), RemoteError> {
            self.events.push(Event::Detach);
            if self.detach_failures > 0 {
                self.detach_failures -= 1;
                Err(RemoteError::OperationFailed("detach"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn AttachWaitFailureStopsBeforeDetachAndRetainsOwnershipWhenDetachFails() {
        let mut ownership = AttachOwnership::Detached;
        let mut syscalls = FakeSyscalls {
            events: vec![],
            wait_error: true,
            stop_error: false,
            detach_failures: 1,
        };

        assert_eq!(
            attach_owned(&mut ownership, &mut syscalls),
            Err(RemoteError::OperationFailed("detach"))
        );
        assert_eq!(ownership, AttachOwnership::OwnedStopped);
        assert_eq!(
            syscalls.events,
            [
                Event::Attach,
                Event::Wait,
                Event::StopAndReap,
                Event::Detach
            ]
        );

        detach_owned(&mut ownership, &mut syscalls).unwrap();
        assert_eq!(ownership, AttachOwnership::Detached);
        assert_eq!(syscalls.events.last(), Some(&Event::Detach));
    }

    #[test]
    fn AttachWaitFailureKeepsOwnershipWhenAStopCannotBeReaped() {
        let mut ownership = AttachOwnership::Detached;
        let mut syscalls = FakeSyscalls {
            events: vec![],
            wait_error: true,
            stop_error: true,
            detach_failures: 0,
        };

        assert_eq!(
            attach_owned(&mut ownership, &mut syscalls),
            Err(RemoteError::OperationFailed("stop"))
        );
        assert_eq!(ownership, AttachOwnership::OwnedUnstopped);
        assert_eq!(
            syscalls.events,
            [Event::Attach, Event::Wait, Event::StopAndReap]
        );

        syscalls.stop_error = false;
        detach_owned(&mut ownership, &mut syscalls).unwrap();
        assert_eq!(ownership, AttachOwnership::Detached);
        assert_eq!(&syscalls.events[3..], [Event::StopAndReap, Event::Detach]);
    }
}
