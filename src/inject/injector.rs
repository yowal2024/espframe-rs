use super::{Fixup, RemoteArg, RemoteError, RemoteProcess};
use std::ffi::{CStr, CString};

const MAX_ARM64_ARGUMENTS: usize = 8;
const ARM64_POINTER_SIZE: usize = 8;
const MEMFD_NAME: &[u8] = b"espframe\0";
const ARM64_NR_MEMFD_CREATE: u64 = 279;
const MFD_CLOEXEC_ALLOW_SEALING: u64 = 3;
const PROT_READ_WRITE: u64 = 3;
const MAP_PRIVATE_ANONYMOUS_POPULATE: u64 = 0x8022;
const F_ADD_SEALS: u64 = 1033;
const ALL_MEMFD_SEALS: u64 = 15;
const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;
const RTLD_GLOBAL_NOW: u64 = 0x102;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectRequest {
    pub elf: Vec<u8>,
    pub entry_symbol: CString,
    pub args: Vec<RemoteArg>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InjectResult {
    pub entry_return: i64,
}

/// Remote entry points return pointers as raw AArch64 register values. Android
/// may apply an MTE allocation tag in the top byte; strip that tag before the
/// value crosses into the Java-facing signed `Long` ABI.
pub fn canonical_pointer_return(value: i64) -> i64 {
    const POINTER_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    let raw = value as u64;
    if raw >> 56 == 0 {
        value
    } else {
        (raw & POINTER_MASK) as i64
    }
}

#[cfg(test)]
mod pointer_return_tests {
    #[test]
    fn arm64_mte_tag_is_removed_from_pointer_returns() {
        let tagged = 0xb400_006e_e0bd_aa40_u64 as i64;
        assert_eq!(
            super::canonical_pointer_return(tagged),
            0x006e_e0bd_aa40_i64
        );
    }

    #[test]
    fn small_non_pointer_status_values_are_preserved() {
        assert_eq!(super::canonical_pointer_return(0), 0);
        assert_eq!(super::canonical_pointer_return(1), 1);
        assert_eq!(super::canonical_pointer_return(2), 2);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InjectError {
    #[error("ELF image is empty")]
    EmptyElf,
    #[error("symbol is empty")]
    EmptySymbol,
    #[error("byte argument is empty")]
    EmptyBytes,
    #[error("ARM64 supports at most 8 register arguments, got {count}")]
    TooManyArguments { count: usize },
    #[error("fixup pointer at offset {offset} exceeds buffer length {buffer_len}")]
    FixupOutOfBounds { offset: usize, buffer_len: usize },
    #[error("marshalled byte length overflow")]
    SizeOverflow,
    #[error("remote address overflow")]
    AddressOverflow,
    #[error("memfd result {value:#x} does not fit Android's i32 fd field")]
    MemfdOutOfRange { value: u64 },
    #[error("remote cleanup failed during {operation}: {source}")]
    Cleanup {
        operation: &'static str,
        source: RemoteError,
    },
    #[error("remote {operation} returned {value:#x}")]
    UnexpectedReturn { operation: &'static str, value: u64 },
    #[error(transparent)]
    Remote(#[from] RemoteError),
}

pub struct PtraceInjector<P: RemoteProcess> {
    process: P,
}

impl<P: RemoteProcess> PtraceInjector<P> {
    pub fn new(process: P) -> Self {
        Self { process }
    }

    pub fn IntoProcess(self) -> P {
        self.process
    }

    pub fn Inject(&mut self, request: &InjectRequest) -> Result<InjectResult, InjectError> {
        let _lock = crate::inject::INJECTION_DRIVER_LOCK.lock();
        self.InjectCoordinated(request)
    }

    pub(crate) fn InjectCoordinated(
        &mut self,
        request: &InjectRequest,
    ) -> Result<InjectResult, InjectError> {
        crate::espframe_log!(
            "ptrace.inject.begin",
            "elf_len={} args={}",
            request.elf.len(),
            request.args.len()
        );
        if request.elf.is_empty() {
            crate::espframe_log!("ptrace.inject.reject", "error={}", InjectError::EmptyElf);
            return Err(InjectError::EmptyElf);
        }
        validate_symbol(&request.entry_symbol)?;
        validate_args(&request.args)?;

        let mut stage = "attach";
        crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
        let mut session = match Session::attach(&mut self.process) {
            Ok(session) => session,
            Err(error) => {
                crate::espframe_log!("ptrace.inject.error", "stage={} error={}", stage, error);
                return Err(error);
            }
        };
        let result = (|| {
            stage = "memfd_name";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let memfd_name = session.alloc_and_write(MEMFD_NAME)?;
            stage = "resolve_syscall";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let syscall = session.resolve(c"syscall")?;
            stage = "memfd_create";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let memfd = session.call(
                syscall,
                &[ARM64_NR_MEMFD_CREATE, memfd_name, MFD_CLOEXEC_ALLOW_SEALING],
            )?;
            if (memfd as i64) < 0 {
                return Err(InjectError::UnexpectedReturn {
                    operation: "memfd_create",
                    value: memfd,
                });
            }
            session.memfd = Some(memfd);
            let memfd_i32 =
                i32::try_from(memfd).map_err(|_| InjectError::MemfdOutOfRange { value: memfd })?;
            session.free_now(memfd_name)?;

            stage = "resolve_mmap";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let mmap = session.resolve(c"mmap")?;
            stage = "mmap";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let scratch = session.call(
                mmap,
                &[
                    0,
                    request.elf.len() as u64,
                    PROT_READ_WRITE,
                    MAP_PRIVATE_ANONYMOUS_POPULATE,
                    u64::MAX,
                    0,
                ],
            )?;
            if scratch == 0 || scratch == u64::MAX {
                return Err(InjectError::UnexpectedReturn {
                    operation: "mmap",
                    value: scratch,
                });
            }
            session.scratch = Some((scratch, request.elf.len()));
            stage = "write_scratch";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            session.write(scratch, &request.elf)?;

            stage = "resolve_write";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let write = session.resolve(c"write")?;
            stage = "write_memfd";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let write_result = session.call(write, &[memfd, scratch, request.elf.len() as u64]);
            stage = "unmap_scratch";
            session.unmap_now()?;
            let wrote = write_result?;
            if wrote != request.elf.len() as u64 {
                return Err(InjectError::UnexpectedReturn {
                    operation: "write",
                    value: wrote,
                });
            }

            stage = "resolve_fcntl";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let fcntl = session.resolve(c"fcntl")?;
            stage = "seal_memfd";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let seal_result = session.call(fcntl, &[memfd, F_ADD_SEALS, ALL_MEMFD_SEALS])?;
            if seal_result != 0 {
                return Err(InjectError::UnexpectedReturn {
                    operation: "fcntl(F_ADD_SEALS)",
                    value: seal_result,
                });
            }

            stage = "dlopen_args";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let soname = session.alloc_and_write(MEMFD_NAME)?;
            let extinfo = session.alloc_and_write(&AndroidDlExtInfo::new(memfd_i32).to_bytes())?;
            stage = "resolve_android_dlopen_ext";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let android_dlopen_ext = session.resolve(c"android_dlopen_ext")?;
            stage = "android_dlopen_ext";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let handle_result =
                session.call(android_dlopen_ext, &[soname, RTLD_GLOBAL_NOW, extinfo]);
            session.free_now(extinfo)?;
            session.free_now(soname)?;
            let handle = handle_result?;
            if handle == 0 {
                return Err(InjectError::UnexpectedReturn {
                    operation: "android_dlopen_ext",
                    value: handle,
                });
            }

            // The loaded DSO is intentionally process-owned. Closing its source fd does not unload it.
            stage = "close_memfd";
            session.close_memfd_now()?;

            stage = "entry_symbol";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let remote_symbol =
                session.alloc_and_write(request.entry_symbol.as_bytes_with_nul())?;
            stage = "resolve_dlsym";
            let dlsym = session.resolve(c"dlsym")?;
            stage = "dlsym_entry";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let entry_result = session.call(dlsym, &[handle, remote_symbol]);
            session.free_now(remote_symbol)?;
            let entry = entry_result?;
            if entry == 0 {
                return Err(InjectError::UnexpectedReturn {
                    operation: "dlsym",
                    value: entry,
                });
            }

            stage = "call_entry";
            crate::espframe_log!("ptrace.inject.stage", "stage={}", stage);
            let result = marshal_and_call(&mut session, entry, &request.args)?;
            Ok(InjectResult {
                entry_return: result as i64,
            })
        })();
        if let Err(error) = &result {
            crate::espframe_log!("ptrace.inject.error", "stage={} error={}", stage, error);
        }
        let finished = session.finish(result);
        match &finished {
            Ok(value) => {
                crate::espframe_log!("ptrace.inject.end", "entry_return={}", value.entry_return)
            }
            Err(error) => crate::espframe_log!(
                "ptrace.inject.finish_error",
                "stage={} error={}",
                stage,
                error
            ),
        }
        finished
    }

    pub fn Call(&mut self, symbol: &CStr, args: &[RemoteArg]) -> Result<InjectResult, InjectError> {
        let _lock = crate::inject::INJECTION_DRIVER_LOCK.lock();
        self.CallCoordinated(symbol, args)
    }

    pub(crate) fn CallCoordinated(
        &mut self,
        symbol: &CStr,
        args: &[RemoteArg],
    ) -> Result<InjectResult, InjectError> {
        crate::espframe_log!("ptrace.call.begin", "args={}", args.len());
        validate_symbol(symbol)?;
        validate_args(args)?;

        let mut session = Session::attach(&mut self.process).map_err(|error| {
            crate::espframe_log!("ptrace.call.attach_error", "error={}", error);
            error
        })?;
        let result = (|| {
            let address = session.process.Resolve(0, symbol)?;
            if address == 0 {
                return Err(InjectError::UnexpectedReturn {
                    operation: "Resolve",
                    value: 0,
                });
            }
            let result = marshal_and_call(&mut session, address, args)?;
            Ok(InjectResult {
                entry_return: result as i64,
            })
        })();
        let finished = session.finish(result);
        match &finished {
            Ok(value) => {
                crate::espframe_log!("ptrace.call.end", "entry_return={}", value.entry_return)
            }
            Err(error) => crate::espframe_log!("ptrace.call.error", "error={}", error),
        }
        finished
    }
}

fn validate_symbol(symbol: &CStr) -> Result<(), InjectError> {
    if symbol.to_bytes().is_empty() {
        Err(InjectError::EmptySymbol)
    } else {
        Ok(())
    }
}

fn validate_args(args: &[RemoteArg]) -> Result<(), InjectError> {
    if args.len() > MAX_ARM64_ARGUMENTS {
        return Err(InjectError::TooManyArguments { count: args.len() });
    }
    for arg in args {
        match arg {
            RemoteArg::Str(bytes) => {
                bytes
                    .len()
                    .checked_add(1)
                    .ok_or(InjectError::SizeOverflow)?;
            }
            RemoteArg::Bytes { data, fixups } => {
                if data.is_empty() {
                    return Err(InjectError::EmptyBytes);
                }
                for fixup in fixups {
                    validate_fixup(data.len(), fixup)?;
                }
            }
            RemoteArg::Int(_) | RemoteArg::Ptr(_) => {}
        }
    }
    Ok(())
}

fn validate_fixup(buffer_len: usize, fixup: &Fixup) -> Result<(), InjectError> {
    let pointer_end =
        fixup
            .offset
            .checked_add(ARM64_POINTER_SIZE)
            .ok_or(InjectError::FixupOutOfBounds {
                offset: fixup.offset,
                buffer_len,
            })?;
    if pointer_end > buffer_len {
        return Err(InjectError::FixupOutOfBounds {
            offset: fixup.offset,
            buffer_len,
        });
    }
    if fixup.nul_terminated {
        fixup
            .data
            .len()
            .checked_add(1)
            .ok_or(InjectError::SizeOverflow)?;
    }
    Ok(())
}

fn marshal_and_call<P: RemoteProcess>(
    session: &mut Session<'_, P>,
    address: u64,
    args: &[RemoteArg],
) -> Result<u64, InjectError> {
    let allocation_mark = session.allocations.len();
    let mut values = Vec::with_capacity(args.len());
    for arg in args {
        match arg {
            RemoteArg::Int(value) => values.push(*value as u64),
            RemoteArg::Ptr(value) => values.push(*value),
            RemoteArg::Str(bytes) => {
                let mut marshalled = Vec::with_capacity(bytes.len() + 1);
                marshalled.extend_from_slice(bytes);
                marshalled.push(0);
                values.push(session.alloc_and_write(&marshalled)?);
            }
            RemoteArg::Bytes { data, fixups } => {
                let parent = session.alloc_and_write(data)?;
                values.push(parent);
                for fixup in fixups {
                    let mut child =
                        Vec::with_capacity(fixup.data.len() + usize::from(fixup.nul_terminated));
                    child.extend_from_slice(&fixup.data);
                    if fixup.nul_terminated {
                        child.push(0);
                    }
                    let child_address = session.alloc_and_write(&child)?;
                    let pointer_address = parent
                        .checked_add(fixup.offset as u64)
                        .ok_or(InjectError::AddressOverflow)?;
                    session.write(pointer_address, &child_address.to_le_bytes())?;
                }
            }
        }
    }
    let result = session.process.CallAddress(address, &values);
    let cleanup = session.free_since(allocation_mark);
    match (result, cleanup) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => Ok(result?),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AndroidDlExtInfo {
    flags: u64,
    reserved_addr: u64,
    reserved_size: u64,
    relro_fd: i32,
    library_fd: i32,
    library_fd_offset: i64,
    library_namespace: u64,
}

impl AndroidDlExtInfo {
    fn new(library_fd: i32) -> Self {
        Self {
            flags: ANDROID_DLEXT_USE_LIBRARY_FD,
            library_fd,
            ..Self::default()
        }
    }

    fn to_bytes(self) -> [u8; core::mem::size_of::<Self>()] {
        const SIZE: usize = core::mem::size_of::<AndroidDlExtInfo>();
        let mut bytes = [0_u8; SIZE];
        // Layout assertions below prove all 48 bytes are initialized fields with no padding.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&self as *const AndroidDlExtInfo).cast::<u8>(),
                bytes.as_mut_ptr(),
                SIZE,
            );
        }
        bytes
    }
}

const _: () = {
    assert!(core::mem::size_of::<AndroidDlExtInfo>() == 48);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, flags) == 0);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, reserved_addr) == 8);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, reserved_size) == 16);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, relro_fd) == 24);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, library_fd) == 28);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, library_fd_offset) == 32);
    assert!(core::mem::offset_of!(AndroidDlExtInfo, library_namespace) == 40);
};

struct Session<'a, P: RemoteProcess> {
    process: &'a mut P,
    attached: bool,
    allocations: Vec<u64>,
    scratch: Option<(u64, usize)>,
    memfd: Option<u64>,
}

impl<'a, P: RemoteProcess> Session<'a, P> {
    fn attach(process: &'a mut P) -> Result<Self, InjectError> {
        process.Attach()?;
        Ok(Self {
            process,
            attached: true,
            allocations: Vec::new(),
            scratch: None,
            memfd: None,
        })
    }

    fn alloc_and_write(&mut self, bytes: &[u8]) -> Result<u64, InjectError> {
        let address = self.process.Alloc(bytes.len())?;
        if address == 0 || address == u64::MAX {
            return Err(InjectError::UnexpectedReturn {
                operation: "malloc",
                value: address,
            });
        }
        self.allocations.push(address);
        self.write(address, bytes)?;
        Ok(address)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), InjectError> {
        if !bytes.is_empty() && address.checked_add(bytes.len() as u64 - 1).is_none() {
            return Err(InjectError::AddressOverflow);
        }
        self.process.Write(address, bytes)?;
        Ok(())
    }

    fn resolve(&mut self, symbol: &CStr) -> Result<u64, InjectError> {
        let address = self.process.Resolve(0, symbol)?;
        if address == 0 {
            Err(InjectError::UnexpectedReturn {
                operation: "Resolve",
                value: address,
            })
        } else {
            Ok(address)
        }
    }

    fn call(&mut self, address: u64, args: &[u64]) -> Result<u64, InjectError> {
        Ok(self.process.CallAddress(address, args)?)
    }

    fn free_now(&mut self, address: u64) -> Result<(), InjectError> {
        if let Some(index) = self
            .allocations
            .iter()
            .position(|candidate| *candidate == address)
        {
            self.process
                .Free(address)
                .map_err(|source| InjectError::Cleanup {
                    operation: "free",
                    source,
                })?;
            self.allocations.remove(index);
        }
        Ok(())
    }

    fn free_since(&mut self, mark: usize) -> Result<(), InjectError> {
        let mut first_error = None;
        let mut index = self.allocations.len();
        while index > mark {
            index -= 1;
            let address = self.allocations[index];
            match self.process.Free(address) {
                Ok(()) => {
                    self.allocations.remove(index);
                }
                Err(source) if first_error.is_none() => {
                    first_error = Some(InjectError::Cleanup {
                        operation: "free",
                        source,
                    });
                }
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn unmap_now(&mut self) -> Result<(), InjectError> {
        if let Some((address, len)) = self.scratch {
            let munmap =
                self.process
                    .Resolve(0, c"munmap")
                    .map_err(|source| InjectError::Cleanup {
                        operation: "resolve(munmap)",
                        source,
                    })?;
            if munmap == 0 || munmap == u64::MAX {
                return Err(InjectError::Cleanup {
                    operation: "resolve(munmap)",
                    source: RemoteError::OperationFailed("invalid address"),
                });
            }
            let result = self
                .process
                .CallAddress(munmap, &[address, len as u64])
                .map_err(|source| InjectError::Cleanup {
                    operation: "munmap",
                    source,
                })?;
            if result != 0 {
                return Err(InjectError::Cleanup {
                    operation: "munmap",
                    source: RemoteError::OperationFailed("nonzero munmap result"),
                });
            }
            self.scratch = None;
        }
        Ok(())
    }

    fn close_memfd_now(&mut self) -> Result<(), InjectError> {
        if let Some(fd) = self.memfd {
            let close =
                self.process
                    .Resolve(0, c"close")
                    .map_err(|source| InjectError::Cleanup {
                        operation: "resolve(close)",
                        source,
                    })?;
            if close == 0 || close == u64::MAX {
                return Err(InjectError::Cleanup {
                    operation: "resolve(close)",
                    source: RemoteError::OperationFailed("invalid address"),
                });
            }
            let result =
                self.process
                    .CallAddress(close, &[fd])
                    .map_err(|source| InjectError::Cleanup {
                        operation: "close",
                        source,
                    })?;
            if result != 0 {
                return Err(InjectError::Cleanup {
                    operation: "close",
                    source: RemoteError::OperationFailed("nonzero close result"),
                });
            }
            self.memfd = None;
        }
        Ok(())
    }

    fn cleanup(&mut self, final_attempt: bool) -> Result<(), InjectError> {
        let mut first_error = self.free_since(0).err();
        if let Err(error) = self.unmap_now() {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.close_memfd_now() {
            first_error.get_or_insert(error);
        }
        if self.attached && (first_error.is_none() || final_attempt) {
            match self.process.Detach() {
                Ok(()) => self.attached = false,
                Err(source) => {
                    first_error.get_or_insert(InjectError::Cleanup {
                        operation: "detach",
                        source,
                    });
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn finish<T>(&mut self, result: Result<T, InjectError>) -> Result<T, InjectError> {
        match (result, self.cleanup(false)) {
            (_, Err(cleanup)) => Err(cleanup),
            (result, Ok(())) => result,
        }
    }
}

impl<P: RemoteProcess> Drop for Session<'_, P> {
    fn drop(&mut self) {
        let _ = self.cleanup(true);
    }
}

#[cfg(test)]
mod tests {
    use super::AndroidDlExtInfo;
    use core::mem::{offset_of, size_of};

    #[test]
    fn AndroidDlExtInfoMatchesTheApi26Arm64Layout() {
        assert_eq!(size_of::<AndroidDlExtInfo>(), 48);
        assert_eq!(offset_of!(AndroidDlExtInfo, flags), 0);
        assert_eq!(offset_of!(AndroidDlExtInfo, reserved_addr), 8);
        assert_eq!(offset_of!(AndroidDlExtInfo, reserved_size), 16);
        assert_eq!(offset_of!(AndroidDlExtInfo, relro_fd), 24);
        assert_eq!(offset_of!(AndroidDlExtInfo, library_fd), 28);
        assert_eq!(offset_of!(AndroidDlExtInfo, library_fd_offset), 32);
        assert_eq!(offset_of!(AndroidDlExtInfo, library_namespace), 40);
    }
}
