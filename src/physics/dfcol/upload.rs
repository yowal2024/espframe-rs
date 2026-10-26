#![allow(non_snake_case)]

use std::ffi::CStr;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use crate::inject::{
    InjectError, KernelRemoteMemory, PtraceInjector, RemoteArg, RemoteError, RemoteProcess,
    TargetMemory,
};
use crate::kernel::KernelTransport;

const EXPECTED_ZIP_SIZE: u64 = 81_894_203;
const PAGE_SIZE: u64 = 4096;
const CHUNK_SIZE: usize = 1024 * 1024;
const MIN_REMOTE_ADDRESS: usize = 1_usize << 38;
const MAX_REMOTE_ADDRESS: usize = 1_usize << 39;
const PROT_READ: i64 = 1;
const PROT_READ_WRITE: i64 = 3;
const MAP_PRIVATE_ANONYMOUS_POPULATE: i64 = 0x8022;

/// AArch64 Android may return heap/mmap pointers with an MTE allocation tag
/// in the top byte. DFCOL's remote-call abstraction uses a signed `i64`, so a
/// tagged pointer otherwise becomes negative and is rejected by `call_mmap`.
fn canonical_remote_pointer_return(value: i64) -> i64 {
    const POINTER_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    let raw = value as u64;
    if raw >> 56 == 0 {
        value
    } else {
        (raw & POINTER_MASK) as i64
    }
}

/// Coordinator-owned lock shared by all injection and DFC upload transactions.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DfcolCall {
    Begin {
        generation: u64,
    },
    Adopt {
        generation: u64,
        address: usize,
        stored_size: u64,
        mapped_size: u64,
    },
    Commit {
        generation: u64,
        expected_count: u32,
    },
    Abort {
        generation: u64,
    },
    GetStatus,
    Mmap {
        mapped_size: u64,
    },
    Mprotect {
        address: usize,
        mapped_size: u64,
    },
    Munmap {
        address: usize,
        mapped_size: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DfcolError {
    #[error("generation must be nonzero")]
    InvalidGeneration,
    #[error("adopt address is not a readable target mapping")]
    InvalidAddress,
    #[error("stored size must be nonzero")]
    InvalidStoredSize,
    #[error("stored size exceeds mapped size")]
    StoredSizeExceedsMapping,
    #[error("mapped size is not page aligned")]
    MappingNotPageAligned,
    #[error("expected count must be nonzero")]
    InvalidCount,
    #[error("numeric value does not fit the remote ABI")]
    NumericOverflow,
}

impl DfcolCall {
    pub fn validate(&self) -> Result<(), DfcolError> {
        match *self {
            Self::Begin { generation } | Self::Abort { generation } => {
                if generation == 0 {
                    Err(DfcolError::InvalidGeneration)
                } else if generation > i64::MAX as u64 {
                    Err(DfcolError::NumericOverflow)
                } else {
                    Ok(())
                }
            }
            Self::Adopt {
                generation,
                address,
                stored_size,
                mapped_size,
            } => {
                if generation == 0 {
                    Err(DfcolError::InvalidGeneration)
                } else if generation > i64::MAX as u64
                    || stored_size > i64::MAX as u64
                    || mapped_size > i64::MAX as u64
                {
                    Err(DfcolError::NumericOverflow)
                } else if !(MIN_REMOTE_ADDRESS..MAX_REMOTE_ADDRESS).contains(&address) {
                    Err(DfcolError::InvalidAddress)
                } else if stored_size == 0 {
                    Err(DfcolError::InvalidStoredSize)
                } else if stored_size > mapped_size {
                    Err(DfcolError::StoredSizeExceedsMapping)
                } else if mapped_size == 0 || mapped_size % PAGE_SIZE != 0 {
                    Err(DfcolError::MappingNotPageAligned)
                } else {
                    Ok(())
                }
            }
            Self::Commit {
                generation,
                expected_count,
            } => {
                if generation == 0 {
                    Err(DfcolError::InvalidGeneration)
                } else if generation > i64::MAX as u64 {
                    Err(DfcolError::NumericOverflow)
                } else if expected_count == 0 {
                    Err(DfcolError::InvalidCount)
                } else {
                    Ok(())
                }
            }
            Self::GetStatus => Ok(()),
            Self::Mmap { mapped_size } => validate_mapped_size(mapped_size),
            Self::Mprotect {
                address,
                mapped_size,
            }
            | Self::Munmap {
                address,
                mapped_size,
            } => {
                if !(MIN_REMOTE_ADDRESS..MAX_REMOTE_ADDRESS).contains(&address) {
                    Err(DfcolError::InvalidAddress)
                } else {
                    validate_mapped_size(mapped_size)
                }
            }
        }
    }

    fn remote(&self, prefix: &CStr) -> (CString, Vec<RemoteArg>) {
        match *self {
            Self::Begin { generation } => (
                symbol(prefix, "DfcolBeginPack"),
                vec![RemoteArg::Int(generation as i64)],
            ),
            Self::Adopt {
                generation,
                address,
                stored_size,
                mapped_size,
            } => (
                symbol(prefix, "DfcolAdoptPack"),
                vec![
                    RemoteArg::Int(generation as i64),
                    RemoteArg::Ptr(address as u64),
                    RemoteArg::Int(stored_size as i64),
                    RemoteArg::Int(mapped_size as i64),
                ],
            ),
            Self::Commit {
                generation,
                expected_count,
            } => (
                symbol(prefix, "DfcolCommitPack"),
                vec![
                    RemoteArg::Int(generation as i64),
                    RemoteArg::Int(expected_count as i64),
                ],
            ),
            Self::Abort { generation } => (
                symbol(prefix, "DfcolAbortPack"),
                vec![RemoteArg::Int(generation as i64)],
            ),
            Self::GetStatus => (symbol(prefix, "DfcolGetPackStatus"), vec![]),
            Self::Mmap { mapped_size } => (
                c"mmap".into(),
                vec![
                    RemoteArg::Ptr(0),
                    RemoteArg::Int(mapped_size as i64),
                    RemoteArg::Int(PROT_READ_WRITE),
                    RemoteArg::Int(MAP_PRIVATE_ANONYMOUS_POPULATE),
                    RemoteArg::Int(-1),
                    RemoteArg::Int(0),
                ],
            ),
            Self::Mprotect {
                address,
                mapped_size,
            } => (
                c"mprotect".into(),
                vec![
                    RemoteArg::Ptr(address as u64),
                    RemoteArg::Int(mapped_size as i64),
                    RemoteArg::Int(PROT_READ),
                ],
            ),
            Self::Munmap {
                address,
                mapped_size,
            } => (
                c"munmap".into(),
                vec![
                    RemoteArg::Ptr(address as u64),
                    RemoteArg::Int(mapped_size as i64),
                ],
            ),
        }
    }
}

pub trait RemoteCalls {
    fn Call(&mut self, symbol: &CStr, args: &[RemoteArg]) -> Result<i64, InjectError>;
}

impl<P: RemoteProcess> RemoteCalls for PtraceInjector<P> {
    fn Call(&mut self, symbol: &CStr, args: &[RemoteArg]) -> Result<i64, InjectError> {
        Ok(self.CallCoordinated(symbol, args)?.entry_return)
    }
}

pub trait MemoryWriter {
    fn ResolveTarget(&mut self) -> Result<i32, RemoteError>;
    fn Write(&mut self, pid: i32, address: usize, bytes: &[u8]) -> Result<(), RemoteError>;

    // The target owns the mapping after a successful AdoptPack call.
    fn TransferOwnership(&mut self, _address: usize) {}
}

pub trait TargetResolver {
    fn ResolveTarget(&mut self) -> Result<i32, RemoteError>;
}

/// Task 2's kernel writer paired with the manager's authoritative PID resolver.
pub struct KernelMemoryWriter<T: KernelTransport, S> {
    memory: KernelRemoteMemory<T>,
    resolver: S,
}

impl<T: KernelTransport, S> KernelMemoryWriter<T, S> {
    pub fn new(memory: KernelRemoteMemory<T>, resolver: S) -> Self {
        Self { memory, resolver }
    }

    pub fn IntoParts(self) -> (KernelRemoteMemory<T>, S) {
        (self.memory, self.resolver)
    }
}

impl<T: KernelTransport, S: TargetResolver> MemoryWriter for KernelMemoryWriter<T, S> {
    fn ResolveTarget(&mut self) -> Result<i32, RemoteError> {
        self.resolver.ResolveTarget()
    }

    fn Write(&mut self, pid: i32, address: usize, bytes: &[u8]) -> Result<(), RemoteError> {
        self.memory.WriteTarget(pid, address as u64, bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DfcolUploadError {
    #[error(transparent)]
    Contract(#[from] DfcolError),
    #[error(transparent)]
    Inject(#[from] InjectError),
    #[error(transparent)]
    Memory(#[from] RemoteError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("DFC upload must begin before this operation")]
    NotBegun,
    #[error("DFC generation does not match the active transaction")]
    GenerationMismatch,
    #[error("DFC generation already owns an adopted mapping")]
    MappingAlreadyAdopted,
    #[error("a DFC transaction is already active")]
    TransactionActive,
    #[error("DFC archive does not have the required size")]
    InvalidArchiveSize,
    #[error("DFC archive is not a ZIP file")]
    InvalidArchiveMagic,
    #[error("target PID changed while copying the DFC archive")]
    TargetChanged,
    #[error("remote {operation} returned {value}")]
    UnexpectedReturn { operation: &'static str, value: i64 },
    #[error("remote rollback failed: {source}")]
    RollbackFailed { source: Box<DfcolUploadError> },
}

pub struct DfcolUploader<R, M> {
    pub remote: R,
    pub memory: M,
    symbol_prefix: CString,
    active_generation: Option<u64>,
    adopted: bool,
}

impl<R, M> DfcolUploader<R, M> {
    /// Use the framework's default `EspFrame_` payload export namespace.
    pub fn new(remote: R, memory: M) -> Self {
        Self::with_symbol_prefix(remote, memory, c"EspFrame_")
    }

    /// Select the caller's payload export namespace at construction time.
    pub fn with_symbol_prefix(remote: R, memory: M, symbol_prefix: &CStr) -> Self {
        Self {
            remote,
            memory,
            symbol_prefix: symbol_prefix.to_owned(),
            active_generation: None,
            adopted: false,
        }
    }

    pub fn IntoParts(self) -> (R, M) {
        (self.remote, self.memory)
    }
}

impl<R: RemoteCalls, M: MemoryWriter> DfcolUploader<R, M> {
    pub fn Begin(&mut self, generation: u64) -> Result<(), DfcolUploadError> {
        if self.active_generation.is_some() {
            return Err(DfcolUploadError::TransactionActive);
        }
        let _transaction = crate::inject::INJECTION_DRIVER_LOCK.lock();
        let call = DfcolCall::Begin { generation };
        self.call_one(&call)?;
        self.active_generation = Some(generation);
        self.adopted = false;
        Ok(())
    }

    pub fn Upload(&mut self, generation: u64, path: &Path) -> Result<(), DfcolUploadError> {
        self.require_generation(generation)?;
        if self.adopted {
            return Err(DfcolUploadError::MappingAlreadyAdopted);
        }
        let archive = read_archive(path)?;
        validate_archive(&archive)?;
        let mapped_size = page_aligned_size(archive.len())?;

        let _transaction = crate::inject::INJECTION_DRIVER_LOCK.lock();
        let pid = self.memory.ResolveTarget()?;
        let remote = self.call_mmap(mapped_size)?;
        let mut mapping = RemoteMapping::new(self, remote, mapped_size);
        let upload_result = (|| {
            for chunk in archive.chunks(CHUNK_SIZE) {
                let offset = archive.as_ptr_range().start as usize;
                let chunk_offset = chunk.as_ptr() as usize - offset;
                let address = remote
                    .checked_add(chunk_offset)
                    .ok_or(DfcolUploadError::Memory(RemoteError::AddressOverflow))?;
                mapping.uploader.memory.Write(pid, address, chunk)?;
                if mapping.uploader.memory.ResolveTarget()? != pid {
                    return Err(DfcolUploadError::TargetChanged);
                }
            }

            mapping.uploader.call_mprotect(remote, mapped_size)?;
            let adopt = DfcolCall::Adopt {
                generation,
                address: remote,
                stored_size: archive.len() as u64,
                mapped_size: mapped_size as u64,
            };
            mapping.uploader.call_one(&adopt)?;
            mapping.disarm();
            mapping.uploader.memory.TransferOwnership(remote);
            mapping.uploader.adopted = true;
            Ok(())
        })();
        if let Err(error) = upload_result {
            if let Err(rollback) = mapping.rollback() {
                return Err(DfcolUploadError::RollbackFailed {
                    source: Box::new(rollback),
                });
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn Commit(&mut self, generation: u64, expected_count: u32) -> Result<(), DfcolUploadError> {
        let _transaction = crate::inject::INJECTION_DRIVER_LOCK.lock();
        self.require_generation(generation)?;
        self.call_one(&DfcolCall::Commit {
            generation,
            expected_count,
        })?;
        self.active_generation = None;
        self.adopted = false;
        Ok(())
    }

    pub fn Abort(&mut self, generation: u64) -> Result<(), DfcolUploadError> {
        let _transaction = crate::inject::INJECTION_DRIVER_LOCK.lock();
        self.require_generation(generation)?;
        self.call_one(&DfcolCall::Abort { generation })?;
        self.active_generation = None;
        self.adopted = false;
        Ok(())
    }

    pub fn GetStatus(&mut self) -> Result<i64, DfcolUploadError> {
        // An active uploader already owns the coordinator lock; avoid trying to
        // recursively lock it when status is queried mid-transaction.
        let _transaction = crate::inject::INJECTION_DRIVER_LOCK.lock();
        let value = self.call_raw(&DfcolCall::GetStatus)?;
        if (0..=2).contains(&value) {
            Ok(value)
        } else {
            Err(DfcolUploadError::UnexpectedReturn {
                operation: "remote DFC status",
                value,
            })
        }
    }

    fn require_generation(&self, generation: u64) -> Result<(), DfcolUploadError> {
        match self.active_generation {
            None => Err(DfcolUploadError::NotBegun),
            Some(active) if active != generation => Err(DfcolUploadError::GenerationMismatch),
            Some(_) => Ok(()),
        }
    }

    fn call_one(&mut self, call: &DfcolCall) -> Result<(), DfcolUploadError> {
        let value = self.call_raw(call)?;
        if value == 1 {
            Ok(())
        } else {
            Err(DfcolUploadError::UnexpectedReturn {
                operation: "remote DFC call",
                value,
            })
        }
    }

    fn call_raw(&mut self, call: &DfcolCall) -> Result<i64, DfcolUploadError> {
        call.validate()?;
        let (symbol, args) = call.remote(&self.symbol_prefix);
        Ok(self.remote.Call(&symbol, &args)?)
    }

    fn call_mmap(&mut self, mapped_size: usize) -> Result<usize, DfcolUploadError> {
        let value = canonical_remote_pointer_return(self.call_raw(&DfcolCall::Mmap {
            mapped_size: mapped_size as u64,
        })?);
        let address = usize::try_from(value).ok();
        match address.filter(|address| (MIN_REMOTE_ADDRESS..MAX_REMOTE_ADDRESS).contains(address)) {
            Some(address) => Ok(address),
            None => Err(DfcolUploadError::UnexpectedReturn {
                operation: "mmap",
                value,
            }),
        }
    }

    fn call_mprotect(
        &mut self,
        address: usize,
        mapped_size: usize,
    ) -> Result<(), DfcolUploadError> {
        let value = self.call_raw(&DfcolCall::Mprotect {
            address,
            mapped_size: mapped_size as u64,
        })?;
        if value == 0 {
            Ok(())
        } else {
            Err(DfcolUploadError::UnexpectedReturn {
                operation: "mprotect",
                value,
            })
        }
    }

    fn rollback_mapping(
        &mut self,
        address: usize,
        mapped_size: usize,
    ) -> Result<(), DfcolUploadError> {
        let value = self.call_raw(&DfcolCall::Munmap {
            address,
            mapped_size: mapped_size as u64,
        })?;
        if value == 0 {
            Ok(())
        } else {
            Err(DfcolUploadError::UnexpectedReturn {
                operation: "munmap",
                value,
            })
        }
    }
}

struct RemoteMapping<'a, R: RemoteCalls, M: MemoryWriter> {
    uploader: &'a mut DfcolUploader<R, M>,
    address: usize,
    mapped_size: usize,
    manager_owns_mapping: bool,
}

impl<'a, R: RemoteCalls, M: MemoryWriter> RemoteMapping<'a, R, M> {
    fn new(uploader: &'a mut DfcolUploader<R, M>, address: usize, mapped_size: usize) -> Self {
        Self {
            uploader,
            address,
            mapped_size,
            manager_owns_mapping: true,
        }
    }

    fn disarm(&mut self) {
        self.manager_owns_mapping = false;
    }

    fn rollback(&mut self) -> Result<(), DfcolUploadError> {
        if !self.manager_owns_mapping {
            return Ok(());
        }
        self.manager_owns_mapping = false;
        self.uploader
            .rollback_mapping(self.address, self.mapped_size)
    }
}

impl<R: RemoteCalls, M: MemoryWriter> Drop for RemoteMapping<'_, R, M> {
    fn drop(&mut self) {
        if self.manager_owns_mapping {
            let _ = self.rollback();
        }
    }
}

fn validate_archive(archive: &[u8]) -> Result<(), DfcolUploadError> {
    if archive.len() as u64 != EXPECTED_ZIP_SIZE {
        return Err(DfcolUploadError::InvalidArchiveSize);
    }
    if archive.get(..4) != Some(b"PK\x03\x04") {
        return Err(DfcolUploadError::InvalidArchiveMagic);
    }
    Ok(())
}

fn read_archive(path: &Path) -> Result<Vec<u8>, DfcolUploadError> {
    #[cfg(all(not(unix), not(windows)))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(DfcolUploadError::InvalidArchiveSize);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(DfcolUploadError::InvalidArchiveSize);
        }
    }
    if !metadata.is_file() || metadata.len() != EXPECTED_ZIP_SIZE {
        return Err(DfcolUploadError::InvalidArchiveSize);
    }
    let mut bytes = Vec::with_capacity(EXPECTED_ZIP_SIZE as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn page_aligned_size(size: usize) -> Result<usize, DfcolUploadError> {
    size.checked_add(PAGE_SIZE as usize - 1)
        .map(|value| value & !(PAGE_SIZE as usize - 1))
        .ok_or(DfcolUploadError::Memory(RemoteError::AddressOverflow))
}

fn validate_mapped_size(mapped_size: u64) -> Result<(), DfcolError> {
    if mapped_size == 0 || !mapped_size.is_multiple_of(PAGE_SIZE) {
        Err(DfcolError::MappingNotPageAligned)
    } else if mapped_size > i64::MAX as u64 {
        Err(DfcolError::NumericOverflow)
    } else {
        Ok(())
    }
}

fn symbol(prefix: &CStr, suffix: &str) -> CString {
    let mut bytes = prefix.to_bytes().to_vec();
    bytes.extend_from_slice(suffix.as_bytes());
    CString::new(bytes).expect("CStr prefix and static remote suffix have no NUL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Vec<(CString, Vec<RemoteArg>)>);

    impl RemoteCalls for Recorder {
        fn Call(&mut self, name: &CStr, args: &[RemoteArg]) -> Result<i64, InjectError> {
            self.0.push((name.to_owned(), args.to_vec()));
            Ok(1)
        }
    }

    struct NoMemory;

    impl MemoryWriter for NoMemory {
        fn ResolveTarget(&mut self) -> Result<i32, RemoteError> {
            panic!("control calls must not resolve target memory")
        }
        fn Write(&mut self, _: i32, _: usize, _: &[u8]) -> Result<(), RemoteError> {
            panic!("control calls must not write target memory")
        }
    }

    #[test]
    fn uploader_routes_control_calls_to_the_selected_payload_namespace() {
        for prefix in [c"First_", c"Second_"] {
            let mut uploader =
                DfcolUploader::with_symbol_prefix(Recorder::default(), NoMemory, prefix);
            uploader.Begin(7).unwrap();
            uploader.Abort(7).unwrap();
            assert_eq!(uploader.GetStatus().unwrap(), 1);
            let names: Vec<_> = uploader
                .remote
                .0
                .iter()
                .map(|(name, _)| name.to_owned())
                .collect();
            assert_eq!(
                names,
                [
                    symbol(prefix, "DfcolBeginPack"),
                    symbol(prefix, "DfcolAbortPack"),
                    symbol(prefix, "DfcolGetPackStatus")
                ]
            );
            assert_eq!(uploader.remote.0[0].1, [RemoteArg::Int(7)]);
        }
    }

    #[test]
    fn custom_payload_namespace_does_not_change_system_calls() {
        let (name, args) = DfcolCall::Mmap { mapped_size: 4096 }.remote(c"Example_");
        assert_eq!(name.as_c_str(), c"mmap");
        assert_eq!(args.len(), 6);
        assert_eq!(args[1], RemoteArg::Int(4096));
        let uploader = DfcolUploader::new(Recorder::default(), NoMemory);
        assert_eq!(uploader.symbol_prefix.as_c_str(), c"EspFrame_");
    }
}
