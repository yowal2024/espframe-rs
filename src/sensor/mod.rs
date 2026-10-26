#![allow(non_snake_case)]

pub mod controller;
mod kernel;
pub use kernel::KernelSensorController;
mod dispatch;
pub mod elf;
/// The GOT patcher is deliberately internal so every externally reachable
/// installation participates in the process-global controller lease.
///
/// ```compile_fail
/// use espframe::sensor::SensorHook;
/// ```
mod hook;
pub mod platform;

use std::ffi::CStr;

pub use controller::{AimRotation, Clock, ComputeDelta, MonotonicClock, SensorController};
pub use dispatch::ConvertToSensorEvent;
pub use elf::Elf64Phdr;
pub(crate) use hook::SensorHook;
#[cfg(target_os = "android")]
pub use platform::AndroidSensorPlatform;

pub use crate::xdl::LoadedElf;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SensorError {
    #[error("kernel gyro configuration rejected: {0}; the module must support the gyro event API")]
    KernelRejected(isize),
    #[error("invalid sensor value")]
    InvalidValue,
    #[error("malformed ELF")]
    MalformedElf,
    #[error("ELF has no PT_DYNAMIC")]
    MissingDynamic,
    #[error("ELF dynamic table is unterminated")]
    UnterminatedDynamic,
    #[error("ELF dynamic entry is missing")]
    MissingDynamicEntry,
    #[error("unsupported PLT relocation")]
    UnsupportedRelocation,
    #[error("sensor symbol was not found")]
    SymbolNotFound,
    #[error("loaded sensor module was not found")]
    ModuleNotFound,
    #[error("sensor hook is not active")]
    NotActive,
    #[error("a process-global sensor hook is already active")]
    AlreadyActive,
    #[error("platform operation failed")]
    Platform,
    #[error("sensor hook cleanup failed")]
    CleanupFailed,
}

pub trait SensorPlatform {
    fn ResolveAddress(&self, base: usize, value: u64) -> Result<usize, SensorError> {
        base.checked_add(usize::try_from(value).map_err(|_| SensorError::MalformedElf)?)
            .ok_or(SensorError::MalformedElf)
    }
    fn OpenXdl(&self, name: &CStr) -> Result<LoadedElf, SensorError>;
    fn ProtectWritable(&self, page: usize, length: usize) -> Result<i32, SensorError>;
    fn RestoreProtection(
        &self,
        page: usize,
        length: usize,
        protection: i32,
    ) -> Result<(), SensorError>;
    fn ReadPointer(&self, address: usize) -> Result<usize, SensorError>;
    fn WritePointer(&self, address: usize, value: usize) -> Result<(), SensorError>;
    fn ReadProcessMemory(&self, _address: usize, _bytes: &mut [u8]) -> Result<(), SensorError> {
        Err(SensorError::Platform)
    }
    fn WriteProcessMemory(&self, _address: usize, _bytes: &[u8]) -> Result<(), SensorError> {
        Err(SensorError::Platform)
    }
    fn PageSize(&self) -> usize {
        4096
    }
}
