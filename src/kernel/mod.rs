#![allow(non_snake_case)]

pub mod abi;
mod driver;
mod memory_flags;
mod root_shell;
mod transport;
#[cfg(any(test, target_os = "android"))]
mod worker;

pub use driver::{
    KernelDriver, MmuBreakHandle, ModuleBaseLookup, PageBreakHandle, ShadowBreakHandle,
    ShadowHookHandle,
};
pub use memory_flags::SharedMemoryFlags;
pub use root_shell::{run_root_command, RootShell, SystemRootShell};
pub use transport::{KernelTransport, SyscallTransport};
#[cfg(target_os = "android")]
pub use worker::prepare_current_worker;

/// Minimal process-memory access interface consumed by generic UE readers.
///
/// The production implementation is backed by EspFrame's kernel driver.
/// Host adapters preserve its read/write flags. Return values follow the
/// underlying driver's convention: the number of bytes
/// transferred (or a negative error code).
pub trait MemoryAccess {
    fn read(&self, address: u64, buffer: &mut [u8], cache: bool) -> isize;
    fn write(&self, address: u64, buffer: &[u8], cache: bool) -> isize;
    fn pid(&self) -> i32;

    /// Validate an entire record before separate header/payload reads. Host
    /// adapters may narrow this to their allowed memory ranges; a permitted
    /// range does not guarantee that the subsequent driver read succeeds.
    fn permits_read(&self, address: u64, length: usize) -> bool {
        address != 0 && length != 0 && address.checked_add(length as u64).is_some()
    }
}

impl<T: KernelTransport> MemoryAccess for KernelDriver<T> {
    fn read(&self, address: u64, buffer: &mut [u8], cache: bool) -> isize {
        self.ReadMemory(address, buffer, cache)
    }

    fn write(&self, address: u64, buffer: &[u8], cache: bool) -> isize {
        self.WriteMemory(address, buffer, cache)
    }

    fn pid(&self) -> i32 {
        self.Pid()
    }
}
