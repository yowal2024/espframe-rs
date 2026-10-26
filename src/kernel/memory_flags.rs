use super::abi::CallMemoryFlags;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SharedMemoryFlags {
    bits: Arc<AtomicU8>,
}

impl SharedMemoryFlags {
    pub fn new(flags: CallMemoryFlags) -> Self {
        Self {
            bits: Arc::new(AtomicU8::new(flags.bits())),
        }
    }

    pub fn for_mem_mode(mem_mode: i32) -> Self {
        Self::new(CallMemoryFlags::for_mem_mode(mem_mode))
    }

    pub fn load(&self) -> CallMemoryFlags {
        CallMemoryFlags::from_bits_retain(self.bits.load(Ordering::Acquire))
    }

    pub fn set(&self, flags: CallMemoryFlags) {
        self.bits.store(flags.bits(), Ordering::Release);
    }

    pub fn set_mem_mode(&self, mem_mode: i32) {
        self.set(CallMemoryFlags::for_mem_mode(mem_mode));
    }
}

impl From<CallMemoryFlags> for SharedMemoryFlags {
    fn from(flags: CallMemoryFlags) -> Self {
        Self::new(flags)
    }
}
