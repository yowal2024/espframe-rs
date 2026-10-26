use crate::kernel::MemoryAccess;
use crate::offsets::NameArrayOffsets;

use super::name_array::{NameArray, NameArrayProfile, NameCodec, NameEntryAddress};
use super::ReflectionError;

/// UE global-name access backed by any [`MemoryAccess`] implementation.
pub struct GNames<'a, M: MemoryAccess + ?Sized> {
    names: NameArray<'a, M>,
}

impl<'a, M: MemoryAccess + ?Sized> GNames<'a, M> {
    pub fn New(driver: &'a M, base: u64, layout: NameArrayOffsets) -> Self {
        Self {
            names: NameArray::New(driver, base, layout),
        }
    }

    pub fn EntryAddress(&self, index: u32) -> Result<NameEntryAddress, ReflectionError> {
        self.names.EntryAddress(index)
    }

    pub fn EntryAddressWithStride(
        &self,
        index: u32,
        entry_stride: u64,
    ) -> Result<NameEntryAddress, ReflectionError> {
        self.names.EntryAddressWithStride(index, entry_stride)
    }

    pub fn read_name<C: NameCodec>(
        &self,
        index: u32,
        profile: NameArrayProfile,
        codec: C,
    ) -> Result<String, ReflectionError> {
        self.names.read_name(index, profile, codec)
    }
}
