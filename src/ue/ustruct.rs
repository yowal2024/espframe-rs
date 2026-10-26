use crate::kernel::MemoryAccess;
use crate::offsets::UStructOffsets;

use super::{ReflectionError, UObject};

pub struct UStruct<'a, M: MemoryAccess + ?Sized> {
    object: UObject<'a, M>,
    offsets: UStructOffsets,
}

impl<'a, M: MemoryAccess + ?Sized> UStruct<'a, M> {
    pub fn New(
        driver: &'a M,
        address: u64,
        object_offsets: crate::offsets::UObjectOffsets,
        offsets: UStructOffsets,
    ) -> Self {
        Self {
            object: UObject::New(driver, address, object_offsets),
            offsets,
        }
    }

    pub fn Address(&self) -> u64 {
        self.object.Address()
    }

    pub fn SuperStruct(&self) -> Result<u64, ReflectionError> {
        if self.offsets.super_struct == 0 {
            return Err(ReflectionError::InvalidOffset);
        }
        let address = self
            .object
            .Address()
            .checked_add(self.offsets.super_struct)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        let mut bytes = [0_u8; 8];
        if self.object.driver.read(address, &mut bytes, false) != 8 {
            return Err(ReflectionError::MemoryRead { address, size: 8 });
        }
        Ok(u64::from_le_bytes(bytes))
    }
}
