use crate::kernel::MemoryAccess;
use crate::offsets::UObjectOffsets;

use super::{FName, ReflectionError};

pub struct UObject<'a, M: MemoryAccess + ?Sized> {
    pub(crate) driver: &'a M,
    address: u64,
    offsets: UObjectOffsets,
}

impl<'a, M: MemoryAccess + ?Sized> UObject<'a, M> {
    pub fn New(driver: &'a M, address: u64, offsets: UObjectOffsets) -> Self {
        Self {
            driver,
            address,
            offsets,
        }
    }

    pub fn Address(&self) -> u64 {
        self.address
    }

    pub fn Class(&self) -> Result<u64, ReflectionError> {
        self.ReadU64(self.offsets.class)
    }

    pub fn Name(&self) -> Result<FName, ReflectionError> {
        let value = self.ReadU64(self.offsets.name)?;
        Ok(FName {
            comparison_index: value as u32,
            number: (value >> 32) as u32,
        })
    }

    pub fn Index(&self) -> Result<u32, ReflectionError> {
        self.ReadU32(self.offsets.index)
    }

    fn ReadU64(&self, offset: u64) -> Result<u64, ReflectionError> {
        if self.address == 0 || offset == 0 {
            return Err(ReflectionError::InvalidAddress);
        }
        let address = self
            .address
            .checked_add(offset)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        let mut bytes = [0_u8; 8];
        if self.driver.read(address, &mut bytes, false) != 8 {
            return Err(ReflectionError::MemoryRead { address, size: 8 });
        }
        Ok(u64::from_le_bytes(bytes))
    }

    fn ReadU32(&self, offset: u64) -> Result<u32, ReflectionError> {
        if self.address == 0 || offset == 0 {
            return Err(ReflectionError::InvalidAddress);
        }
        let address = self
            .address
            .checked_add(offset)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        let mut bytes = [0_u8; 4];
        if self.driver.read(address, &mut bytes, false) != 4 {
            return Err(ReflectionError::MemoryRead { address, size: 4 });
        }
        Ok(u32::from_le_bytes(bytes))
    }
}
