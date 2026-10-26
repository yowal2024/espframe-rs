use crate::kernel::MemoryAccess;
use crate::offsets::NameArrayOffsets;

use super::ReflectionError;

/// Reader for block-based Unreal `FNameEntry` storage.
pub struct NameArray<'a, M: MemoryAccess + ?Sized> {
    driver: &'a M,
    base: u64,
    layout: NameArrayOffsets,
}

/// Authenticated parameters describing one FNamePool entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameArrayProfile {
    pub entry_stride: u64,
    pub header_bytes: usize,
    pub length_shift: u8,
    /// Maximum narrow-name bytes or UTF-16 code units. Wide payloads may use
    /// twice this byte count; custom codecs share the same bounded read limit.
    pub max_name_bytes: usize,
}

impl Default for NameArrayProfile {
    fn default() -> Self {
        Self {
            entry_stride: 2,
            header_bytes: 2,
            length_shift: 6,
            max_name_bytes: 256,
        }
    }
}

impl NameArrayProfile {
    pub fn validate(&self) -> Result<(), ReflectionError> {
        if self.entry_stride == 0
            || self.header_bytes == 0
            || self.header_bytes > 64
            || self.length_shift >= 16
            || self.max_name_bytes == 0
            || self.max_name_bytes > 4096
        {
            return Err(ReflectionError::InvalidNameProfile);
        }
        Ok(())
    }
}

/// Host-injected decoder for raw FNamePool entry bytes.
pub trait NameCodec {
    /// Determine the encoded payload length before reading it. Override this
    /// for encrypted headers or a nonstandard entry header.
    fn payload_len(
        &self,
        header: &[u8],
        profile: &NameArrayProfile,
    ) -> Result<usize, ReflectionError> {
        little_endian_payload_len(header, profile)
    }

    fn decode(&self, bytes: &[u8], profile: &NameArrayProfile) -> Result<String, ReflectionError>;
}

fn little_endian_payload_len(
    header: &[u8],
    profile: &NameArrayProfile,
) -> Result<usize, ReflectionError> {
    profile.validate()?;
    if profile.header_bytes != 2 || header.len() < 2 {
        return Err(ReflectionError::NameDecode);
    }
    let value = u16::from_le_bytes([header[0], header[1]]);
    let length = usize::from(value >> profile.length_shift);
    if length == 0 || length > profile.max_name_bytes {
        return Err(ReflectionError::NameDecode);
    }
    length
        .checked_mul(if value & 1 != 0 { 2 } else { 1 })
        .ok_or(ReflectionError::ArithmeticOverflow)
}

impl<F> NameCodec for F
where
    F: Fn(&[u8], &NameArrayProfile) -> Result<String, ReflectionError>,
{
    fn decode(&self, bytes: &[u8], profile: &NameArrayProfile) -> Result<String, ReflectionError> {
        self(bytes, profile)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LittleEndianNameCodec;

impl NameCodec for LittleEndianNameCodec {
    fn decode(&self, bytes: &[u8], profile: &NameArrayProfile) -> Result<String, ReflectionError> {
        let size = self.payload_len(bytes, profile)?;
        let header = u16::from_le_bytes([bytes[0], bytes[1]]);
        let len = usize::from(header >> profile.length_shift);
        let wide = header & 1 != 0;
        if bytes.len() < profile.header_bytes + size {
            return Err(ReflectionError::NameDecode);
        }
        if wide {
            let mut units = Vec::with_capacity(len);
            for chunk in bytes[2..2 + size].chunks_exact(2) {
                units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            String::from_utf16(&units).map_err(|_| ReflectionError::NameDecode)
        } else {
            String::from_utf8(bytes[2..2 + size].to_vec()).map_err(|_| ReflectionError::NameDecode)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameEntryAddress {
    pub block: u32,
    pub offset: u32,
    pub address: u64,
}

impl<'a, M: MemoryAccess + ?Sized> NameArray<'a, M> {
    pub fn New(driver: &'a M, base: u64, layout: NameArrayOffsets) -> Self {
        Self {
            driver,
            base,
            layout,
        }
    }

    pub fn read_name<C: NameCodec>(
        &self,
        index: u32,
        profile: NameArrayProfile,
        codec: C,
    ) -> Result<String, ReflectionError> {
        profile.validate()?;
        let resolved = self.EntryAddressWithStride(index, profile.entry_stride)?;
        let entry = resolved.address;
        let available = ((1_u64 << self.layout.blocks_bit) - u64::from(resolved.offset))
            .checked_mul(profile.entry_stride)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        if profile.header_bytes as u64 > available {
            return Err(ReflectionError::NameDecode);
        }
        let payload_address = entry
            .checked_add(profile.header_bytes as u64)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; profile.header_bytes];
        if self.driver.read(entry, &mut bytes, false) != profile.header_bytes as isize {
            return Err(ReflectionError::MemoryRead {
                address: entry,
                size: profile.header_bytes,
            });
        }
        let payload_len = codec.payload_len(&bytes, &profile)?;
        if payload_len == 0 || payload_len > profile.max_name_bytes * 2 {
            return Err(ReflectionError::NameDecode);
        }
        if (profile.header_bytes + payload_len) as u64 > available {
            return Err(ReflectionError::NameDecode);
        }
        payload_address
            .checked_add(payload_len as u64)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        if !self
            .driver
            .permits_read(entry, profile.header_bytes + payload_len)
        {
            return Err(ReflectionError::MemoryRead {
                address: entry,
                size: profile.header_bytes + payload_len,
            });
        }
        bytes.resize(profile.header_bytes + payload_len, 0);
        if self
            .driver
            .read(payload_address, &mut bytes[profile.header_bytes..], false)
            != payload_len as isize
        {
            return Err(ReflectionError::MemoryRead {
                address: payload_address,
                size: payload_len,
            });
        }
        codec.decode(&bytes, &profile)
    }

    pub fn EntryAddress(&self, index: u32) -> Result<NameEntryAddress, ReflectionError> {
        self.EntryAddressWithStride(index, NameArrayProfile::default().entry_stride)
    }

    /// Resolve an entry using the authenticated byte stride for the selected
    /// FName storage layout. FNamePool's default entry stride is two bytes;
    /// block-table pointers remain eight bytes on Android arm64.
    pub fn EntryAddressWithStride(
        &self,
        index: u32,
        entry_stride: u64,
    ) -> Result<NameEntryAddress, ReflectionError> {
        if self.base == 0
            || !self.base.is_multiple_of(8)
            || self.layout.blocks == 0
            || self.layout.blocks_bit == 0
            || self.layout.blocks_bit >= 32
        {
            return Err(ReflectionError::InvalidOffset);
        }
        if entry_stride == 0 {
            return Err(ReflectionError::InvalidNameProfile);
        }
        let block = index >> self.layout.blocks_bit;
        let offset = index & ((1_u32 << self.layout.blocks_bit) - 1);
        let block_offset = u64::from(block)
            .checked_mul(8)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        let block_ptr_address = self
            .base
            .checked_add(self.layout.blocks)
            .and_then(|address| address.checked_add(block_offset))
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        block_ptr_address
            .checked_add(8)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        if !block_ptr_address.is_multiple_of(8) {
            return Err(ReflectionError::InvalidAddress);
        }
        let mut block_ptr = [0_u8; 8];
        let read = self.driver.read(block_ptr_address, &mut block_ptr, false);
        if read != 8 {
            return Err(ReflectionError::MemoryRead {
                address: block_ptr_address,
                size: 8,
            });
        }
        let block_ptr = u64::from_le_bytes(block_ptr);
        if block_ptr == 0 || !block_ptr.is_multiple_of(8) {
            return Err(ReflectionError::InvalidAddress);
        }
        let address = block_ptr
            .checked_add(
                u64::from(offset)
                    .checked_mul(entry_stride)
                    .ok_or(ReflectionError::ArithmeticOverflow)?,
            )
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        if address == 0 {
            return Err(ReflectionError::InvalidAddress);
        }
        Ok(NameEntryAddress {
            block,
            offset,
            address,
        })
    }
}
