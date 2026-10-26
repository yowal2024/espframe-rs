#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr::NonNull;

use crate::physics::dfcol::{PackBytes, PACK_STORED_BYTES};

const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingError {
    InvalidAddress,
    InvalidRange,
    InvalidAlignment,
    Protection,
    UnsupportedPlatform,
}

pub struct OwnedReadOnlyMapping {
    ptr: NonNull<u8>,
    stored_size: usize,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    mapped_size: usize,
}

unsafe impl Send for OwnedReadOnlyMapping {}
unsafe impl Sync for OwnedReadOnlyMapping {}

impl OwnedReadOnlyMapping {
    /// Adopts an existing read-only mapping and owns its lifetime.
    ///
    /// # Safety
    /// `mapping` must be a live, page-aligned owned mapping of `mapped_size`
    /// bytes covering `stored_size`, and it must not be unmapped separately.
    /// Ownership transfers only after successful return; this value then makes
    /// the mapping read-only and unmaps it on drop.
    pub unsafe fn Adopt(
        mapping: *mut c_void,
        stored_size: u64,
        mapped_size: u64,
    ) -> Result<Self, MappingError> {
        let ptr = NonNull::new(mapping.cast::<u8>()).ok_or(MappingError::InvalidAddress)?;
        let stored_size = usize::try_from(stored_size).map_err(|_| MappingError::InvalidRange)?;
        let mapped_size = usize::try_from(mapped_size).map_err(|_| MappingError::InvalidRange)?;
        if stored_size != PACK_STORED_BYTES || mapped_size == 0 || stored_size > mapped_size {
            return Err(MappingError::InvalidRange);
        }
        if !(ptr.as_ptr() as usize).is_multiple_of(PAGE_SIZE)
            || !mapped_size.is_multiple_of(PAGE_SIZE)
        {
            return Err(MappingError::InvalidAlignment);
        }
        if (ptr.as_ptr() as usize).checked_add(stored_size).is_none()
            || (ptr.as_ptr() as usize).checked_add(mapped_size).is_none()
        {
            return Err(MappingError::InvalidRange);
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if unsafe { libc::mprotect(ptr.as_ptr().cast(), mapped_size, libc::PROT_READ) } != 0 {
                return Err(MappingError::Protection);
            }
            Ok(Self {
                ptr,
                stored_size,
                mapped_size,
            })
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let _ = (ptr, stored_size, mapped_size);
            Err(MappingError::UnsupportedPlatform)
        }
    }
}

impl PackBytes for OwnedReadOnlyMapping {
    fn Bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.stored_size) }
    }
}

impl Drop for OwnedReadOnlyMapping {
    fn drop(&mut self) {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        unsafe {
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.mapped_size);
        }
    }
}
