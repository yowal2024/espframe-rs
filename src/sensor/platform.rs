use super::SensorError;
#[cfg(target_os = "android")]
use super::SensorPlatform;

const PROT_NONE: i32 = 0;
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;

pub fn parse_proc_maps_protection(
    maps: &str,
    address: usize,
    length: usize,
) -> Result<i32, SensorError> {
    if length == 0 {
        return Err(SensorError::Platform);
    }
    let end = address.checked_add(length).ok_or(SensorError::Platform)?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(permissions) = fields.next() else {
            continue;
        };
        let Some((start, range_end)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(range_end) = usize::from_str_radix(range_end, 16) else {
            continue;
        };
        if address < start || end > range_end {
            continue;
        }
        let bytes = permissions.as_bytes();
        if bytes.len() < 3 {
            return Err(SensorError::Platform);
        }
        let mut protection = PROT_NONE;
        match bytes[0] {
            b'r' => protection |= PROT_READ,
            b'-' => {}
            _ => return Err(SensorError::Platform),
        }
        match bytes[1] {
            b'w' => protection |= PROT_WRITE,
            b'-' => {}
            _ => return Err(SensorError::Platform),
        }
        match bytes[2] {
            b'x' => protection |= PROT_EXEC,
            b'-' => {}
            _ => return Err(SensorError::Platform),
        }
        return Ok(protection);
    }
    Err(SensorError::Platform)
}

#[cfg(target_os = "android")]
#[derive(Clone, Copy, Debug, Default)]
pub struct AndroidSensorPlatform;

#[cfg(target_os = "android")]
impl SensorPlatform for AndroidSensorPlatform {
    fn ResolveAddress(&self, base: usize, value: u64) -> Result<usize, SensorError> {
        let value = usize::try_from(value).map_err(|_| SensorError::MalformedElf)?;
        if value >= base {
            Ok(value)
        } else {
            base.checked_add(value).ok_or(SensorError::MalformedElf)
        }
    }

    fn OpenXdl(&self, name: &std::ffi::CStr) -> Result<super::LoadedElf, SensorError> {
        crate::xdl::open_loaded(name).map_err(|_| SensorError::ModuleNotFound)
    }

    fn ProtectWritable(&self, page: usize, length: usize) -> Result<i32, SensorError> {
        let page_size = self.PageSize();
        if page_size == 0
            || length == 0
            || !page.is_multiple_of(page_size)
            || !length.is_multiple_of(page_size)
            || page.checked_add(length).is_none()
        {
            return Err(SensorError::Platform);
        }
        let maps = std::fs::read_to_string("/proc/self/maps").map_err(|_| SensorError::Platform)?;
        let original = parse_proc_maps_protection(&maps, page, length)?;
        let result = unsafe {
            libc::mprotect(
                page as *mut core::ffi::c_void,
                length,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if result == 0 {
            Ok(original)
        } else {
            Err(SensorError::Platform)
        }
    }

    fn RestoreProtection(
        &self,
        page: usize,
        length: usize,
        protection: i32,
    ) -> Result<(), SensorError> {
        if protection & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
            return Err(SensorError::Platform);
        }
        let result = unsafe { libc::mprotect(page as *mut core::ffi::c_void, length, protection) };
        if result == 0 {
            Ok(())
        } else {
            Err(SensorError::Platform)
        }
    }

    fn ReadPointer(&self, address: usize) -> Result<usize, SensorError> {
        if address == 0 || !address.is_multiple_of(std::mem::align_of::<usize>()) {
            return Err(SensorError::Platform);
        }
        let pointer = unsafe { &*(address as *const std::sync::atomic::AtomicUsize) };
        Ok(pointer.load(std::sync::atomic::Ordering::Acquire))
    }

    fn WritePointer(&self, address: usize, value: usize) -> Result<(), SensorError> {
        if address == 0 || !address.is_multiple_of(std::mem::align_of::<usize>()) {
            return Err(SensorError::Platform);
        }
        let pointer = unsafe { &*(address as *const std::sync::atomic::AtomicUsize) };
        pointer.store(value, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn ReadProcessMemory(&self, address: usize, bytes: &mut [u8]) -> Result<(), SensorError> {
        if address == 0 || bytes.is_empty() || address.checked_add(bytes.len()).is_none() {
            return Err(SensorError::Platform);
        }
        let local = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let remote = libc::iovec {
            iov_base: address as *mut core::ffi::c_void,
            iov_len: bytes.len(),
        };
        let read = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
        if read == bytes.len() as isize {
            Ok(())
        } else {
            Err(SensorError::Platform)
        }
    }

    fn WriteProcessMemory(&self, address: usize, bytes: &[u8]) -> Result<(), SensorError> {
        if address == 0 || bytes.is_empty() || address.checked_add(bytes.len()).is_none() {
            return Err(SensorError::Platform);
        }
        let local = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let remote = libc::iovec {
            iov_base: address as *mut core::ffi::c_void,
            iov_len: bytes.len(),
        };
        let written = unsafe { libc::process_vm_writev(libc::getpid(), &local, 1, &remote, 1, 0) };
        if written == bytes.len() as isize {
            Ok(())
        } else {
            Err(SensorError::Platform)
        }
    }

    fn PageSize(&self) -> usize {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size).unwrap_or(0)
    }
}
