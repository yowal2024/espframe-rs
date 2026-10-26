use std::sync::OnceLock;

#[cfg(unix)]
use goblin::elf::program_header::PT_GNU_RELRO;
pub use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
pub use goblin::elf::ProgramHeader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLayout {
    pub min_vaddr: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionRange {
    pub start: usize,
    pub len: usize,
    pub protection: SegmentProtection,
}

static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

pub fn page_size() -> usize {
    *PAGE_SIZE.get_or_init(|| {
        #[cfg(unix)]
        unsafe {
            let size = libc::sysconf(libc::_SC_PAGESIZE);
            if size > 0 {
                return size as usize;
            }
        }

        4096
    })
}

pub fn align_down(addr: usize, alignment: usize) -> usize {
    addr & !(alignment - 1)
}

pub fn align_up(addr: usize, alignment: usize) -> usize {
    (addr + alignment - 1) & !(alignment - 1)
}

pub fn page_start(addr: usize) -> usize {
    align_down(addr, page_size())
}

pub fn page_end(addr: usize) -> usize {
    align_up(addr, page_size())
}

pub fn load_size(phdrs: &[ProgramHeader]) -> Option<LoadLayout> {
    let mut lo = usize::MAX;
    let mut hi = 0usize;

    for ph in phdrs.iter().filter(|ph| ph.p_type == PT_LOAD) {
        let start = usize::try_from(ph.p_vaddr).ok()?;
        let mem_size = usize::try_from(ph.p_memsz).ok()?;
        let file_size = usize::try_from(ph.p_filesz).ok()?;
        let file_offset = usize::try_from(ph.p_offset).ok()?;
        if file_size > mem_size || file_offset.checked_add(file_size).is_none() {
            return None;
        }
        let end = start.checked_add(mem_size)?;
        if start < lo {
            lo = start;
        }
        if end > hi {
            hi = end;
        }
    }

    if lo == usize::MAX || hi == 0 {
        return None;
    }

    let min_vaddr = page_start(lo);
    let max_vaddr = checked_page_end(hi)?;
    Some(LoadLayout {
        min_vaddr,
        size: max_vaddr.checked_sub(min_vaddr)?,
    })
}

fn checked_page_end(addr: usize) -> Option<usize> {
    let alignment = page_size();
    addr.checked_add(alignment - 1)
        .map(|value| align_down(value, alignment))
}

pub fn load_segment_protection_ranges(
    phdrs: &[ProgramHeader],
    load_bias: usize,
    force_writable: bool,
) -> Vec<ProtectionRange> {
    phdrs
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .filter_map(|ph| {
            let seg_start = (ph.p_vaddr as usize).checked_add(load_bias)?;
            let seg_end = seg_start.checked_add(ph.p_memsz as usize)?;
            let page_start = page_start(seg_start);
            let page_end = page_end(seg_end);
            let len = page_end.checked_sub(page_start)?;
            (len != 0).then_some(ProtectionRange {
                start: page_start,
                len,
                protection: SegmentProtection {
                    read: ph.p_flags & PF_R != 0,
                    write: force_writable || ph.p_flags & PF_W != 0,
                    execute: ph.p_flags & PF_X != 0,
                },
            })
        })
        .collect()
}

#[cfg(unix)]
pub struct MappedImage {
    pub base: *mut libc::c_void,
    pub map_size: usize,
    pub bias: usize,
}

#[cfg(unix)]
struct AddressSpaceReservation {
    base: *mut libc::c_void,
    size: usize,
}

#[cfg(unix)]
impl AddressSpaceReservation {
    unsafe fn reserve(size: usize) -> Result<Self, std::io::Error> {
        let base = unsafe { reserve_address_space(size, true)? };
        Ok(Self { base, size })
    }

    fn into_mapped(mut self, bias: usize) -> MappedImage {
        let base = std::mem::replace(&mut self.base, std::ptr::null_mut());
        MappedImage {
            base,
            map_size: self.size,
            bias,
        }
    }
}

#[cfg(unix)]
impl Drop for AddressSpaceReservation {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                unmap_address_space(self.base, self.size);
            }
        }
    }
}

#[cfg(unix)]
/// # Safety
/// The returned mapping must be released exactly once with
/// [`unmap_address_space`]. `size` must be nonzero and page-aligned by the
/// caller's mapping contract.
pub unsafe fn reserve_address_space(
    size: usize,
    prefer_high: bool,
) -> Result<*mut libc::c_void, std::io::Error> {
    let addr = if prefer_high {
        find_highest_gap_start(size).unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    };
    let ptr = unsafe {
        libc::mmap(
            addr,
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

#[cfg(unix)]
/// # Safety
/// `addr` and `size` must identify a mapping previously returned by
/// [`reserve_address_space`] or one of the mapping helpers in this module,
/// and must not be used after this call.
pub unsafe fn unmap_address_space(addr: *mut libc::c_void, size: usize) {
    let _ = unsafe { libc::munmap(addr, size) };
}

#[cfg(unix)]
/// # Safety
/// Every range described by `phdrs` must refer to mapped memory at
/// `load_bias`. The caller must ensure no concurrent unmapping occurs.
pub unsafe fn protect_load_segments(
    phdrs: &[ProgramHeader],
    load_bias: usize,
    force_writable: bool,
) -> Result<(), std::io::Error> {
    for range in load_segment_protection_ranges(phdrs, load_bias, force_writable) {
        if unsafe {
            libc::mprotect(
                range.start as *mut _,
                range.len,
                libc_prot_from_segment(range.protection),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
/// # Safety
/// Every GNU RELRO range in `phdrs` must refer to mapped memory at
/// `load_bias`. The caller must ensure no concurrent unmapping occurs.
pub unsafe fn protect_gnu_relro(
    phdrs: &[ProgramHeader],
    load_bias: usize,
) -> Result<(), std::io::Error> {
    for phdr in phdrs.iter().filter(|phdr| phdr.p_type == PT_GNU_RELRO) {
        let seg_start = usize::try_from(phdr.p_vaddr)
            .ok()
            .and_then(|value| value.checked_add(load_bias))
            .ok_or_else(|| invalid_mapping("GNU RELRO address overflows usize"))?;
        let seg_end = seg_start
            .checked_add(
                usize::try_from(phdr.p_memsz)
                    .map_err(|_| invalid_mapping("GNU RELRO size overflows usize"))?,
            )
            .ok_or_else(|| invalid_mapping("GNU RELRO range overflows usize"))?;
        if !relro_range_is_within_load_pages(phdrs, seg_start, seg_end, load_bias) {
            return Err(invalid_mapping(
                "GNU RELRO range is outside PT_LOAD mappings",
            ));
        }
        let page_start = page_start(seg_start);
        let page_end = checked_page_end(seg_end)
            .ok_or_else(|| invalid_mapping("GNU RELRO page range overflows usize"))?;
        let len = page_end
            .checked_sub(page_start)
            .ok_or_else(|| invalid_mapping("GNU RELRO page range underflows"))?;
        if len == 0 {
            continue;
        }

        if unsafe { libc::mprotect(page_start as *mut _, len, libc::PROT_READ) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg_attr(not(unix), allow(dead_code))]
fn relro_range_is_within_load_pages(
    phdrs: &[ProgramHeader],
    relro_start: usize,
    relro_end: usize,
    load_bias: usize,
) -> bool {
    let relro_start = page_start(relro_start);
    let Some(relro_end) = checked_page_end(relro_end) else {
        return false;
    };

    phdrs
        .iter()
        .filter(|load| load.p_type == PT_LOAD)
        .any(|load| {
            let Some(start) = usize::try_from(load.p_vaddr)
                .ok()
                .and_then(|value| value.checked_add(load_bias))
            else {
                return false;
            };
            let Some(end) = usize::try_from(load.p_memsz)
                .ok()
                .and_then(|size| start.checked_add(size))
            else {
                return false;
            };
            let start = page_start(start);
            let Some(end) = checked_page_end(end) else {
                return false;
            };
            relro_start >= start && relro_end <= end
        })
}

#[cfg(unix)]
/// # Safety
/// `file_bytes` and `phdrs` must describe a valid ELF image. The returned
/// mapping owns its memory and must not be accessed after it is dropped.
pub unsafe fn map_memory_segments(
    file_bytes: &[u8],
    phdrs: &[ProgramHeader],
    layout: LoadLayout,
) -> Result<MappedImage, std::io::Error> {
    validate_mapping_layout(phdrs, layout)?;
    let reservation = unsafe { AddressSpaceReservation::reserve(layout.size)? };
    let bias = (reservation.base as usize)
        .checked_sub(layout.min_vaddr)
        .ok_or_else(|| invalid_mapping("mapping base precedes ELF virtual address range"))?;

    for phdr in phdrs.iter().filter(|ph| ph.p_type == PT_LOAD) {
        unsafe { map_single_memory_segment(file_bytes, phdr, bias)? };
    }

    Ok(reservation.into_mapped(bias))
}

#[cfg(unix)]
/// # Safety
/// `fd` must remain open and refer to the file described by `phdrs` for the
/// duration of this call. The descriptor and program headers must be valid.
pub unsafe fn map_file_segments(
    fd: std::os::unix::io::RawFd,
    phdrs: &[ProgramHeader],
    layout: LoadLayout,
) -> Result<MappedImage, std::io::Error> {
    validate_mapping_layout(phdrs, layout)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file_len = unsafe { stat.assume_init() }
        .st_size
        .try_into()
        .map_err(|_| invalid_mapping("ELF file size is not representable"))?;
    for phdr in phdrs.iter().filter(|ph| ph.p_type == PT_LOAD) {
        let end = usize::try_from(phdr.p_offset)
            .ok()
            .and_then(|offset| {
                usize::try_from(phdr.p_filesz)
                    .ok()
                    .and_then(|size| offset.checked_add(size))
            })
            .ok_or_else(|| invalid_mapping("PT_LOAD file range overflows usize"))?;
        if end > file_len {
            return Err(invalid_mapping("PT_LOAD file range exceeds file length"));
        }
    }
    let reservation = unsafe { AddressSpaceReservation::reserve(layout.size)? };
    let bias = (reservation.base as usize)
        .checked_sub(layout.min_vaddr)
        .ok_or_else(|| invalid_mapping("mapping base precedes ELF virtual address range"))?;

    for phdr in phdrs.iter().filter(|ph| ph.p_type == PT_LOAD) {
        unsafe { map_single_file_segment(fd, phdr, bias)? };
    }

    Ok(reservation.into_mapped(bias))
}

#[cfg(unix)]
fn validate_mapping_layout(
    phdrs: &[ProgramHeader],
    layout: LoadLayout,
) -> Result<(), std::io::Error> {
    let expected =
        load_size(phdrs).ok_or_else(|| invalid_mapping("invalid PT_LOAD segment range"))?;
    if layout != expected {
        return Err(invalid_mapping(
            "PT_LOAD layout does not match segment ranges",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn invalid_mapping(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

#[cfg(unix)]
unsafe fn map_single_memory_segment(
    file_bytes: &[u8],
    phdr: &ProgramHeader,
    bias: usize,
) -> Result<(), std::io::Error> {
    let file_len = usize::try_from(phdr.p_filesz)
        .map_err(|_| invalid_mapping("PT_LOAD file size overflows usize"))?;
    let mem_len = usize::try_from(phdr.p_memsz)
        .map_err(|_| invalid_mapping("PT_LOAD memory size overflows usize"))?;
    if file_len > mem_len {
        return Err(invalid_mapping("PT_LOAD file size exceeds memory size"));
    }
    let file_off = usize::try_from(phdr.p_offset)
        .map_err(|_| invalid_mapping("PT_LOAD file offset overflows usize"))?;
    file_off
        .checked_add(file_len)
        .ok_or_else(|| invalid_mapping("PT_LOAD file range overflows usize"))?;
    let seg_start = usize::try_from(phdr.p_vaddr)
        .ok()
        .and_then(|value| value.checked_add(bias))
        .ok_or_else(|| invalid_mapping("PT_LOAD address overflows usize"))?;
    let seg_end = seg_start
        .checked_add(mem_len)
        .ok_or_else(|| invalid_mapping("PT_LOAD address range overflows usize"))?;
    let seg_page_start = page_start(seg_start);
    let seg_page_end = checked_page_end(seg_end)
        .ok_or_else(|| invalid_mapping("PT_LOAD page range overflows usize"))?;
    let map_size = seg_page_end
        .checked_sub(seg_page_start)
        .ok_or_else(|| invalid_mapping("PT_LOAD page range underflows"))?;

    let prot = prot_from_flags(phdr.p_flags);
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    if unsafe { libc::mprotect(seg_page_start as *mut _, map_size, rw) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    if file_len > 0 {
        let src = file_bytes
            .get(file_off..file_off + file_len)
            .ok_or_else(|| invalid_mapping("PT_LOAD file range exceeds input"))?;
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), seg_start as *mut u8, file_len);
        }
    }

    if prot != rw && unsafe { libc::mprotect(seg_page_start as *mut _, map_size, prot) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
unsafe fn map_single_file_segment(
    fd: std::os::unix::io::RawFd,
    phdr: &ProgramHeader,
    bias: usize,
) -> Result<(), std::io::Error> {
    let file_size = usize::try_from(phdr.p_filesz)
        .map_err(|_| invalid_mapping("PT_LOAD file size overflows usize"))?;
    let mem_size = usize::try_from(phdr.p_memsz)
        .map_err(|_| invalid_mapping("PT_LOAD memory size overflows usize"))?;
    if file_size > mem_size {
        return Err(invalid_mapping("PT_LOAD file size exceeds memory size"));
    }
    let file_offset = usize::try_from(phdr.p_offset)
        .map_err(|_| invalid_mapping("PT_LOAD file offset overflows usize"))?;
    if file_offset % page_size()
        != usize::try_from(phdr.p_vaddr).unwrap_or(usize::MAX) % page_size()
    {
        return Err(invalid_mapping(
            "PT_LOAD file and virtual page offsets differ",
        ));
    }
    let file_end = file_offset
        .checked_add(file_size)
        .ok_or_else(|| invalid_mapping("PT_LOAD file range overflows usize"))?;
    let seg_start = usize::try_from(phdr.p_vaddr)
        .ok()
        .and_then(|value| value.checked_add(bias))
        .ok_or_else(|| invalid_mapping("PT_LOAD address overflows usize"))?;
    let seg_end = seg_start
        .checked_add(mem_size)
        .ok_or_else(|| invalid_mapping("PT_LOAD address range overflows usize"))?;
    let seg_page_start = page_start(seg_start);
    let seg_page_end = checked_page_end(seg_end)
        .ok_or_else(|| invalid_mapping("PT_LOAD page range overflows usize"))?;

    let file_page = page_start(file_offset);
    let file_len = checked_page_end(file_end)
        .ok_or_else(|| invalid_mapping("PT_LOAD file page range overflows usize"))?
        .checked_sub(file_page)
        .ok_or_else(|| invalid_mapping("PT_LOAD file page range underflows"))?;
    let mapped_file_end = seg_page_start
        .checked_add(file_len)
        .ok_or_else(|| invalid_mapping("mapped file page range overflows address"))?;
    if mapped_file_end > seg_page_end {
        return Err(invalid_mapping(
            "file-backed PT_LOAD pages exceed mapped segment",
        ));
    }

    let mut prot = prot_from_flags(phdr.p_flags);
    let needs_exec_restore = prot & libc::PROT_WRITE != 0 && prot & libc::PROT_EXEC != 0;
    if needs_exec_restore {
        prot &= !libc::PROT_EXEC;
    }

    if file_len > 0 {
        let mapped = unsafe {
            libc::mmap(
                seg_page_start as *mut _,
                file_len,
                prot,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                fd,
                file_page as libc::off_t,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
    }

    if file_size < mem_size {
        let tail_start = seg_start
            .checked_add(file_size)
            .ok_or_else(|| invalid_mapping("PT_LOAD tail address overflows"))?;
        let tail_end = page_end(tail_start).min(seg_end);
        if tail_end > tail_start {
            let tail_len = tail_end - tail_start;
            let tail_page = page_start(tail_start);
            let tail_page_len = checked_page_end(tail_end)
                .and_then(|end| end.checked_sub(tail_page))
                .ok_or_else(|| invalid_mapping("PT_LOAD tail page range overflows"))?;
            if unsafe {
                libc::mprotect(
                    tail_page as *mut _,
                    tail_page_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                std::ptr::write_bytes(tail_start as *mut u8, 0, tail_len);
            }
            if unsafe { libc::mprotect(tail_page as *mut _, tail_page_len, prot) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    if seg_page_end > mapped_file_end {
        let bss_addr = mapped_file_end as *mut _;
        let bss_size = seg_page_end
            .checked_sub(mapped_file_end)
            .ok_or_else(|| invalid_mapping("BSS page range underflows"))?;
        let mapped = unsafe {
            libc::mmap(
                bss_addr,
                bss_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
    }

    if needs_exec_restore
        && unsafe {
            libc::mprotect(
                seg_page_start as *mut _,
                seg_page_end - seg_page_start,
                prot | libc::PROT_EXEC,
            )
        } != 0
    {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
fn prot_from_flags(flags: u32) -> i32 {
    libc_prot_from_segment(SegmentProtection {
        read: flags & PF_R != 0,
        write: flags & PF_W != 0,
        execute: flags & PF_X != 0,
    })
}

#[cfg(unix)]
fn libc_prot_from_segment(protection: SegmentProtection) -> i32 {
    let mut prot = 0;
    if protection.read {
        prot |= libc::PROT_READ;
    }
    if protection.write {
        prot |= libc::PROT_WRITE;
    }
    if protection.execute {
        prot |= libc::PROT_EXEC;
    }
    prot
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn find_highest_gap_start(needed_size: usize) -> Option<*mut libc::c_void> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open("/proc/self/maps").ok()?;
    let mut prev_end = 0usize;
    let mut hint = 0usize;
    let needed_size = page_end(needed_size);

    for line in BufReader::new(file).lines().map_while(|result| result.ok()) {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let mut range_parts = range.split('-');
        let start = usize::from_str_radix(range_parts.next()?, 16).ok()?;
        let end = usize::from_str_radix(range_parts.next()?, 16).ok()?;

        let gap_start = page_end(prev_end.max(0x1000_0000));
        if start > gap_start && needed_size <= start.saturating_sub(gap_start) {
            hint = gap_start;
        }
        if end > prev_end {
            prev_end = end;
        }
    }

    (hint != 0).then_some(hint as *mut libc::c_void)
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "android"))))]
#[allow(dead_code)]
fn find_highest_gap_start(_needed_size: usize) -> Option<*mut libc::c_void> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relro_range_accepts_load_segment_padding_to_page_boundary() {
        let load = ProgramHeader {
            p_type: PT_LOAD,
            p_vaddr: 0x1000,
            p_memsz: 0x1f00,
            ..Default::default()
        };

        assert!(relro_range_is_within_load_pages(&[load], 0x2e00, 0x3000, 0,));
    }
}
