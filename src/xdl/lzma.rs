//! System-backed XZ/LZMA bridge used by xDL.
//!
//! This module deliberately does not contain an XZ/LZMA decoder.  It mirrors
//! the original xDL `xdl_lzma.c` contract while resolving the unpacker entry
//! points from Android's `/system/lib[64]/liblzma.so` at runtime.  The Rust
//! code below is limited to the xDL ELF lookup/force-load path, ABI-safe state
//! management, and the original output-buffer loop.

#[cfg(target_os = "android")]
use core::ffi::{c_char, c_int, c_void};
#[cfg(target_os = "android")]
use std::ffi::CStr;
#[cfg(target_os = "android")]
use std::sync::OnceLock;

#[cfg(target_os = "android")]
const STATE_WORDS: usize = 4096 / std::mem::size_of::<u64>();
#[cfg(target_os = "android")]
const SZ_OK: c_int = 0;
#[cfg(target_os = "android")]
const CODER_STATUS_NOT_FINISHED: c_int = 2;
#[cfg(target_os = "android")]
const CODER_STATUS_NEEDS_MORE_INPUT: c_int = 3;
#[cfg(target_os = "android")]
const CODER_FINISH_ANY: c_int = 0;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum LzmaError {
    #[error("system liblzma XZ unpacker is unavailable")]
    Unavailable,
    #[error("lzma input is empty")]
    EmptyInput,
    #[error("system liblzma rejected the input stream")]
    DecodeFailed,
    #[error("system liblzma needs more input to finish the stream")]
    Truncated,
    #[error("lzma output exceeded {limit} bytes")]
    OutputTooLarge { limit: usize },
    #[error("lzma output size overflow")]
    SizeOverflow,
}

#[cfg(target_os = "android")]
#[repr(C)]
struct ISzAlloc {
    alloc: unsafe extern "C" fn(*const ISzAlloc, usize) -> *mut c_void,
    free: unsafe extern "C" fn(*const ISzAlloc, *mut c_void),
}

#[cfg(target_os = "android")]
unsafe extern "C" fn internal_alloc(_allocator: *const ISzAlloc, size: usize) -> *mut c_void {
    if size == 0 {
        return std::ptr::null_mut();
    }
    unsafe { libc::malloc(size).cast() }
}

#[cfg(target_os = "android")]
unsafe extern "C" fn internal_free(_allocator: *const ISzAlloc, address: *mut c_void) {
    if address.is_null() {
        return;
    }
    unsafe { libc::free(address) };
}

#[cfg(target_os = "android")]
type CrcGenerateFn = unsafe extern "C" fn();
#[cfg(target_os = "android")]
type ConstructFn = unsafe extern "C" fn(*mut c_void, *const ISzAlloc);
#[cfg(target_os = "android")]
type IsFinishedFn = unsafe extern "C" fn(*const c_void) -> c_int;
#[cfg(target_os = "android")]
type FreeFn = unsafe extern "C" fn(*mut c_void);
#[cfg(target_os = "android")]
type CodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut u8,
    *mut usize,
    *const u8,
    *mut usize,
    c_int,
    *mut c_int,
) -> c_int;
#[cfg(target_os = "android")]
type CodeQFn = unsafe extern "C" fn(
    *mut c_void,
    *mut u8,
    *mut usize,
    *const u8,
    *mut usize,
    c_int,
    c_int,
    *mut c_int,
) -> c_int;

#[cfg(target_os = "android")]
struct SystemLzma {
    // Keep the DSO mapped for the process lifetime, as xDL does after
    // resolving the function pointers from a forced-loaded system library.
    _handle: usize,
    construct: ConstructFn,
    is_finished: IsFinishedFn,
    free: FreeFn,
    code: *mut c_void,
}

#[cfg(target_os = "android")]
unsafe impl Send for SystemLzma {}
#[cfg(target_os = "android")]
unsafe impl Sync for SystemLzma {}

#[cfg(target_os = "android")]
static SYSTEM_LZMA: OnceLock<Option<SystemLzma>> = OnceLock::new();

/// Decompress one complete XZ stream with xDL's system `liblzma.so` symbols.
pub fn xdl_lzma_decompress(input: &[u8]) -> Result<Vec<u8>, LzmaError> {
    decompress(input, None)
}

/// Decompress using xDL's system unpacker and reject output above `max_output`.
pub fn xdl_lzma_decompress_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, LzmaError> {
    decompress(input, Some(max_output))
}

fn decompress(input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, LzmaError> {
    if input.is_empty() {
        return Err(LzmaError::EmptyInput);
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = max_output;
        Err(LzmaError::Unavailable)
    }
    #[cfg(target_os = "android")]
    {
        let unpacker = SYSTEM_LZMA
            .get_or_init(|| unsafe { SystemLzma::load() })
            .as_ref()
            .ok_or(LzmaError::Unavailable)?;
        // The C helper starts with `src_size` bytes and doubles the owned
        // output buffer before every call into `XzUnpacker_Code`. Keep that
        // growth strategy (rather than using a Rust-side decoder or a fixed
        // heuristic) so the system unpacker sees the same buffer contract.
        let initial_size = match max_output {
            Some(limit) => input
                .len()
                .min(limit.checked_add(1).ok_or(LzmaError::SizeOverflow)?),
            None => input.len(),
        };
        if initial_size == 0 {
            return Err(LzmaError::SizeOverflow);
        }
        let mut output = vec![0u8; initial_size];
        let allocator = ISzAlloc {
            alloc: internal_alloc,
            free: internal_free,
        };
        let mut state = [0u64; STATE_WORDS];
        unsafe { (unpacker.construct)(state.as_mut_ptr().cast(), &allocator) };
        let result = decompress_into(unpacker, &mut state, input, &mut output, max_output);
        unsafe { (unpacker.free)(state.as_mut_ptr().cast()) };
        result
    }
}

#[cfg(target_os = "android")]
fn decompress_into(
    unpacker: &SystemLzma,
    state: &mut [u64; STATE_WORDS],
    input: &[u8],
    output: &mut Vec<u8>,
    max_output: Option<usize>,
) -> Result<Vec<u8>, LzmaError> {
    let api_level = android_api_level();
    let mut source_offset = 0usize;
    let mut output_offset = 0usize;
    let final_status = loop {
        // Match the original `do { dst_size *= 2; realloc(...); ... } while
        // (status == CODER_STATUS_NOT_FINISHED)` loop. A bounded decode keeps
        // one sentinel byte (`limit + 1`) so an over-limit write is detected
        // by the post-call offset check without ever returning oversized data.
        let doubled_len = output.len().checked_mul(2).ok_or(LzmaError::SizeOverflow)?;
        let target_len = if let Some(limit) = max_output {
            doubled_len.min(limit.checked_add(1).ok_or(LzmaError::SizeOverflow)?)
        } else {
            doubled_len
        };
        if target_len > output.len() {
            output.resize(target_len, 0);
        }
        let source_remaining = input
            .len()
            .checked_sub(source_offset)
            .ok_or(LzmaError::SizeOverflow)?;
        let output_remaining = output
            .len()
            .checked_sub(output_offset)
            .ok_or(LzmaError::SizeOverflow)?;
        let mut source_used = source_remaining;
        let mut output_used = output_remaining;
        let mut status = 0i32;
        let result = unsafe {
            if api_level >= 29 {
                let code: CodeQFn = std::mem::transmute(unpacker.code);
                code(
                    state.as_mut_ptr().cast(),
                    output.as_mut_ptr().add(output_offset),
                    &mut output_used,
                    input.as_ptr().add(source_offset),
                    &mut source_used,
                    1,
                    CODER_FINISH_ANY,
                    &mut status,
                )
            } else {
                let code: CodeFn = std::mem::transmute(unpacker.code);
                code(
                    state.as_mut_ptr().cast(),
                    output.as_mut_ptr().add(output_offset),
                    &mut output_used,
                    input.as_ptr().add(source_offset),
                    &mut source_used,
                    CODER_FINISH_ANY,
                    &mut status,
                )
            }
        };
        if result != SZ_OK {
            return Err(LzmaError::DecodeFailed);
        }
        source_offset = source_offset
            .checked_add(source_used)
            .ok_or(LzmaError::SizeOverflow)?;
        output_offset = output_offset
            .checked_add(output_used)
            .ok_or(LzmaError::SizeOverflow)?;
        if let Some(limit) = max_output {
            if output_offset > limit {
                return Err(LzmaError::OutputTooLarge { limit });
            }
        }
        if status != CODER_STATUS_NOT_FINISHED {
            break status;
        }
        if source_used == 0 && output_used == 0 {
            if source_offset >= input.len() {
                return Err(LzmaError::Truncated);
            }
            if let Some(limit) = max_output {
                if output_offset >= limit {
                    return Err(LzmaError::OutputTooLarge { limit });
                }
            }
            return Err(LzmaError::DecodeFailed);
        }
    };
    let finished = unsafe { (unpacker.is_finished)(state.as_ptr().cast()) } != 0;
    if !finished {
        if final_status == CODER_STATUS_NEEDS_MORE_INPUT {
            return Err(LzmaError::Truncated);
        }
        return Err(LzmaError::DecodeFailed);
    }
    // XzUnpacker accepts a complete concatenated stream itself. Once it
    // reports a finished stream, only the legacy xDL four-byte zero alignment
    // may remain in the caller-provided input. Silently accepting arbitrary
    // bytes here would turn malformed/authentication-tainted payloads into a
    // successful decode.
    let trailing = input.get(source_offset..).ok_or(LzmaError::SizeOverflow)?;
    let valid_padding = trailing.len() % 4 == 0 && trailing.iter().all(|byte| *byte == 0);
    if !valid_padding {
        return Err(LzmaError::DecodeFailed);
    }
    output.truncate(output_offset);
    Ok(std::mem::take(output))
}

#[cfg(target_os = "android")]
impl SystemLzma {
    unsafe fn load() -> Option<Self> {
        let path: &CStr = if cfg!(target_pointer_width = "64") {
            c"/system/lib64/liblzma.so"
        } else {
            c"/system/lib/liblzma.so"
        };
        // Match xDL_TRY_FORCE_LOAD: reuse an already mapped system image first,
        // then request the canonical /system path if it is not present.
        let already_loaded = crate::xdl::open_loaded(path).is_ok();
        let handle = if already_loaded {
            std::ptr::null_mut()
        } else {
            libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
        };
        let handle = if !already_loaded && handle.is_null() {
            force_system_dlopen(path)
        } else {
            handle
        };
        if !already_loaded && handle.is_null() {
            return None;
        }
        let symbol = |name: &CStr| unsafe { resolve_system_symbol(handle, path, name) };
        let crc_generate_raw = symbol(c"CrcGenerateTable");
        let crc64_generate_raw = symbol(c"Crc64GenerateTable");
        let construct_raw = symbol(c"XzUnpacker_Construct");
        let is_finished_raw = symbol(c"XzUnpacker_IsStreamWasFinished");
        let free_raw = symbol(c"XzUnpacker_Free");
        let code = symbol(c"XzUnpacker_Code");
        if [
            crc_generate_raw,
            crc64_generate_raw,
            construct_raw,
            is_finished_raw,
            free_raw,
            code,
        ]
        .iter()
        .any(|address| address.is_null())
        {
            return None;
        }
        let crc_generate: CrcGenerateFn = std::mem::transmute(crc_generate_raw);
        let crc64_generate: CrcGenerateFn = std::mem::transmute(crc64_generate_raw);
        let construct: ConstructFn = std::mem::transmute(construct_raw);
        let is_finished: IsFinishedFn = std::mem::transmute(is_finished_raw);
        let free: FreeFn = std::mem::transmute(free_raw);
        crc_generate();
        crc64_generate();
        Some(Self {
            _handle: handle as usize,
            construct,
            is_finished,
            free,
            code,
        })
    }
}

#[cfg(target_os = "android")]
pub(crate) fn force_system_dlopen(filename: &CStr) -> *mut c_void {
    let api_level = android_api_level();
    if api_level < 24 {
        return std::ptr::null_mut();
    }

    // Match xDL's default, ART, SP-HAL, and VNDK namespace callers. A linker
    // namespace uses the caller PC to decide which search paths are visible.
    let callers = namespace_caller_addresses();
    if callers.is_empty() {
        return std::ptr::null_mut();
    }

    if api_level >= 28 {
        // Android P and newer expose the namespace-aware three-argument
        // __loader_dlopen entry through the dynamic linker API.
        let symbol = linker_symbol(c"__loader_dlopen").unwrap_or_else(|| unsafe {
            libc::dlsym(std::ptr::null_mut(), c"__loader_dlopen".as_ptr())
        });
        if symbol.is_null() {
            return std::ptr::null_mut();
        }
        type LoaderDlopenFn =
            unsafe extern "C" fn(*const c_char, c_int, *const c_void) -> *mut c_void;
        let loader_dlopen: LoaderDlopenFn = unsafe { std::mem::transmute(symbol) };
        for caller in callers.iter().copied() {
            let handle = unsafe {
                loader_dlopen(filename.as_ptr(), libc::RTLD_NOW, caller as *const c_void)
            };
            if !handle.is_null() {
                return handle;
            }
        }
        return std::ptr::null_mut();
    }

    if api_level >= 26 {
        // Android O/O MR1 use the three-argument __dlopen entry point.
        let symbol = linker_symbol(c"__dl__Z8__dlopenPKciPKv").unwrap_or_else(|| unsafe {
            libc::dlsym(std::ptr::null_mut(), c"__dl__Z8__dlopenPKciPKv".as_ptr())
        });
        if symbol.is_null() {
            return std::ptr::null_mut();
        }
        type DlopenOFn = unsafe extern "C" fn(*const c_char, c_int, *const c_void) -> *mut c_void;
        let dlopen_o: DlopenOFn = unsafe { std::mem::transmute(symbol) };
        for caller in callers.iter().copied() {
            let handle =
                unsafe { dlopen_o(filename.as_ptr(), libc::RTLD_NOW, caller as *const c_void) };
            if !handle.is_null() {
                return handle;
            }
        }
        return std::ptr::null_mut();
    }

    // Android N/N MR1 use one of two four-argument linker entry points.  The
    // final argument is the caller address and the extension-info argument is
    // intentionally null, matching xDL's force-load path.
    type DlopenNFn =
        unsafe extern "C" fn(*const c_char, c_int, *const c_void, *const c_void) -> *mut c_void;
    for name in [
        c"__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv",
        c"__dl__Z9do_dlopenPKciPK17android_dlextinfoPv",
    ] {
        let symbol = linker_symbol(name)
            .unwrap_or_else(|| unsafe { libc::dlsym(std::ptr::null_mut(), name.as_ptr()) });
        if symbol.is_null() {
            continue;
        }
        let dlopen_n: DlopenNFn = unsafe { std::mem::transmute(symbol) };
        for caller in callers.iter().copied() {
            let handle = unsafe {
                dlopen_n(
                    filename.as_ptr(),
                    libc::RTLD_NOW,
                    std::ptr::null(),
                    caller as *const c_void,
                )
            };
            if !handle.is_null() {
                return handle;
            }
        }
    }
    std::ptr::null_mut()
}

#[cfg(target_os = "android")]
fn namespace_caller_addresses() -> Vec<usize> {
    let mut selected = [(usize::MAX, 0usize); 4];
    let _ = crate::xdl::xdl_iterate_phdr(crate::xdl::XDL_DEFAULT, |module| {
        let Some(address) = module
            .program_headers()
            .iter()
            .find(|header| header.p_type == 1)
            .and_then(|header| usize::try_from(header.p_vaddr).ok())
            .and_then(|offset| module.load_bias().checked_add(offset))
        else {
            return 0;
        };
        for (namespace, rank) in namespace_matches(module.pathname().to_bytes()) {
            if rank < selected[namespace].0 {
                selected[namespace] = (rank, address);
            }
        }
        0
    });
    selected
        .into_iter()
        .filter_map(|(_, address)| (address != 0).then_some(address))
        .collect()
}

#[cfg(any(target_os = "android", test))]
fn namespace_matches(pathname: &[u8]) -> Vec<(usize, usize)> {
    let library_dir = if cfg!(target_pointer_width = "64") {
        b"lib64".as_slice()
    } else {
        b"lib".as_slice()
    };
    let mut matches = Vec::new();
    if pathname == b"libc.so" || pathname.ends_with(b"/libc.so") {
        matches.push((0, 0));
    }
    if pathname == b"libart.so" || pathname.ends_with(b"/libart.so") {
        matches.push((1, 0));
    }

    let vendor_egl = [b"/vendor/".as_slice(), library_dir, b"/egl/"].concat();
    let vendor_hw = [b"/vendor/".as_slice(), library_dir, b"/hw/"].concat();
    let vendor = [b"/vendor/".as_slice(), library_dir, b"/"].concat();
    let odm = [b"/odm/".as_slice(), library_dir, b"/"].concat();
    let sphal_rank = if pathname.starts_with(&vendor_egl) {
        Some(0)
    } else if pathname.starts_with(&vendor_hw) {
        Some(1)
    } else if pathname.starts_with(&vendor) {
        Some(2)
    } else if pathname.starts_with(&odm) {
        Some(3)
    } else {
        None
    };
    if let Some(rank) = sphal_rank {
        matches.push((2, rank));
    }

    let vendor_vndk = [b"/vendor/".as_slice(), library_dir, b"/vndk-sp/"].concat();
    let odm_vndk = [b"/odm/".as_slice(), library_dir, b"/vndk-sp/"].concat();
    let vndk_rank = if pathname.starts_with(b"/apex/com.android.vndk.v") {
        Some(0)
    } else if pathname.starts_with(&vendor_vndk) {
        Some(1)
    } else if pathname.starts_with(&odm_vndk) {
        Some(2)
    } else {
        None
    };
    if let Some(rank) = vndk_rank {
        matches.push((3, rank));
    }
    matches
}

/// Resolve a private linker entry from the on-disk linker image. Android O
/// keeps the `__dl_*` symbols out of `.dynsym`; the original xDL therefore
/// falls back to its `.symtab` (`xdl_dsym`) lookup. This is the Rust equivalent
/// used only when the public process lookup cannot see the private symbol.
#[cfg(target_os = "android")]
fn linker_symbol(name: &CStr) -> Option<*mut c_void> {
    let module_name = if cfg!(target_pointer_width = "64") {
        c"linker64"
    } else {
        c"linker"
    };
    let module = crate::xdl::open_loaded(module_name).ok()?;
    // Android O still ships the linker in /system/bin, while newer releases
    // may expose the same image from the runtime APEX.  The loaded module's
    // load bias is identical for either path, so try all known locations and
    // use the first image containing the requested private symbol.
    let paths: &[&str] = if cfg!(target_pointer_width = "64") {
        &[
            "/system/bin/linker64",
            "/apex/com.android.runtime/bin/linker64",
        ]
    } else {
        &["/system/bin/linker", "/apex/com.android.runtime/bin/linker"]
    };
    for path in paths {
        let Ok(image) = std::fs::read(path) else {
            continue;
        };
        let Some(value) = find_file_symbol(&image, name.to_bytes()) else {
            continue;
        };
        if let Some(address) = linker_runtime_address(module, value) {
            return Some(address as *mut c_void);
        }
    }
    None
}

#[cfg(target_os = "android")]
fn linker_runtime_address(module: crate::xdl::LoadedElf, value: usize) -> Option<usize> {
    // ET_DYN symbol values are relative to the load bias, whereas a few
    // vendor linkers emit absolute values.  Accept either form only when it
    // points into a PT_LOAD segment of the mapped linker image.
    let headers =
        unsafe { std::slice::from_raw_parts(module.program_headers, module.program_header_count) };
    let in_load = |address: usize| {
        headers
            .iter()
            .filter(|header| header.p_type == 1)
            .any(|header| {
                let Ok(start_offset) = usize::try_from(header.p_vaddr) else {
                    return false;
                };
                let Ok(length) = usize::try_from(header.p_memsz) else {
                    return false;
                };
                let Some(start) = module.base.checked_add(start_offset) else {
                    return false;
                };
                let Some(end) = start.checked_add(length) else {
                    return false;
                };
                address >= start && address < end
            })
    };
    if in_load(value) {
        Some(value)
    } else {
        module
            .base
            .checked_add(value)
            .filter(|address| in_load(*address))
    }
}

#[cfg(any(target_os = "android", test))]
fn find_file_symbol(image: &[u8], wanted: &[u8]) -> Option<usize> {
    if image.len() < 52 || image.get(..4) != Some(b"\x7fELF") || image.get(5) != Some(&1) {
        return None;
    }
    match image[4] {
        1 => find_file_symbol32(image, wanted),
        2 => find_file_symbol64(image, wanted),
        _ => None,
    }
}

#[cfg(any(target_os = "android", test))]
fn find_file_symbol64(image: &[u8], wanted: &[u8]) -> Option<usize> {
    let section_offset = usize::try_from(read_u64(image, 40)?).ok()?;
    let section_size = usize::from(read_u16(image, 58)?);
    let section_count = usize::from(read_u16(image, 60)?);
    if section_size < 64 || section_count == 0 {
        return None;
    }
    let mut best: Option<(u8, usize)> = None;
    for section_index in 0..section_count {
        let section = table_entry(image, section_offset, section_size, section_index)?;
        if read_u32(section, 4)? != 2 {
            continue;
        }
        let strings_index = usize::try_from(read_u32(section, 40)?).ok()?;
        let strings_section = table_entry(image, section_offset, section_size, strings_index)?;
        let strings = section_data64(image, strings_section)?;
        let symbols = section_data64(image, section)?;
        let entry_size = usize::try_from(read_u64(section, 56)?).ok()?;
        if entry_size < 24 {
            continue;
        }
        for symbol in symbols.chunks_exact(entry_size) {
            // Ignore undefined entries and zero-valued symbols.  A stripped
            // linker can contain duplicate local aliases; prefer GLOBAL over
            // WEAK/LOCAL so we do not accidentally call an unrelated alias.
            if read_u16(symbol, 6)? == 0 {
                continue;
            }
            let name_offset = usize::try_from(read_u32(symbol, 0)?).ok()?;
            let actual = strings
                .get(name_offset..)?
                .split(|byte| *byte == 0)
                .next()?;
            if actual == wanted {
                let value = usize::try_from(read_u64(symbol, 8)?).ok()?;
                if value == 0 {
                    continue;
                }
                let binding = symbol[4] >> 4;
                let rank = match binding {
                    1 => 3, // STB_GLOBAL
                    2 => 2, // STB_WEAK
                    0 => 1, // STB_LOCAL
                    _ => 0,
                };
                if rank == 0 {
                    continue;
                }
                if best.is_none_or(|(old_rank, _)| rank > old_rank) {
                    best = Some((rank, value));
                }
            }
        }
    }
    best.map(|(_, value)| value)
}

#[cfg(any(target_os = "android", test))]
fn find_file_symbol32(image: &[u8], wanted: &[u8]) -> Option<usize> {
    let section_offset = usize::try_from(read_u32(image, 32)?).ok()?;
    let section_size = usize::from(read_u16(image, 46)?);
    let section_count = usize::from(read_u16(image, 48)?);
    if section_size < 40 || section_count == 0 {
        return None;
    }
    let mut best: Option<(u8, usize)> = None;
    for section_index in 0..section_count {
        let section = table_entry(image, section_offset, section_size, section_index)?;
        if read_u32(section, 4)? != 2 {
            continue;
        }
        let strings_index = usize::try_from(read_u32(section, 24)?).ok()?;
        let strings_section = table_entry(image, section_offset, section_size, strings_index)?;
        let strings = section_data32(image, strings_section)?;
        let symbols = section_data32(image, section)?;
        let entry_size = usize::try_from(read_u32(section, 36)?).ok()?;
        if entry_size < 16 {
            continue;
        }
        for symbol in symbols.chunks_exact(entry_size) {
            if read_u16(symbol, 14)? == 0 {
                continue;
            }
            let name_offset = usize::try_from(read_u32(symbol, 0)?).ok()?;
            let actual = strings
                .get(name_offset..)?
                .split(|byte| *byte == 0)
                .next()?;
            if actual == wanted {
                let value = usize::try_from(read_u32(symbol, 4)?).ok()?;
                if value == 0 {
                    continue;
                }
                let binding = symbol[12] >> 4;
                let rank = match binding {
                    1 => 3,
                    2 => 2,
                    0 => 1,
                    _ => 0,
                };
                if rank == 0 {
                    continue;
                }
                if best.is_none_or(|(old_rank, _)| rank > old_rank) {
                    best = Some((rank, value));
                }
            }
        }
    }
    best.map(|(_, value)| value)
}

#[cfg(any(target_os = "android", test))]
fn table_entry(
    image: &[u8],
    table_offset: usize,
    entry_size: usize,
    index: usize,
) -> Option<&[u8]> {
    let offset = table_offset.checked_add(index.checked_mul(entry_size)?)?;
    image.get(offset..offset.checked_add(entry_size)?)
}

#[cfg(any(target_os = "android", test))]
fn section_data64<'a>(image: &'a [u8], section: &[u8]) -> Option<&'a [u8]> {
    let offset = usize::try_from(read_u64(section, 24)?).ok()?;
    let size = usize::try_from(read_u64(section, 32)?).ok()?;
    image.get(offset..offset.checked_add(size)?)
}

#[cfg(any(target_os = "android", test))]
fn section_data32<'a>(image: &'a [u8], section: &[u8]) -> Option<&'a [u8]> {
    let offset = usize::try_from(read_u32(section, 16)?).ok()?;
    let size = usize::try_from(read_u32(section, 20)?).ok()?;
    image.get(offset..offset.checked_add(size)?)
}

#[cfg(any(target_os = "android", test))]
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

#[cfg(any(target_os = "android", test))]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(any(target_os = "android", test))]
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(target_os = "android")]
unsafe fn resolve_system_symbol(handle: *mut c_void, path: &CStr, name: &CStr) -> *mut c_void {
    if let Ok(loaded) = crate::xdl::open_loaded(path) {
        let headers = unsafe {
            std::slice::from_raw_parts(loaded.program_headers, loaded.program_header_count)
        };
        if let Ok(symbol) = unsafe { crate::xdl::resolve_dynamic_symbol(loaded.base, headers, name) } {
            return symbol.address as *mut c_void;
        }
    }
    if handle.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { libc::dlsym(handle, name.as_ptr()) }
    }
}

#[cfg(target_os = "android")]
pub(crate) fn android_api_level() -> i32 {
    let mut value = [0u8; 128];
    let length = unsafe {
        libc::__system_property_get(c"ro.build.version.sdk".as_ptr(), value.as_mut_ptr().cast())
    };
    if length <= 0 {
        return build_prop_api_level();
    }
    let bytes = &value[..length as usize];
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .filter(|level| *level > 0)
        .unwrap_or_else(build_prop_api_level)
}

#[cfg(target_os = "android")]
fn build_prop_api_level() -> i32 {
    std::fs::read_to_string("/system/build.prop")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("ro.build.version.sdk=")
                    .and_then(|value| value.trim().parse::<i32>().ok())
            })
        })
        .filter(|level| *level > 0)
        .unwrap_or(16)
}

#[cfg(test)]
mod tests {
    use super::{find_file_symbol, namespace_matches, xdl_lzma_decompress, LzmaError};

    #[test]
    fn empty_input_is_rejected_before_platform_lookup() {
        assert_eq!(xdl_lzma_decompress(&[]), Err(LzmaError::EmptyInput));
    }

    #[test]
    fn force_load_classifies_all_xdl_linker_namespaces() {
        assert_eq!(
            namespace_matches(b"/apex/com.android.runtime/lib64/bionic/libc.so"),
            vec![(0, 0)]
        );
        assert_eq!(
            namespace_matches(b"/apex/com.android.art/lib64/libart.so"),
            vec![(1, 0)]
        );
        assert_eq!(
            namespace_matches(b"/vendor/lib64/egl/libGLES.so"),
            vec![(2, 0)]
        );
        assert_eq!(
            namespace_matches(b"/vendor/lib64/vndk-sp/libbase.so"),
            vec![(2, 2), (3, 1)]
        );
        assert_eq!(
            namespace_matches(b"/apex/com.android.vndk.v35/lib64/libbase.so"),
            vec![(3, 0)]
        );
    }

    #[test]
    fn file_symbol_lookup_prefers_defined_global_alias() {
        // Minimal ELF64 section table containing a local and a global symbol
        // with the same name. This exercises the parser without requiring an
        // Android linker image on the host running unit tests.
        // Keep section metadata, symbol entries, and strings in disjoint
        // file ranges; the parser intentionally rejects overlapping/truncated
        // sections through checked slices.
        let mut image = vec![0u8; 352];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2; // ELFCLASS64
        image[5] = 1; // little endian
        image[40..48].copy_from_slice(&(64u64).to_le_bytes()); // e_shoff
        image[58..60].copy_from_slice(&(64u16).to_le_bytes()); // e_shentsize
        image[60..62].copy_from_slice(&(3u16).to_le_bytes()); // e_shnum

        // .symtab (section 1), linked to .strtab (section 2).
        let sh = 64 + 64;
        image[sh + 4..sh + 8].copy_from_slice(&(2u32).to_le_bytes());
        image[sh + 24..sh + 32].copy_from_slice(&(256u64).to_le_bytes());
        image[sh + 32..sh + 40].copy_from_slice(&(72u64).to_le_bytes());
        image[sh + 40..sh + 44].copy_from_slice(&(2u32).to_le_bytes());
        image[sh + 56..sh + 64].copy_from_slice(&(24u64).to_le_bytes());

        // .strtab: "" + "target".
        let strtab = 328;
        image[strtab..strtab + 7].copy_from_slice(b"\0target");
        let sh2 = 64 + 64 * 2;
        image[sh2 + 4..sh2 + 8].copy_from_slice(&(3u32).to_le_bytes());
        image[sh2 + 24..sh2 + 32].copy_from_slice(&(strtab as u64).to_le_bytes());
        image[sh2 + 32..sh2 + 40].copy_from_slice(&(7u64).to_le_bytes());

        // Local alias at 0x10, global definition at 0x20.
        let sym_local = 256 + 24;
        image[sym_local..sym_local + 4].copy_from_slice(&(1u32).to_le_bytes());
        image[sym_local + 4] = 0x00;
        image[sym_local + 6..sym_local + 8].copy_from_slice(&(1u16).to_le_bytes());
        image[sym_local + 8..sym_local + 16].copy_from_slice(&(0x10u64).to_le_bytes());
        let sym_global = sym_local + 24;
        image[sym_global..sym_global + 4].copy_from_slice(&(1u32).to_le_bytes());
        image[sym_global + 4] = 0x10;
        image[sym_global + 6..sym_global + 8].copy_from_slice(&(1u16).to_le_bytes());
        image[sym_global + 8..sym_global + 16].copy_from_slice(&(0x20u64).to_le_bytes());

        assert_eq!(find_file_symbol(&image, b"target"), Some(0x20));
    }
}
