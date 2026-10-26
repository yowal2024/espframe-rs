use std::collections::HashMap;
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
use std::ffi::CStr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::soloader::deps::basename;
use crate::soloader::elf::{ElfImage, ResolvedSymbol};

const MAX_CUSTOM_LIBS: usize = 64;
#[cfg(any(target_os = "linux", target_os = "android"))]
// Keep closed tokens alive so an old pointer can never be recycled for a
// different image.  The cap bounds memory retained by repeated unload/reload
// cycles; once exhausted, a matching custom image fails closed with NULL.
const MAX_CUSTOM_HANDLE_TOKENS: usize = 1024;

const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_PTR: u8 = 0x00;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SDATA2: u8 = 0x0a;
const DW_EH_PE_SDATA4: u8 = 0x0b;
const DW_EH_PE_SDATA8: u8 = 0x0c;
const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_DATAREL: u8 = 0x30;
const DW_EH_PE_INDIRECT: u8 = 0x80;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BacktraceHandle(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBacktraceSymbol {
    pub handle: BacktraceHandle,
    pub file_name: String,
    pub file_base: usize,
    pub symbol_name: Option<String>,
    pub symbol_address: Option<usize>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EhFrameLocation {
    pub address: usize,
    pub size: usize,
}

#[derive(Debug, Default)]
struct BacktraceState {
    slots: Vec<Option<Box<RegisteredLibrary>>>,
    next_generation: u64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    custom_handles: HashMap<usize, CustomHandleRecord>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    custom_handle_storage: HashMap<usize, Box<CustomHandleToken>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    custom_handle_by_image: HashMap<(usize, u64), usize>,
}

#[derive(Debug, Clone)]
struct RegisteredLibrary {
    image: ElfImage,
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    file_name: CString,
    file_base: usize,
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    tls_modid: usize,
    eh_frame_registered: Option<usize>,
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    symbol_name_cache: HashMap<usize, CString>,
    generation: u64,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Copy, Clone)]
struct CustomHandleRecord {
    slot: usize,
    generation: u64,
    /// Number of dlopen calls outstanding for this image token.
    refs: u32,
    active: bool,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[repr(C)]
#[derive(Debug)]
struct CustomHandleToken {
    _private: u8,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
struct IteratePhdrEntry {
    file_name: CString,
    file_base: usize,
    phdrs: Vec<NativeProgramHeader>,
    tls_modid: usize,
}

impl RegisteredLibrary {
    fn new(image: &ElfImage, tls_modid: Option<usize>) -> Option<Self> {
        let file_name = CString::new(image.name()).ok()?;
        Some(Self {
            image: image.clone(),
            file_name,
            file_base: image.base().wrapping_sub(image.bias()),
            tls_modid: tls_modid.unwrap_or(0),
            eh_frame_registered: None,
            symbol_name_cache: HashMap::new(),
            generation: 0,
        })
    }

    fn contains_address(&self, addr: usize) -> bool {
        self.image.program_headers().iter().any(|phdr| {
            if phdr.p_type != goblin::elf::program_header::PT_LOAD {
                return false;
            }

            let start = self.file_base.wrapping_add(phdr.p_vaddr as usize);
            let end = start.wrapping_add(phdr.p_memsz as usize);
            addr >= start && addr < end
        })
    }

    fn resolve_address(&self, addr: usize) -> Option<ResolvedSymbol> {
        self.image.get_symbol_for_address(addr)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn exported_symbol_address(&self, name: &str) -> Option<usize> {
        self.image.exported_symbol_address(name)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn symbol_address(&self, name: &str) -> Option<usize> {
        self.image.symbol_address(name)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn cached_symbol_name(&mut self, address: usize, name: &str) -> Option<*const libc::c_char> {
        if name.is_empty() {
            return None;
        }

        let entry = self
            .symbol_name_cache
            .entry(address)
            .or_insert_with(|| CString::new(name).unwrap_or_default());
        Some(entry.as_ptr())
    }
}

#[cfg(all(unix, target_pointer_width = "64"))]
type NativeProgramHeader = libc::Elf64_Phdr;

#[cfg(all(unix, target_pointer_width = "32"))]
type NativeProgramHeader = libc::Elf32_Phdr;

#[cfg(unix)]
fn to_native_program_headers(phdrs: &[goblin::elf::ProgramHeader]) -> Vec<NativeProgramHeader> {
    phdrs.iter().map(to_native_program_header).collect()
}

#[cfg(all(unix, target_pointer_width = "64"))]
fn to_native_program_header(phdr: &goblin::elf::ProgramHeader) -> NativeProgramHeader {
    NativeProgramHeader {
        p_type: phdr.p_type as _,
        p_flags: phdr.p_flags as _,
        p_offset: phdr.p_offset as _,
        p_vaddr: phdr.p_vaddr as _,
        p_paddr: phdr.p_paddr as _,
        p_filesz: phdr.p_filesz as _,
        p_memsz: phdr.p_memsz as _,
        p_align: phdr.p_align as _,
    }
}

#[cfg(all(unix, target_pointer_width = "32"))]
fn to_native_program_header(phdr: &goblin::elf::ProgramHeader) -> NativeProgramHeader {
    NativeProgramHeader {
        p_type: phdr.p_type as _,
        p_offset: phdr.p_offset as _,
        p_vaddr: phdr.p_vaddr as _,
        p_paddr: phdr.p_paddr as _,
        p_filesz: phdr.p_filesz as _,
        p_memsz: phdr.p_memsz as _,
        p_flags: phdr.p_flags as _,
        p_align: phdr.p_align as _,
    }
}

impl BacktraceState {
    fn register_image(
        &mut self,
        image: &ElfImage,
        tls_modid: Option<usize>,
    ) -> Option<BacktraceHandle> {
        let slot = self.slots.iter().position(Option::is_none)?;
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let mut entry = RegisteredLibrary::new(image, tls_modid)?;
        entry.generation = generation;
        self.slots[slot] = Some(Box::new(entry));
        Some(BacktraceHandle(slot))
    }

    fn unregister_image(&mut self, handle: BacktraceHandle) -> bool {
        let Some(slot) = self.slots.get_mut(handle.0) else {
            return false;
        };
        let Some(mut entry) = slot.take() else {
            return false;
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let generation = entry.generation;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.invalidate_custom_handles(handle.0, generation);
        unsafe {
            unregister_frame_for_entry(&mut entry);
        }
        true
    }

    fn with_entry_mut<T>(
        &mut self,
        handle: BacktraceHandle,
        f: impl FnOnce(&mut RegisteredLibrary) -> T,
    ) -> Option<T> {
        self.slots.get_mut(handle.0)?.as_deref_mut().map(f)
    }

    fn entry_by_address(&self, addr: usize) -> Option<(usize, &RegisteredLibrary)> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let entry = slot.as_deref()?;
            entry.contains_address(addr).then_some((index, entry))
        })
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn entry_by_address_mut(&mut self, addr: usize) -> Option<(usize, &mut RegisteredLibrary)> {
        self.slots.iter_mut().enumerate().find_map(|(index, slot)| {
            let entry = slot.as_deref_mut()?;
            entry.contains_address(addr).then_some((index, entry))
        })
    }

    fn deinit(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        for record in self.custom_handles.values_mut() {
            record.active = false;
            record.refs = 0;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.custom_handle_by_image.clear();
        let mut slots = std::mem::take(&mut self.slots);
        for slot in &mut slots {
            if let Some(mut entry) = slot.take() {
                unsafe {
                    unregister_frame_for_entry(&mut entry);
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn invalidate_custom_handles(&mut self, slot: usize, generation: u64) {
        for record in self.custom_handles.values_mut() {
            if record.slot == slot && record.generation == generation {
                record.active = false;
                record.refs = 0;
            }
        }
        self.custom_handle_by_image.remove(&(slot, generation));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn custom_handle_for_entry(&mut self, slot: usize, generation: u64) -> *mut libc::c_void {
        let key = (slot, generation);
        if let Some(ptr) = self.custom_handle_by_image.get(&key).copied() {
            if let Some(record) = self.custom_handles.get_mut(&ptr) {
                if record.active {
                    record.refs = record.refs.saturating_add(1);
                    return ptr as *mut libc::c_void;
                }
            }
            self.custom_handle_by_image.remove(&key);
        }
        if self.custom_handle_storage.len() >= MAX_CUSTOM_HANDLE_TOKENS {
            return std::ptr::null_mut();
        }
        let token = Box::new(CustomHandleToken { _private: 0 });
        let ptr = (&*token as *const CustomHandleToken) as usize;
        self.custom_handle_storage.insert(ptr, token);
        self.custom_handles.insert(
            ptr,
            CustomHandleRecord {
                slot,
                generation,
                refs: 1,
                active: true,
            },
        );
        self.custom_handle_by_image.insert(key, ptr);
        ptr as *mut libc::c_void
    }
}

#[derive(Debug)]
pub struct BacktraceRegistry {
    state: Mutex<BacktraceState>,
}

impl Default for BacktraceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BacktraceRegistry {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BacktraceState {
                slots: vec![None; MAX_CUSTOM_LIBS],
                next_generation: 1,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                custom_handles: HashMap::new(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                custom_handle_storage: HashMap::new(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                custom_handle_by_image: HashMap::new(),
            }),
        }
    }

    pub fn register_image(
        &self,
        image: &ElfImage,
        tls_modid: Option<usize>,
    ) -> Option<BacktraceHandle> {
        lock_state(&self.state).register_image(image, tls_modid)
    }

    pub fn unregister_image(&self, handle: BacktraceHandle) -> bool {
        lock_state(&self.state).unregister_image(handle)
    }

    pub fn register_eh_frame_for_library(&self, handle: BacktraceHandle) -> bool {
        let mut state = lock_state(&self.state);
        state
            .with_entry_mut(handle, |entry| unsafe { register_frame_for_entry(entry) })
            .unwrap_or(false)
    }

    pub fn unregister_eh_frame_for_library(&self, handle: BacktraceHandle) -> bool {
        let mut state = lock_state(&self.state);
        state
            .with_entry_mut(handle, |entry| unsafe { unregister_frame_for_entry(entry) })
            .unwrap_or(false)
    }

    pub fn resolve_address(&self, addr: usize) -> Option<ResolvedBacktraceSymbol> {
        let state = lock_state(&self.state);
        let (slot, entry) = state.entry_by_address(addr)?;
        let resolved = entry.resolve_address(addr);
        Some(ResolvedBacktraceSymbol {
            handle: BacktraceHandle(slot),
            file_name: entry.image.name().to_owned(),
            file_base: entry.file_base,
            symbol_name: resolved.as_ref().map(|sym| sym.name.clone()),
            symbol_address: resolved.as_ref().map(|sym| sym.address),
        })
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn dlopen_handle(&self, filename: Option<&CStr>, flags: libc::c_int) -> *mut libc::c_void {
        let Some(filename) = filename else {
            return unsafe { libc::dlopen(std::ptr::null(), flags) };
        };
        let needle = filename.to_string_lossy();
        let mut state = lock_state(&self.state);
        if let Some((index, generation)) =
            state.slots.iter().enumerate().find_map(|(index, slot)| {
                let entry = slot.as_deref()?;
                image_name_matches(entry.image.name(), needle.as_ref())
                    .then_some((index, entry.generation))
            })
        {
            return state.custom_handle_for_entry(index, generation);
        }
        drop(state);
        unsafe { libc::dlopen(filename.as_ptr(), flags) }
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Resolve a symbol from a native loader handle or a registered custom image.
    ///
    /// # Safety
    /// `handle` must be a valid live native loader handle, unless it is a handle
    /// previously returned by this registry. The handle must not be closed
    /// concurrently with this call.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn dlsym_handle(
        &self,
        handle: *mut libc::c_void,
        symbol: Option<&CStr>,
    ) -> *mut libc::c_void {
        let Some(symbol) = symbol else {
            return std::ptr::null_mut();
        };

        let state = lock_state(&self.state);
        if let Some(record) = state.custom_handles.get(&(handle as usize)).copied() {
            let entry = state
                .slots
                .get(record.slot)
                .and_then(Option::as_deref)
                .filter(|entry| record.active && entry.generation == record.generation);
            let Some(entry) = entry else {
                return std::ptr::null_mut();
            };
            let name = symbol.to_string_lossy();
            let address = entry
                .exported_symbol_address(name.as_ref())
                .or_else(|| entry.symbol_address(name.as_ref()));
            return address
                .map(|addr| addr as *mut libc::c_void)
                .unwrap_or(std::ptr::null_mut());
        }
        drop(state);
        unsafe { libc::dlsym(handle, symbol.as_ptr()) }
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Close a native loader handle or release one returned by this registry.
    ///
    /// # Safety
    /// `handle` must be a valid live native loader handle, unless it is a handle
    /// previously returned by this registry. It must not be closed concurrently.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn dlclose_handle(&self, handle: *mut libc::c_void) -> libc::c_int {
        let mut state = lock_state(&self.state);
        if let Some(record) = state.custom_handles.get_mut(&(handle as usize)) {
            if !record.active {
                return -1;
            }
            let key = (record.slot, record.generation);
            if record.refs > 1 {
                record.refs -= 1;
            } else {
                record.active = false;
                record.refs = 0;
                state.custom_handle_by_image.remove(&key);
            }
            return 0;
        }
        drop(state);
        unsafe { libc::dlclose(handle) }
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Resolve the native image and symbol containing an address.
    ///
    /// # Safety
    /// `addr` must be a valid address suitable for the platform `dladdr` call
    /// and `info` must point to writable storage for a complete `Dl_info`.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn custom_dladdr(
        &self,
        addr: *const libc::c_void,
        info: *mut libc::Dl_info,
    ) -> libc::c_int {
        let Some(info) = (unsafe { info.as_mut() }) else {
            return 0;
        };

        if unsafe { libc::dladdr(addr, info) } != 0 {
            return 1;
        }

        let addr = addr as usize;
        let mut state = lock_state(&self.state);
        let Some((_, entry)) = state.entry_by_address_mut(addr) else {
            return 0;
        };

        let resolved = entry.resolve_address(addr);
        info.dli_fname = entry.file_name.as_ptr();
        info.dli_fbase = entry.file_base as *mut libc::c_void;

        if let Some(resolved) = resolved {
            let ptr = entry
                .cached_symbol_name(resolved.address, &resolved.name)
                .unwrap_or(std::ptr::null());
            info.dli_sname = ptr;
            info.dli_saddr = resolved.address as *mut libc::c_void;
            return 1;
        }

        info.dli_sname = std::ptr::null();
        info.dli_saddr = std::ptr::null_mut();
        1
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Iterate native and registered custom loader images.
    ///
    /// # Safety
    /// `callback` must remain valid for the duration of the call and obey the
    /// platform `dl_iterate_phdr` callback contract. `data` must be valid for
    /// each callback invocation.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn custom_dl_iterate_phdr(
        &self,
        callback: unsafe extern "C" fn(
            *mut libc::dl_phdr_info,
            libc::size_t,
            *mut libc::c_void,
        ) -> libc::c_int,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        unsafe {
            let host = libc::dl_iterate_phdr(Some(callback), data);
            if host != 0 {
                return host;
            }
        }

        let entries = {
            let state = lock_state(&self.state);
            state
                .slots
                .iter()
                .filter_map(|slot| slot.as_deref())
                .map(|entry| IteratePhdrEntry {
                    file_name: entry.file_name.clone(),
                    file_base: entry.file_base,
                    phdrs: to_native_program_headers(entry.image.program_headers()),
                    tls_modid: entry.tls_modid,
                })
                .collect::<Vec<_>>()
        };
        for entry in &entries {
            let mut info = libc::dl_phdr_info {
                dlpi_addr: entry.file_base as _,
                dlpi_name: entry.file_name.as_ptr(),
                dlpi_phdr: entry.phdrs.as_ptr(),
                dlpi_phnum: entry.phdrs.len() as _,
                dlpi_adds: 1,
                dlpi_subs: 0,
                dlpi_tls_modid: entry.tls_modid,
                dlpi_tls_data: std::ptr::null_mut(),
            };

            let result =
                unsafe { callback(&mut info, std::mem::size_of::<libc::dl_phdr_info>(), data) };
            if result != 0 {
                return result;
            }
        }

        0
    }

    pub fn deinit(&self) {
        lock_state(&self.state).deinit();
    }
}

pub fn global_backtrace_registry() -> &'static BacktraceRegistry {
    GLOBAL_BACKTRACE_REGISTRY.get_or_init(BacktraceRegistry::new)
}

static GLOBAL_BACKTRACE_REGISTRY: OnceLock<BacktraceRegistry> = OnceLock::new();

/// Locate the image's `.eh_frame` data using its parsed ELF metadata.
///
/// # Safety
/// The image must have been parsed from valid ELF bytes and its cached
/// addresses must refer to the image's mapped, readable memory.
pub unsafe fn locate_eh_frame(image: &ElfImage) -> Option<EhFrameLocation> {
    if let Some(region) = image.eh_frame() {
        return Some(EhFrameLocation {
            address: region.address,
            size: region.size,
        });
    }

    let hdr = image.eh_frame_hdr()?;
    let hdr_vaddr = hdr
        .address
        .wrapping_add(image.bias())
        .wrapping_sub(image.base());
    let range = image.file_range_for_vaddr(hdr_vaddr, hdr.size)?;
    let bytes = &image.bytes()[range];
    decode_eh_frame_hdr(
        bytes,
        hdr.address,
        image.word_size(),
        image.is_little_endian(),
    )
    .map(|address| EhFrameLocation { address, size: 0 })
}

pub fn register_backtrace_library(
    image: &ElfImage,
    tls_modid: Option<usize>,
) -> Option<BacktraceHandle> {
    global_backtrace_registry().register_image(image, tls_modid)
}

pub fn unregister_backtrace_library(handle: BacktraceHandle) -> bool {
    global_backtrace_registry().unregister_image(handle)
}

pub fn register_backtrace_eh_frame(handle: BacktraceHandle) -> bool {
    global_backtrace_registry().register_eh_frame_for_library(handle)
}

pub fn unregister_backtrace_eh_frame(handle: BacktraceHandle) -> bool {
    global_backtrace_registry().unregister_eh_frame_for_library(handle)
}

pub fn resolve_backtrace_address(addr: usize) -> Option<ResolvedBacktraceSymbol> {
    global_backtrace_registry().resolve_address(addr)
}

pub fn deinit_backtrace_registry() {
    global_backtrace_registry().deinit();
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
/// # Safety
/// `addr` must be a valid address for the platform loader, and `info` must
/// point to writable storage for a complete `Dl_info` value.
pub unsafe extern "C" fn custom_dladdr(
    addr: *const libc::c_void,
    info: *mut libc::Dl_info,
) -> libc::c_int {
    global_backtrace_registry().custom_dladdr(addr, info)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
/// # Safety
/// `callback` must obey the platform `dl_iterate_phdr` callback contract and
/// remain valid for the duration of this call. `data` must be valid whenever
/// the callback receives it.
pub unsafe extern "C" fn custom_dl_iterate_phdr(
    callback: unsafe extern "C" fn(
        *mut libc::dl_phdr_info,
        libc::size_t,
        *mut libc::c_void,
    ) -> libc::c_int,
    data: *mut libc::c_void,
) -> libc::c_int {
    global_backtrace_registry().custom_dl_iterate_phdr(callback, data)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
/// # Safety
/// `filename` is either null or a valid NUL-terminated string. `flags` must be
/// a valid platform `dlopen` flag combination.
pub unsafe extern "C" fn custom_dlopen(
    filename: *const libc::c_char,
    flags: libc::c_int,
) -> *mut libc::c_void {
    let filename = if filename.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(filename) })
    };
    global_backtrace_registry().dlopen_handle(filename, flags)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
/// # Safety
/// `symbol` is either null or a valid NUL-terminated string. `handle` must be
/// a valid native or registry-owned loader handle.
pub unsafe extern "C" fn custom_dlsym(
    handle: *mut libc::c_void,
    symbol: *const libc::c_char,
) -> *mut libc::c_void {
    let symbol = if symbol.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(symbol) })
    };
    global_backtrace_registry().dlsym_handle(handle, symbol)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
/// # Safety
/// `handle` must be a valid native or registry-owned loader handle that has
/// not already been closed.
pub unsafe extern "C" fn custom_dlclose(handle: *mut libc::c_void) -> libc::c_int {
    global_backtrace_registry().dlclose_handle(handle)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn image_name_matches(image_name: &str, name_or_path: &str) -> bool {
    image_name == name_or_path
        || basename(image_name) == basename(name_or_path)
        || image_name.contains(name_or_path)
        || name_or_path.contains(image_name)
}

fn lock_state(state: &Mutex<BacktraceState>) -> MutexGuard<'_, BacktraceState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn decode_eh_frame_hdr(
    bytes: &[u8],
    hdr_addr: usize,
    word_size: usize,
    little_endian: bool,
) -> Option<usize> {
    if bytes.len() < 4 {
        return None;
    }

    if bytes[0] != 1 {
        return None;
    }

    let eh_frame_ptr_enc = bytes[1];
    let mut cursor = 4usize;
    let base = hdr_addr.wrapping_add(cursor);
    let data_base = hdr_addr;
    decode_eh_value(
        eh_frame_ptr_enc,
        bytes,
        &mut cursor,
        base,
        data_base,
        word_size,
        little_endian,
    )
}

fn decode_eh_value(
    enc: u8,
    bytes: &[u8],
    cursor: &mut usize,
    base: usize,
    data_base: usize,
    word_size: usize,
    little_endian: bool,
) -> Option<usize> {
    if enc == DW_EH_PE_OMIT {
        return None;
    }

    let format = enc & 0x0f;
    let application = enc & 0x70;
    let indirect = enc & DW_EH_PE_INDIRECT != 0;

    let mut value = match format {
        DW_EH_PE_PTR => read_pointer(bytes, cursor, word_size, little_endian)?,
        DW_EH_PE_ULEB128 => read_uleb128(bytes, cursor)?,
        DW_EH_PE_UDATA2 => read_fixed(bytes, cursor, 2, little_endian)? as usize,
        DW_EH_PE_UDATA4 => read_fixed(bytes, cursor, 4, little_endian)? as usize,
        DW_EH_PE_UDATA8 => read_fixed(bytes, cursor, 8, little_endian)?,
        DW_EH_PE_SDATA2 => read_fixed(bytes, cursor, 2, little_endian)? as i16 as isize as usize,
        DW_EH_PE_SDATA4 => read_fixed(bytes, cursor, 4, little_endian)? as i32 as isize as usize,
        DW_EH_PE_SDATA8 => read_fixed(bytes, cursor, 8, little_endian)? as i64 as isize as usize,
        _ => return None,
    };

    value = match application {
        DW_EH_PE_ABSPTR => value,
        DW_EH_PE_PCREL => value.wrapping_add(base),
        DW_EH_PE_DATAREL => value.wrapping_add(data_base),
        _ => value,
    };

    if indirect {
        if value == 0 {
            return None;
        }
        value = unsafe { *(value as *const usize) };
    }

    Some(value)
}

fn read_pointer(
    bytes: &[u8],
    cursor: &mut usize,
    word_size: usize,
    little_endian: bool,
) -> Option<usize> {
    match word_size {
        4 => read_fixed(bytes, cursor, 4, little_endian),
        8 => read_fixed(bytes, cursor, 8, little_endian),
        _ => None,
    }
}

fn read_fixed(
    bytes: &[u8],
    cursor: &mut usize,
    width: usize,
    little_endian: bool,
) -> Option<usize> {
    let end = cursor.checked_add(width)?;
    let chunk = bytes.get(*cursor..end)?;
    *cursor = end;

    match width {
        2 => {
            let mut array = [0u8; 2];
            array.copy_from_slice(chunk);
            Some(if little_endian {
                u16::from_le_bytes(array) as usize
            } else {
                u16::from_be_bytes(array) as usize
            })
        }
        4 => {
            let mut array = [0u8; 4];
            array.copy_from_slice(chunk);
            Some(if little_endian {
                u32::from_le_bytes(array) as usize
            } else {
                u32::from_be_bytes(array) as usize
            })
        }
        8 => {
            let mut array = [0u8; 8];
            array.copy_from_slice(chunk);
            Some(if little_endian {
                u64::from_le_bytes(array) as usize
            } else {
                u64::from_be_bytes(array) as usize
            })
        }
        _ => None,
    }
}

fn read_uleb128(bytes: &[u8], cursor: &mut usize) -> Option<usize> {
    let mut value = 0usize;
    let mut shift = 0usize;

    while *cursor < bytes.len() {
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift = shift.saturating_add(7);
        if shift >= usize::BITS as usize {
            return None;
        }
    }

    None
}

unsafe fn register_frame_for_entry(entry: &mut RegisteredLibrary) -> bool {
    if entry.eh_frame_registered.is_some() {
        return true;
    }

    let Some(location) = (unsafe { locate_eh_frame(&entry.image) }) else {
        return false;
    };

    let Some(register_frame) = frame_hooks().0 else {
        return false;
    };

    unsafe {
        register_frame(location.address as *mut libc::c_void);
    }
    entry.eh_frame_registered = Some(location.address);
    true
}

unsafe fn unregister_frame_for_entry(entry: &mut RegisteredLibrary) -> bool {
    let Some(ptr) = entry.eh_frame_registered.take() else {
        return false;
    };

    let Some(deregister_frame) = frame_hooks().1 else {
        return true;
    };

    unsafe {
        deregister_frame(ptr as *mut libc::c_void);
    }
    true
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
type RegisterFrameFn = unsafe extern "C" fn(*mut libc::c_void);

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
type DeregisterFrameFn = unsafe extern "C" fn(*mut libc::c_void);

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn frame_hooks() -> (Option<RegisterFrameFn>, Option<DeregisterFrameFn>) {
    static HOOKS: OnceLock<(Option<RegisterFrameFn>, Option<DeregisterFrameFn>)> = OnceLock::new();
    *HOOKS.get_or_init(|| unsafe {
        let register_frame = lookup_frame_symbol("__register_frame");
        let deregister_frame = lookup_frame_symbol("__deregister_frame");
        (register_frame, deregister_frame)
    })
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
unsafe fn lookup_frame_symbol<T: Copy>(name: &str) -> Option<T> {
    let name = CString::new(name).ok()?;
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute_copy(&ptr) })
    }
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "android"))))]
fn frame_hooks() -> (
    Option<unsafe extern "C" fn(*mut libc::c_void)>,
    Option<unsafe extern "C" fn(*mut libc::c_void)>,
) {
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_round_trips_basic_symbol_resolution() {
        let bytes = synthetic_elf_for_backtrace(true);
        let image = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();
        let registry = BacktraceRegistry::new();

        let handle = registry.register_image(&image, Some(7)).unwrap();

        let resolved = registry.resolve_address(0x7000_0104).unwrap();
        assert_eq!(resolved.file_name, "sample.so");
        assert_eq!(resolved.file_base, 0x7000_0000);
        assert_eq!(resolved.symbol_name.as_deref(), Some("main_object"));
        assert_eq!(resolved.symbol_address, Some(0x7000_0100));

        assert!(registry.unregister_image(handle));
        assert!(registry.resolve_address(0x7000_0104).is_none());
    }

    #[test]
    fn locate_eh_frame_prefers_direct_section() {
        let bytes = synthetic_elf_for_backtrace(true);
        let image = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();

        let located = unsafe { locate_eh_frame(&image) }.unwrap();

        assert_eq!(located.address, 0x7000_0400);
        assert_eq!(located.size, 16);
    }

    #[test]
    fn locate_eh_frame_decodes_pcrel_eh_frame_header_fallback() {
        let bytes = synthetic_elf_for_backtrace(false);
        let image = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();

        let located = unsafe { locate_eh_frame(&image) }.unwrap();

        assert_eq!(located.address, 0x7000_0400);
        assert_eq!(located.size, 0);
    }

    fn synthetic_elf_for_backtrace(include_direct_eh_frame: bool) -> Vec<u8> {
        const EHDR_SIZE: usize = 64;
        const PHDR_SIZE: usize = 56;
        const SHDR_SIZE: usize = 64;
        const SYM_SIZE: usize = 24;
        const PT_LOAD: u32 = 1;
        const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
        const SHT_PROGBITS: u32 = 1;
        const SHT_SYMTAB: u32 = 2;
        const SHT_STRTAB: u32 = 3;

        let eh_hdr_off = 0x200usize;
        let eh_frame_off = 0x400usize;
        let symtab_off = align(eh_frame_off + 16, 8);
        let strtab = b"\0main_object\0";
        let strtab_off = align(symtab_off + (SYM_SIZE * 2), 8);
        let shstr = if include_direct_eh_frame {
            b"\0.eh_frame\0.eh_frame_hdr\0.symtab\0.strtab\0.shstrtab\0".as_slice()
        } else {
            b"\0.eh_frame_hdr\0.symtab\0.strtab\0.shstrtab\0".as_slice()
        };
        let shstr_off = align(strtab_off + strtab.len(), 8);
        let shoff = align(shstr_off + shstr.len(), 8);
        let shnum = if include_direct_eh_frame { 6 } else { 5 };
        let shstrndx = shnum - 1;
        let size = shoff + (SHDR_SIZE * shnum);

        let mut bytes = vec![0u8; size];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 3);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, EHDR_SIZE as u64);
        put_u64(&mut bytes, 40, shoff as u64);
        put_u16(&mut bytes, 52, EHDR_SIZE as u16);
        put_u16(&mut bytes, 54, PHDR_SIZE as u16);
        put_u16(&mut bytes, 56, 2);
        put_u16(&mut bytes, 58, SHDR_SIZE as u16);
        put_u16(&mut bytes, 60, shnum as u16);
        put_u16(&mut bytes, 62, shstrndx as u16);

        put_phdr(
            &mut bytes,
            EHDR_SIZE,
            PT_LOAD,
            5,
            0,
            0,
            size as u64,
            0x1000,
            8,
        );
        put_phdr(
            &mut bytes,
            EHDR_SIZE + PHDR_SIZE,
            PT_GNU_EH_FRAME,
            4,
            eh_hdr_off as u64,
            eh_hdr_off as u64,
            8,
            8,
            4,
        );

        bytes[eh_hdr_off] = 1;
        bytes[eh_hdr_off + 1] = 0x1b;
        bytes[eh_hdr_off + 2] = 0xff;
        bytes[eh_hdr_off + 3] = 0xff;
        put_u32(&mut bytes, eh_hdr_off + 4, 0x1fc);

        put_sym(&mut bytes, symtab_off + SYM_SIZE, 1, 0x11, 1, 0x100, 8);
        bytes[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);
        bytes[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

        if include_direct_eh_frame {
            put_shdr(
                &mut bytes,
                shoff + SHDR_SIZE,
                1,
                SHT_PROGBITS,
                eh_frame_off,
                16,
                0,
                1,
            );
            put_u64(&mut bytes, shoff + SHDR_SIZE + 16, eh_frame_off as u64);
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 2),
                11,
                SHT_PROGBITS,
                eh_hdr_off,
                8,
                0,
                1,
            );
            put_u64(&mut bytes, shoff + (SHDR_SIZE * 2) + 16, eh_hdr_off as u64);
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 3),
                25,
                SHT_SYMTAB,
                symtab_off,
                SYM_SIZE * 2,
                4,
                SYM_SIZE,
            );
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 4),
                33,
                SHT_STRTAB,
                strtab_off,
                strtab.len(),
                0,
                1,
            );
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 5),
                41,
                SHT_STRTAB,
                shstr_off,
                shstr.len(),
                0,
                1,
            );
        } else {
            put_shdr(
                &mut bytes,
                shoff + SHDR_SIZE,
                1,
                SHT_PROGBITS,
                eh_hdr_off,
                8,
                0,
                1,
            );
            put_u64(&mut bytes, shoff + SHDR_SIZE + 16, eh_hdr_off as u64);
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 2),
                15,
                SHT_SYMTAB,
                symtab_off,
                SYM_SIZE * 2,
                3,
                SYM_SIZE,
            );
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 3),
                23,
                SHT_STRTAB,
                strtab_off,
                strtab.len(),
                0,
                1,
            );
            put_shdr(
                &mut bytes,
                shoff + (SHDR_SIZE * 4),
                31,
                SHT_STRTAB,
                shstr_off,
                shstr.len(),
                0,
                1,
            );
        }

        bytes
    }

    fn align(value: usize, alignment: usize) -> usize {
        (value + alignment - 1) & !(alignment - 1)
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn put_phdr(
        bytes: &mut [u8],
        offset: usize,
        p_type: u32,
        flags: u32,
        file_off: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) {
        put_u32(bytes, offset, p_type);
        put_u32(bytes, offset + 4, flags);
        put_u64(bytes, offset + 8, file_off);
        put_u64(bytes, offset + 16, vaddr);
        put_u64(bytes, offset + 32, filesz);
        put_u64(bytes, offset + 40, memsz);
        put_u64(bytes, offset + 48, align);
    }

    fn put_sym(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        info: u8,
        shndx: u16,
        value: u64,
        size: u64,
    ) {
        put_u32(bytes, offset, name);
        bytes[offset + 4] = info;
        put_u16(bytes, offset + 6, shndx);
        put_u64(bytes, offset + 8, value);
        put_u64(bytes, offset + 16, size);
    }

    #[allow(clippy::too_many_arguments)]
    fn put_shdr(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        sh_type: u32,
        sh_offset: usize,
        sh_size: usize,
        sh_link: u32,
        sh_entsize: usize,
    ) {
        put_u32(bytes, offset, name);
        put_u32(bytes, offset + 4, sh_type);
        put_u64(bytes, offset + 24, sh_offset as u64);
        put_u64(bytes, offset + 32, sh_size as u64);
        put_u32(bytes, offset + 40, sh_link);
        put_u64(bytes, offset + 56, sh_entsize as u64);
    }
}
