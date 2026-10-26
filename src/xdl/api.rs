use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use crate::xdl::elf::Elf64Phdr;
use crate::xdl::xdl::{dynamic_symbol_by_address, resolve_dynamic_symbol, DynamicSymbol};
use crate::xdl::{LoadedModuleSnapshot, XdlError};

pub const XDL_DEFAULT: i32 = 0;
pub const XDL_TRY_FORCE_LOAD: i32 = 0x01;
pub const XDL_ALWAYS_FORCE_LOAD: i32 = 0x02;
pub const XDL_NON_SYM: i32 = 0x01;
pub const XDL_FULL_PATHNAME: i32 = 0x01;
pub const XDL_DI_DLINFO: i32 = 1;

const PT_LOAD: u32 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_HIRESERVE: u16 = 0xffff;
const STT_TLS: u8 = 6;
const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;
const MAX_DEBUGDATA_SIZE: usize = 256 * 1024 * 1024;
const MAX_SECTION_COUNT: usize = 65_536;
const MAX_SYMBOL_COUNT: usize = 4 * 1024 * 1024;

pub struct XdlHandle {
    pathname: CString,
    load_bias: usize,
    program_headers: Vec<Elf64Phdr>,
    #[cfg(target_os = "android")]
    linker_handle: usize,
    debug_symbols: OnceLock<Result<Vec<FileSymbol>, XdlError>>,
}

/// Native linker ownership returned by an explicit force-load operation.
///
/// This mirrors xDL's `xdl_close()` return value: dropping this value leaves
/// the DSO mapped, while [`XdlLinkerHandle::close`] requests `dlclose()`.
#[derive(Debug, PartialEq, Eq)]
pub struct XdlLinkerHandle(usize);

impl XdlLinkerHandle {
    pub const fn as_raw(&self) -> usize {
        self.0
    }

    /// Release the native linker reference.
    ///
    /// # Safety
    ///
    /// No address, function pointer, or borrowed data from this DSO may be
    /// used after the final linker reference is released.
    pub unsafe fn close(self) {
        #[cfg(target_os = "android")]
        unsafe {
            libc::dlclose(self.0 as *mut core::ffi::c_void);
        }
        #[cfg(not(target_os = "android"))]
        let _ = self;
    }
}

impl XdlHandle {
    fn from_snapshot(snapshot: LoadedModuleSnapshot<'_>) -> Result<Self, XdlError> {
        if snapshot.load_bias() == 0
            || snapshot.program_headers().is_empty()
            || !snapshot
                .program_headers()
                .iter()
                .any(|header| header.p_type == PT_LOAD && header.p_memsz != 0)
        {
            return Err(XdlError::MalformedElf);
        }
        Ok(Self {
            pathname: snapshot.pathname().to_owned(),
            load_bias: snapshot.load_bias(),
            program_headers: snapshot.program_headers().to_vec(),
            #[cfg(target_os = "android")]
            linker_handle: 0,
            debug_symbols: OnceLock::new(),
        })
    }

    fn contains(&self, address: usize) -> bool {
        self.program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .any(|header| {
                let Ok(offset) = usize::try_from(header.p_vaddr) else {
                    return false;
                };
                let Ok(length) = usize::try_from(header.p_memsz) else {
                    return false;
                };
                let Some(start) = self.load_bias.checked_add(offset) else {
                    return false;
                };
                let Some(end) = start.checked_add(length) else {
                    return false;
                };
                address >= start && address < end
            })
    }

    fn metadata(&self) -> XdlInfo {
        XdlInfo {
            pathname: self.pathname.clone(),
            base: self.load_bias,
            program_headers: self.program_headers.clone(),
            symbol_name: None,
            symbol_address: None,
            symbol_size: 0,
        }
    }

    fn debug_symbols(&self) -> Result<&[FileSymbol], XdlError> {
        self.debug_symbols
            .get_or_init(|| load_debug_symbols(self.pathname.as_c_str()))
            .as_deref()
            .map_err(|error| *error)
    }
}

#[derive(Default)]
pub struct XdlAddressCache {
    handles: Vec<XdlHandle>,
}

impl XdlAddressCache {
    pub fn insert(&mut self, handle: XdlHandle) {
        self.handles.push(handle);
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }
}

#[derive(Clone, Debug)]
pub struct XdlInfo {
    pathname: CString,
    base: usize,
    program_headers: Vec<Elf64Phdr>,
    symbol_name: Option<CString>,
    symbol_address: Option<usize>,
    symbol_size: usize,
}

impl XdlInfo {
    pub fn pathname(&self) -> &CStr {
        self.pathname.as_c_str()
    }

    pub const fn base(&self) -> usize {
        self.base
    }

    pub fn program_headers(&self) -> &[Elf64Phdr] {
        &self.program_headers
    }

    pub fn symbol_name(&self) -> Option<&CStr> {
        self.symbol_name.as_deref()
    }

    pub const fn symbol_address(&self) -> Option<usize> {
        self.symbol_address
    }

    pub const fn symbol_size(&self) -> usize {
        self.symbol_size
    }
}

pub fn xdl_open(filename: &CStr, flags: i32) -> Result<XdlHandle, XdlError> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = (filename, flags);
        Err(XdlError::UnsupportedPlatform)
    }
    #[cfg(target_os = "android")]
    {
        let always_force = flags & XDL_ALWAYS_FORCE_LOAD != 0;
        if !always_force {
            if let Ok(handle) = find_runtime_by_name(filename, XDL_DEFAULT) {
                return Ok(handle);
            }
            if flags & XDL_TRY_FORCE_LOAD == 0 {
                return Err(XdlError::ModuleNotFound);
            }
        }

        // Take an owned linker reference even when the image is already mapped.
        // Pre-N Android has no namespace-aware force-load entry point.
        let linker_handle = unsafe {
            libc::dlopen(filename.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
        };
        let linker_handle = if linker_handle.is_null() {
            crate::xdl::lzma::force_system_dlopen(filename)
        } else {
            linker_handle
        };
        if linker_handle.is_null() {
            return Err(XdlError::ForceLoadFailed);
        }
        match find_runtime_by_name(filename, XDL_DEFAULT) {
            Ok(mut handle) => {
                handle.linker_handle = linker_handle as usize;
                Ok(handle)
            }
            Err(error) => {
                unsafe { libc::dlclose(linker_handle) };
                Err(error)
            }
        }
    }
}

pub fn xdl_open2(snapshot: LoadedModuleSnapshot<'_>) -> Result<XdlHandle, XdlError> {
    XdlHandle::from_snapshot(snapshot)
}

#[cfg(target_os = "android")]
pub fn xdl_close(mut handle: XdlHandle) -> Option<XdlLinkerHandle> {
    let linker_handle = handle.linker_handle;
    handle.linker_handle = 0;
    drop(handle);
    (linker_handle != 0).then_some(XdlLinkerHandle(linker_handle))
}

#[cfg(not(target_os = "android"))]
pub fn xdl_close(handle: XdlHandle) -> Option<XdlLinkerHandle> {
    drop(handle);
    None
}

/// Resolve an exported symbol from a module that remains mapped by `handle`.
///
/// # Safety
///
/// `xdl_open2` accepts caller-supplied metadata, so the caller must ensure the
/// module's `PT_LOAD` ranges and dynamic tables are valid, trusted, mapped,
/// readable, and not concurrently unloaded or rewritten. If the requested
/// symbol is `STT_GNU_IFUNC`, resolution invokes module code. The caller must
/// therefore also ensure the resolver address names a callable function using
/// the target platform's ABI; resolving an untrusted module can execute its
/// code.
pub unsafe fn xdl_sym(handle: &XdlHandle, symbol: &CStr) -> Result<DynamicSymbol, XdlError> {
    unsafe { resolve_dynamic_symbol(handle.load_bias, &handle.program_headers, symbol) }
}

/// Resolve a private/static symbol from the module's on-disk `.symtab`.
///
/// # Safety
///
/// The module represented by `handle` must remain mapped while the returned
/// address is used.
pub unsafe fn xdl_dsym(handle: &XdlHandle, symbol: &CStr) -> Result<DynamicSymbol, XdlError> {
    let wanted = symbol.to_bytes();
    let entry = handle
        .debug_symbols()?
        .iter()
        .find(|entry| canonical_symbol_matches(entry.name.as_bytes(), wanted))
        .ok_or(XdlError::SymbolNotFound)?;
    if entry.symbol_type == STT_TLS {
        return Err(XdlError::UnsupportedSymbol);
    }
    let resolver_address = handle
        .load_bias
        .checked_add(entry.value)
        .ok_or(XdlError::MalformedElf)?;
    let address = resolver_address;
    if address == 0 {
        return Err(XdlError::SymbolNotFound);
    }
    Ok(DynamicSymbol {
        address,
        size: entry.size,
    })
}

pub fn xdl_info(handle: &XdlHandle, request: i32) -> Result<XdlInfo, XdlError> {
    if request != XDL_DI_DLINFO {
        return Err(XdlError::InvalidRequest);
    }
    Ok(handle.metadata())
}

/// Locate the module and nearest containing symbol for `address`.
///
/// # Safety
///
/// The address must refer to the current process and mapped modules must not be
/// unloaded concurrently.
pub unsafe fn xdl_addr(address: usize, cache: &mut XdlAddressCache) -> Result<XdlInfo, XdlError> {
    unsafe { xdl_addr4(address, cache, XDL_DEFAULT) }
}

/// Locate module metadata for `address`, optionally skipping symbol lookup.
///
/// # Safety
///
/// The address must refer to the current process and mapped modules must not be
/// unloaded concurrently.
pub unsafe fn xdl_addr4(
    address: usize,
    cache: &mut XdlAddressCache,
    flags: i32,
) -> Result<XdlInfo, XdlError> {
    if address == 0 {
        return Err(XdlError::ModuleNotFound);
    }
    let index = if let Some(index) = cache
        .handles
        .iter()
        .position(|handle| handle.contains(address))
    {
        index
    } else {
        let handle = find_runtime_by_address(address)?;
        cache.handles.push(handle);
        cache.handles.len() - 1
    };
    let handle = &cache.handles[index];
    let mut info = handle.metadata();
    if flags & XDL_NON_SYM != 0 {
        return Ok(info);
    }

    if let Ok(Some(symbol)) =
        unsafe { dynamic_symbol_by_address(handle.load_bias, &handle.program_headers, address) }
    {
        info.symbol_name = Some(symbol.name);
        info.symbol_address = Some(symbol.address);
        info.symbol_size = symbol.size;
        return Ok(info);
    }
    if let Ok(symbols) = handle.debug_symbols() {
        if let Some(symbol) = symbols.iter().find(|symbol| {
            symbol.symbol_type != STT_TLS
                && handle
                    .load_bias
                    .checked_add(symbol.value)
                    .zip(symbol.value.checked_add(symbol.size))
                    .is_some_and(|(start, value_end)| {
                        let end = handle.load_bias.checked_add(value_end);
                        end.is_some_and(|end| address >= start && address < end)
                    })
        }) {
            info.symbol_name = Some(symbol.name.clone());
            info.symbol_address = handle.load_bias.checked_add(symbol.value);
            info.symbol_size = symbol.size;
        }
    }
    Ok(info)
}

pub fn xdl_addr_clean(cache: &mut XdlAddressCache) {
    cache.handles.clear();
}

#[cfg(target_os = "android")]
pub fn xdl_iterate_phdr<F>(flags: i32, mut callback: F) -> Result<i32, XdlError>
where
    F: FnMut(LoadedModuleSnapshot<'_>) -> i32,
{
    let linker = crate::xdl::xdl::linker_from_auxv();
    let linker_base = linker.map_or(0, |module| module.base);
    if let Some(module) = linker {
        let pathname = if cfg!(target_pointer_width = "64") {
            c"/system/bin/linker64"
        } else {
            c"/system/bin/linker"
        };
        let headers = unsafe {
            std::slice::from_raw_parts(module.program_headers, module.program_header_count)
        };
        let result = callback(LoadedModuleSnapshot::new(pathname, module.base, headers));
        if result != 0 {
            return Ok(result);
        }
    }

    struct Context<'a, F> {
        flags: i32,
        linker_base: usize,
        callback: &'a mut F,
    }

    unsafe extern "C" fn adapter<F>(
        info: *mut libc::dl_phdr_info,
        size: usize,
        data: *mut core::ffi::c_void,
    ) -> libc::c_int
    where
        F: FnMut(LoadedModuleSnapshot<'_>) -> i32,
    {
        if info.is_null() || data.is_null() {
            return 0;
        }
        let required = std::mem::offset_of!(libc::dl_phdr_info, dlpi_phnum)
            + std::mem::size_of::<libc::Elf64_Half>();
        if size < required {
            return 0;
        }
        let info = unsafe { &*info };
        let context = unsafe { &mut *(data.cast::<Context<'_, F>>()) };
        if info.dlpi_addr == 0
            || info.dlpi_addr as usize == context.linker_base
            || info.dlpi_name.is_null()
            || info.dlpi_phdr.is_null()
            || info.dlpi_phnum == 0
        {
            return 0;
        }
        let headers = unsafe {
            std::slice::from_raw_parts(
                info.dlpi_phdr.cast::<Elf64Phdr>(),
                usize::from(info.dlpi_phnum),
            )
        };
        let loaded_name = unsafe { CStr::from_ptr(info.dlpi_name) };
        let full_name = if context.flags & XDL_FULL_PATHNAME != 0
            && !loaded_name.to_bytes().starts_with(b"/")
            && !loaded_name.to_bytes().starts_with(b"[")
        {
            full_pathname(info.dlpi_addr as usize, headers)
        } else {
            None
        };
        let pathname = full_name.as_deref().unwrap_or(loaded_name);
        (context.callback)(LoadedModuleSnapshot::new(
            pathname,
            info.dlpi_addr as usize,
            headers,
        ))
    }

    let mut context = Context {
        flags,
        linker_base,
        callback: &mut callback,
    };
    let result = unsafe {
        libc::dl_iterate_phdr(
            Some(adapter::<F>),
            (&mut context as *mut Context<'_, F>).cast(),
        )
    };
    Ok(result)
}

#[cfg(not(target_os = "android"))]
pub fn xdl_iterate_phdr<F>(_flags: i32, _callback: F) -> Result<i32, XdlError>
where
    F: FnMut(LoadedModuleSnapshot<'_>) -> i32,
{
    Err(XdlError::UnsupportedPlatform)
}

#[cfg(target_os = "android")]
fn find_runtime_by_name(filename: &CStr, flags: i32) -> Result<XdlHandle, XdlError> {
    let mut found = None;
    xdl_iterate_phdr(flags | XDL_FULL_PATHNAME, |snapshot| {
        if crate::xdl::find_loaded_module(filename, [snapshot]).is_some() {
            found = XdlHandle::from_snapshot(snapshot).ok();
            1
        } else {
            0
        }
    })?;
    found.ok_or(XdlError::ModuleNotFound)
}

fn find_runtime_by_address(address: usize) -> Result<XdlHandle, XdlError> {
    let mut found = None;
    xdl_iterate_phdr(XDL_DEFAULT, |snapshot| {
        let candidate = XdlHandle::from_snapshot(snapshot).ok();
        if candidate
            .as_ref()
            .is_some_and(|handle| handle.contains(address))
        {
            found = candidate;
            1
        } else {
            0
        }
    })?;
    found.ok_or(XdlError::ModuleNotFound)
}

#[cfg(test)]
mod tests {
    use crate::xdl::elf::Elf64Phdr;

    use super::{canonical_symbol_matches, mapped_pathname_from_maps, pathname_from_maps, PT_LOAD};

    #[test]
    fn canonical_symbol_suffix_requires_dot_or_dollar_boundary() {
        assert!(canonical_symbol_matches(b"target", b"target"));
        assert!(canonical_symbol_matches(b"target.llvm.123", b"target"));
        assert!(canonical_symbol_matches(b"target$local", b"target"));
        assert!(!canonical_symbol_matches(b"target_extra", b"target"));
        assert!(!canonical_symbol_matches(b"target", b"target_longer"));
    }

    #[test]
    fn maps_lookup_skips_unrelated_malformed_lines() {
        let maps = concat!(
            "not-a-map-line\n",
            "1000-2000 r--p 00000000 00:00 0\n",
            "3000-4000 r-xp 00000000 08:01 1 /system/lib64/libtarget.so\n",
        );
        assert_eq!(
            pathname_from_maps(maps, 0x3800).unwrap().as_c_str(),
            c"/system/lib64/libtarget.so"
        );
    }

    #[test]
    fn mapped_pathname_recovers_a_system_path_for_a_bare_soname() {
        let headers = [Elf64Phdr {
            p_type: PT_LOAD,
            p_vaddr: 0x1000,
            p_memsz: 0x1000,
            ..Default::default()
        }];
        let maps = "2000-3000 r--p 00000000 08:01 1 /system/lib64/libfixture.so\n";

        assert_eq!(
            mapped_pathname_from_maps(maps, 0x1000, &headers)
                .unwrap()
                .as_c_str(),
            c"/system/lib64/libfixture.so"
        );
    }
}

#[cfg(target_os = "android")]
fn full_pathname(load_bias: usize, headers: &[Elf64Phdr]) -> Option<CString> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    mapped_pathname_from_maps(&maps, load_bias, headers)
}

#[cfg(any(target_os = "android", test))]
fn mapped_pathname_from_maps(
    maps: &str,
    load_bias: usize,
    headers: &[Elf64Phdr],
) -> Option<CString> {
    let minimum = headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .filter_map(|header| usize::try_from(header.p_vaddr).ok())
        .min()?;
    let base = load_bias.checked_add(minimum)?;
    pathname_from_maps(maps, base)
}

#[cfg(any(target_os = "android", test))]
fn pathname_from_maps(maps: &str, base: usize) -> Option<CString> {
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(_permissions) = fields.next() else {
            continue;
        };
        let Some(_offset) = fields.next() else {
            continue;
        };
        let Some(_device) = fields.next() else {
            continue;
        };
        let Some(_inode) = fields.next() else {
            continue;
        };
        let Some(pathname) = fields.next() else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(end) = usize::from_str_radix(end, 16) else {
            continue;
        };
        if base >= start && base < end && pathname.starts_with('/') {
            return CString::new(pathname.as_bytes()).ok();
        }
    }
    None
}

#[derive(Clone, Debug)]
struct FileSymbol {
    name: CString,
    value: usize,
    size: usize,
    symbol_type: u8,
}

fn canonical_symbol_matches(actual: &[u8], wanted: &[u8]) -> bool {
    if actual.is_empty() || actual.len() < wanted.len() || !actual.starts_with(wanted) {
        return false;
    }
    actual.len() == wanted.len() || matches!(actual.get(wanted.len()), Some(b'.' | b'$'))
}

fn load_debug_symbols(pathname: &CStr) -> Result<Vec<FileSymbol>, XdlError> {
    if pathname.to_bytes().starts_with(b"[") {
        return Err(XdlError::SymbolNotFound);
    }
    let path = std::path::Path::new(pathname.to_str().map_err(|_| XdlError::Io)?);
    let metadata = std::fs::metadata(path).map_err(|_| XdlError::Io)?;
    let length = usize::try_from(metadata.len()).map_err(|_| XdlError::MalformedElf)?;
    if length == 0 || length > MAX_FILE_SIZE {
        return Err(XdlError::MalformedElf);
    }
    let image = std::fs::read(path).map_err(|_| XdlError::Io)?;
    match parse_elf64_symtab(&image)? {
        ParsedSymbols::Symbols(symbols) => Ok(symbols),
        ParsedSymbols::DebugData(compressed) => {
            let unpacked = crate::xdl::xdl_lzma_decompress_bounded(compressed, MAX_DEBUGDATA_SIZE)
                .map_err(|_| XdlError::MalformedElf)?;
            match parse_elf64_symtab(&unpacked)? {
                ParsedSymbols::Symbols(symbols) => Ok(symbols),
                ParsedSymbols::DebugData(_) | ParsedSymbols::Missing => {
                    Err(XdlError::SymbolNotFound)
                }
            }
        }
        ParsedSymbols::Missing => Err(XdlError::SymbolNotFound),
    }
}

enum ParsedSymbols<'a> {
    Symbols(Vec<FileSymbol>),
    DebugData(&'a [u8]),
    Missing,
}

fn parse_elf64_symtab(image: &[u8]) -> Result<ParsedSymbols<'_>, XdlError> {
    if image.len() < 64
        || image.get(..4) != Some(b"\x7fELF")
        || image.get(4) != Some(&2)
        || image.get(5) != Some(&1)
    {
        return Err(XdlError::MalformedElf);
    }
    let section_offset = to_usize(read_u64(image, 40)?)?;
    let section_size = usize::from(read_u16(image, 58)?);
    let section_count = usize::from(read_u16(image, 60)?);
    let string_index = usize::from(read_u16(image, 62)?);
    if section_size < 64
        || section_count == 0
        || section_count > MAX_SECTION_COUNT
        || string_index >= section_count
    {
        return Err(XdlError::MalformedElf);
    }
    let string_section = table_entry(image, section_offset, section_size, string_index)?;
    if read_u32(string_section, 4)? != SHT_STRTAB {
        return Err(XdlError::MalformedElf);
    }
    let section_names = section_data(image, string_section)?;
    let mut debugdata = None;

    for index in 0..section_count {
        let section = table_entry(image, section_offset, section_size, index)?;
        let name = string_at(section_names, to_usize(read_u32(section, 0)?)?)?;
        let section_type = read_u32(section, 4)?;
        if section_type == SHT_PROGBITS && name == b".gnu_debugdata" {
            debugdata = Some(section_data(image, section)?);
            continue;
        }
        if section_type != SHT_SYMTAB || name != b".symtab" {
            continue;
        }
        let strings_index = to_usize(read_u32(section, 40)?)?;
        if strings_index >= section_count {
            return Err(XdlError::MalformedElf);
        }
        let strings_section = table_entry(image, section_offset, section_size, strings_index)?;
        if read_u32(strings_section, 4)? != SHT_STRTAB {
            return Err(XdlError::MalformedElf);
        }
        let strings = section_data(image, strings_section)?;
        let entries = section_data(image, section)?;
        let entry_size = to_usize(read_u64(section, 56)?)?;
        if entry_size < 24 || entries.len() / entry_size > MAX_SYMBOL_COUNT {
            return Err(XdlError::MalformedElf);
        }
        let mut symbols = Vec::new();
        for entry in entries.chunks_exact(entry_size) {
            let section_index = read_u16(entry, 6)?;
            if section_index == SHN_UNDEF
                || (SHN_LORESERVE..=SHN_HIRESERVE).contains(&section_index)
            {
                continue;
            }
            let name = string_at(strings, to_usize(read_u32(entry, 0)?)?)?;
            if name.is_empty() {
                continue;
            }
            symbols.push(FileSymbol {
                name: CString::new(name).map_err(|_| XdlError::MalformedElf)?,
                symbol_type: entry[4] & 0x0f,
                value: to_usize(read_u64(entry, 8)?)?,
                size: to_usize(read_u64(entry, 16)?)?,
            });
        }
        return Ok(ParsedSymbols::Symbols(symbols));
    }
    Ok(debugdata.map_or(ParsedSymbols::Missing, ParsedSymbols::DebugData))
}

fn table_entry(
    image: &[u8],
    table_offset: usize,
    entry_size: usize,
    index: usize,
) -> Result<&[u8], XdlError> {
    let offset = table_offset
        .checked_add(
            index
                .checked_mul(entry_size)
                .ok_or(XdlError::MalformedElf)?,
        )
        .ok_or(XdlError::MalformedElf)?;
    image
        .get(
            offset
                ..offset
                    .checked_add(entry_size)
                    .ok_or(XdlError::MalformedElf)?,
        )
        .ok_or(XdlError::MalformedElf)
}

fn section_data<'a>(image: &'a [u8], section: &[u8]) -> Result<&'a [u8], XdlError> {
    let offset = to_usize(read_u64(section, 24)?)?;
    let size = to_usize(read_u64(section, 32)?)?;
    image
        .get(offset..offset.checked_add(size).ok_or(XdlError::MalformedElf)?)
        .ok_or(XdlError::MalformedElf)
}

fn string_at(strings: &[u8], offset: usize) -> Result<&[u8], XdlError> {
    let tail = strings.get(offset..).ok_or(XdlError::MalformedElf)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(XdlError::MalformedElf)?;
    Ok(&tail[..end])
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, XdlError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(2).ok_or(XdlError::MalformedElf)?)
            .ok_or(XdlError::MalformedElf)?
            .try_into()
            .map_err(|_| XdlError::MalformedElf)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, XdlError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(4).ok_or(XdlError::MalformedElf)?)
            .ok_or(XdlError::MalformedElf)?
            .try_into()
            .map_err(|_| XdlError::MalformedElf)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, XdlError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(8).ok_or(XdlError::MalformedElf)?)
            .ok_or(XdlError::MalformedElf)?
            .try_into()
            .map_err(|_| XdlError::MalformedElf)?,
    ))
}

fn to_usize<T>(value: T) -> Result<usize, XdlError>
where
    usize: TryFrom<T>,
{
    usize::try_from(value).map_err(|_| XdlError::MalformedElf)
}
