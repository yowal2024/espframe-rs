use core::ffi::c_void;
use std::ffi::CStr;
use std::mem::size_of;

use crate::xdl::elf::Elf64Phdr;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const SHN_UNDEF: u16 = 0;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;
const MAX_PROGRAM_HEADERS: usize = 1024;
const MAX_DYNAMIC_ENTRIES: usize = 16 * 1024;
const MAX_HASH_ENTRIES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicSymbol {
    pub address: usize,
    pub size: usize,
}

#[derive(Clone, Copy)]
pub struct LoadedModuleSnapshot<'a> {
    pathname: &'a CStr,
    load_bias: usize,
    program_headers: &'a [Elf64Phdr],
}

impl<'a> LoadedModuleSnapshot<'a> {
    pub const fn new(
        pathname: &'a CStr,
        load_bias: usize,
        program_headers: &'a [Elf64Phdr],
    ) -> Self {
        Self {
            pathname,
            load_bias,
            program_headers,
        }
    }

    pub const fn pathname(self) -> &'a CStr {
        self.pathname
    }

    pub const fn load_bias(self) -> usize {
        self.load_bias
    }

    pub const fn program_headers(self) -> &'a [Elf64Phdr] {
        self.program_headers
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XdlError {
    #[error("loaded module was not found")]
    ModuleNotFound,
    #[error("malformed loaded ELF")]
    MalformedElf,
    #[error("dynamic symbol was not found")]
    SymbolNotFound,
    #[error("dynamic symbol type requires linker-specific resolution")]
    UnsupportedSymbol,
    #[error("loaded module discovery is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("force-loading the requested module failed")]
    ForceLoadFailed,
    #[error("the xDL info request is unsupported")]
    InvalidRequest,
    #[error("the module image could not be read")]
    Io,
}

pub(crate) struct AddressSymbol {
    pub(crate) name: std::ffi::CString,
    pub(crate) address: usize,
    pub(crate) size: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadedElf {
    pub base: usize,
    pub program_headers: *const Elf64Phdr,
    pub program_header_count: usize,
}

#[cfg(any(target_os = "android", test))]
fn is_linker_request(requested: &CStr, is_64_bit: bool) -> bool {
    let basename = if is_64_bit {
        b"linker64".as_slice()
    } else {
        b"linker".as_slice()
    };
    let bytes = requested.to_bytes();
    bytes == basename
        || bytes
            .strip_suffix(basename)
            .is_some_and(|prefix| prefix.last() == Some(&b'/'))
}

#[cfg(target_os = "android")]
pub(crate) fn linker_from_auxv() -> Option<LoadedElf> {
    const AT_BASE: libc::c_ulong = 7;
    let image_base = unsafe { libc::getauxval(AT_BASE) } as usize;
    if image_base == 0 {
        return None;
    }
    let header = unsafe { std::slice::from_raw_parts(image_base as *const u8, 64) };
    if header.get(..4) != Some(b"\x7fELF") || header.get(4) != Some(&2) || header.get(5) != Some(&1)
    {
        return None;
    }
    let phoff = usize::try_from(u64::from_le_bytes(header.get(32..40)?.try_into().ok()?)).ok()?;
    let phentsize = usize::from(u16::from_le_bytes(header.get(54..56)?.try_into().ok()?));
    let phnum = usize::from(u16::from_le_bytes(header.get(56..58)?.try_into().ok()?));
    if phentsize != size_of::<Elf64Phdr>() || phnum == 0 || phnum > MAX_PROGRAM_HEADERS {
        return None;
    }
    let program_headers = image_base.checked_add(phoff)? as *const Elf64Phdr;
    let headers = unsafe { std::slice::from_raw_parts(program_headers, phnum) };
    let minimum_vaddr = headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .filter_map(|header| usize::try_from(header.p_vaddr).ok())
        .min()?;
    Some(LoadedElf {
        base: image_base.checked_sub(minimum_vaddr)?,
        program_headers,
        program_header_count: phnum,
    })
}

#[cfg(target_os = "android")]
struct OpenContext<'a> {
    requested: &'a CStr,
    found: Option<LoadedElf>,
}

#[cfg(target_os = "android")]
unsafe extern "C" fn open_callback(
    info: *mut libc::dl_phdr_info,
    size: usize,
    data: *mut core::ffi::c_void,
) -> libc::c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    let required =
        std::mem::offset_of!(libc::dl_phdr_info, dlpi_phnum) + size_of::<libc::Elf64_Half>();
    if size < required {
        return 0;
    }
    let info = unsafe { &*info };
    if info.dlpi_addr == 0
        || info.dlpi_name.is_null()
        || info.dlpi_phdr.is_null()
        || info.dlpi_phnum == 0
        || usize::from(info.dlpi_phnum) > MAX_PROGRAM_HEADERS
    {
        return 0;
    }
    let pathname = unsafe { CStr::from_ptr(info.dlpi_name) };
    let context = unsafe { &mut *(data as *mut OpenContext<'_>) };
    if !module_name_matches(context.requested.to_bytes(), pathname.to_bytes()) {
        return 0;
    }
    context.found = Some(LoadedElf {
        base: info.dlpi_addr as usize,
        program_headers: info.dlpi_phdr.cast::<Elf64Phdr>(),
        program_header_count: usize::from(info.dlpi_phnum),
    });
    1
}

#[cfg(target_os = "android")]
pub fn open_loaded(requested: &CStr) -> Result<LoadedElf, XdlError> {
    if is_linker_request(requested, cfg!(target_pointer_width = "64")) {
        if let Some(linker) = linker_from_auxv() {
            return Ok(linker);
        }
    }
    let mut context = OpenContext {
        requested,
        found: None,
    };
    unsafe {
        libc::dl_iterate_phdr(
            Some(open_callback),
            (&mut context as *mut OpenContext<'_>).cast(),
        );
    }
    context.found.ok_or(XdlError::ModuleNotFound)
}

#[cfg(not(target_os = "android"))]
pub fn open_loaded(_requested: &CStr) -> Result<LoadedElf, XdlError> {
    Err(XdlError::UnsupportedPlatform)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[derive(Default)]
struct DynamicInfo {
    symtab: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<usize>,
    syment: Option<usize>,
    sysv_hash: Option<u64>,
    gnu_hash: Option<u64>,
}

struct LoadedRanges {
    ranges: Vec<(usize, usize)>,
    executable_ranges: Vec<(usize, usize)>,
}

impl LoadedRanges {
    fn new(load_bias: usize, phdrs: &[Elf64Phdr]) -> Result<Self, XdlError> {
        if phdrs.is_empty() || phdrs.len() > MAX_PROGRAM_HEADERS {
            return Err(XdlError::MalformedElf);
        }
        let mut ranges = Vec::new();
        let mut executable_ranges = Vec::new();
        for phdr in phdrs.iter().filter(|phdr| phdr.p_type == PT_LOAD) {
            if phdr.p_memsz == 0 {
                continue;
            }
            let start = add_u64(load_bias, phdr.p_vaddr)?;
            let length = usize::try_from(phdr.p_memsz).map_err(|_| XdlError::MalformedElf)?;
            let end = start.checked_add(length).ok_or(XdlError::MalformedElf)?;
            ranges.push((start, end));
            if phdr.p_flags & PF_X != 0 {
                executable_ranges.push((start, end));
            }
        }
        if ranges.is_empty() {
            return Err(XdlError::MalformedElf);
        }
        Ok(Self {
            ranges,
            executable_ranges,
        })
    }

    fn contains(&self, address: usize, length: usize) -> bool {
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        self.ranges
            .iter()
            .any(|(start, range_end)| address >= *start && end <= *range_end)
    }

    fn contains_executable(&self, address: usize, length: usize) -> bool {
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        self.executable_ranges
            .iter()
            .any(|(start, range_end)| address >= *start && end <= *range_end)
    }

    fn resolve(&self, load_bias: usize, value: u64, length: usize) -> Result<usize, XdlError> {
        let raw = usize::try_from(value).map_err(|_| XdlError::MalformedElf)?;
        if self.contains(raw, length) {
            return Ok(raw);
        }
        let relative = load_bias.checked_add(raw).ok_or(XdlError::MalformedElf)?;
        if self.contains(relative, length) {
            Ok(relative)
        } else {
            Err(XdlError::MalformedElf)
        }
    }

    fn read<T: Copy>(&self, address: usize) -> Result<T, XdlError> {
        if !self.contains(address, size_of::<T>()) {
            return Err(XdlError::MalformedElf);
        }
        Ok(unsafe { (address as *const T).read_unaligned() })
    }
}

pub fn find_loaded_module<'a>(
    requested: &CStr,
    modules: impl IntoIterator<Item = LoadedModuleSnapshot<'a>>,
) -> Option<LoadedModuleSnapshot<'a>> {
    modules
        .into_iter()
        .find(|module| module_name_matches(requested.to_bytes(), module.pathname.to_bytes()))
}

fn module_name_matches(requested: &[u8], loaded: &[u8]) -> bool {
    if requested.is_empty()
        || loaded.is_empty()
        || requested.last() == Some(&b'/')
        || loaded.last() == Some(&b'/')
    {
        return false;
    }
    if requested.first() == Some(&b'[') {
        return requested == loaded;
    }
    if requested == loaded {
        return true;
    }
    if requested.first() == Some(&b'/') {
        if loaded.first() == Some(&b'/') {
            false
        } else {
            path_ends_with_basename(requested, loaded)
        }
    } else if loaded.first() == Some(&b'/') {
        path_ends_with_basename(loaded, requested)
    } else {
        false
    }
}

fn path_ends_with_basename(path: &[u8], basename: &[u8]) -> bool {
    path.strip_suffix(basename)
        .is_some_and(|prefix| prefix.last() == Some(&b'/'))
}

/// Resolves one exported symbol from an ELF image that is already loaded.
///
/// # Safety
///
/// The caller must ensure the supplied ELF metadata is trusted and that every
/// `PT_LOAD` range and dynamic-table pointer it describes remains mapped,
/// readable, and stable for the duration of this call. The module must not be
/// unloaded concurrently. A `STT_GNU_IFUNC` entry causes this function to call
/// its resolver, so its validated executable address must be a callable target
/// platform ABI function. Resolving an untrusted image can execute module code.
pub unsafe fn resolve_dynamic_symbol(
    load_bias: usize,
    phdrs: &[Elf64Phdr],
    symbol: &CStr,
) -> Result<DynamicSymbol, XdlError> {
    let ranges = LoadedRanges::new(load_bias, phdrs)?;
    let dynamic = phdrs
        .iter()
        .find(|phdr| phdr.p_type == PT_DYNAMIC)
        .ok_or(XdlError::MalformedElf)?;
    let dynamic_size = usize::try_from(dynamic.p_memsz).map_err(|_| XdlError::MalformedElf)?;
    if dynamic_size == 0 || dynamic_size % size_of::<Elf64Dyn>() != 0 {
        return Err(XdlError::MalformedElf);
    }
    let dynamic_count = dynamic_size / size_of::<Elf64Dyn>();
    if dynamic_count > MAX_DYNAMIC_ENTRIES {
        return Err(XdlError::MalformedElf);
    }
    let dynamic_address = add_u64(load_bias, dynamic.p_vaddr)?;
    if !ranges.contains(dynamic_address, dynamic_size) {
        return Err(XdlError::MalformedElf);
    }

    let mut info = DynamicInfo::default();
    let mut terminated = false;
    for index in 0..dynamic_count {
        let address = dynamic_address
            .checked_add(
                index
                    .checked_mul(size_of::<Elf64Dyn>())
                    .ok_or(XdlError::MalformedElf)?,
            )
            .ok_or(XdlError::MalformedElf)?;
        let entry: Elf64Dyn = ranges.read(address)?;
        match entry.d_tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_HASH => info.sysv_hash = Some(entry.d_val),
            DT_GNU_HASH => info.gnu_hash = Some(entry.d_val),
            DT_SYMTAB => info.symtab = Some(entry.d_val),
            DT_STRTAB => info.strtab = Some(entry.d_val),
            DT_STRSZ => {
                info.strsz = Some(usize::try_from(entry.d_val).map_err(|_| XdlError::MalformedElf)?)
            }
            DT_SYMENT => {
                info.syment =
                    Some(usize::try_from(entry.d_val).map_err(|_| XdlError::MalformedElf)?)
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(XdlError::MalformedElf);
    }

    let symtab = ranges.resolve(
        load_bias,
        info.symtab.ok_or(XdlError::MalformedElf)?,
        size_of::<Elf64Sym>(),
    )?;
    let strsz = info.strsz.ok_or(XdlError::MalformedElf)?;
    if strsz == 0 {
        return Err(XdlError::MalformedElf);
    }
    let strtab = ranges.resolve(load_bias, info.strtab.ok_or(XdlError::MalformedElf)?, strsz)?;
    if info.syment.unwrap_or(size_of::<Elf64Sym>()) != size_of::<Elf64Sym>() {
        return Err(XdlError::MalformedElf);
    }

    let context = SymbolContext {
        load_bias,
        ranges: &ranges,
        symtab,
        strtab,
        strsz,
        name: symbol.to_bytes(),
    };
    if let Some(hash) = info.gnu_hash {
        if let Some(found) = find_gnu_symbol(&context, hash)? {
            return Ok(found);
        }
    }
    if let Some(hash) = info.sysv_hash {
        if let Some(found) = find_sysv_symbol(&context, hash)? {
            return Ok(found);
        }
    }
    if info.gnu_hash.is_none() && info.sysv_hash.is_none() {
        return Err(XdlError::MalformedElf);
    }
    Err(XdlError::SymbolNotFound)
}

struct SymbolContext<'a> {
    load_bias: usize,
    ranges: &'a LoadedRanges,
    symtab: usize,
    strtab: usize,
    strsz: usize,
    name: &'a [u8],
}

impl SymbolContext<'_> {
    fn symbol(&self, index: usize) -> Result<Option<DynamicSymbol>, XdlError> {
        if index >= MAX_HASH_ENTRIES {
            return Err(XdlError::MalformedElf);
        }
        let address = self
            .symtab
            .checked_add(
                index
                    .checked_mul(size_of::<Elf64Sym>())
                    .ok_or(XdlError::MalformedElf)?,
            )
            .ok_or(XdlError::MalformedElf)?;
        let symbol: Elf64Sym = self.ranges.read(address)?;
        if symbol.st_shndx == SHN_UNDEF {
            return Ok(None);
        }
        let name_offset = usize::try_from(symbol.st_name).map_err(|_| XdlError::MalformedElf)?;
        let required = self
            .name
            .len()
            .checked_add(1)
            .ok_or(XdlError::MalformedElf)?;
        if name_offset >= self.strsz {
            return Err(XdlError::MalformedElf);
        }
        if required > self.strsz - name_offset {
            return Ok(None);
        }
        let name_address = self
            .strtab
            .checked_add(name_offset)
            .ok_or(XdlError::MalformedElf)?;
        if !self.ranges.contains(name_address, required) {
            return Err(XdlError::MalformedElf);
        }
        let actual = unsafe { std::slice::from_raw_parts(name_address as *const u8, required) };
        if actual[..self.name.len()] != *self.name || actual[self.name.len()] != 0 {
            return Ok(None);
        }
        if matches!(symbol.st_info & 0xf, STT_TLS) {
            return Err(XdlError::UnsupportedSymbol);
        }
        let raw_value = usize::try_from(symbol.st_value).map_err(|_| XdlError::MalformedElf)?;
        if matches!(symbol.st_info & 0xf, STT_GNU_IFUNC) {
            let resolver_address = self.resolve_ifunc_address(raw_value)?;
            let resolved_address = unsafe { invoke_ifunc_resolver(resolver_address) };
            if resolved_address == 0 {
                return Ok(None);
            }
            return Ok(Some(DynamicSymbol {
                address: resolved_address,
                size: 0,
            }));
        }
        let symbol_address = self
            .load_bias
            .checked_add(raw_value)
            .ok_or(XdlError::MalformedElf)?;
        let symbol_size = usize::try_from(symbol.st_size).map_err(|_| XdlError::MalformedElf)?;
        if !self.ranges.contains(symbol_address, symbol_size.max(1)) {
            return Err(XdlError::MalformedElf);
        }
        Ok(Some(DynamicSymbol {
            address: symbol_address,
            size: symbol_size,
        }))
    }

    fn resolve_ifunc_address(&self, raw_value: usize) -> Result<usize, XdlError> {
        let address = self
            .load_bias
            .checked_add(raw_value)
            .ok_or(XdlError::MalformedElf)?;
        self.ranges
            .contains_executable(address, 1)
            .then_some(address)
            .ok_or(XdlError::MalformedElf)
    }
}

#[cfg(any(all(target_os = "android", target_arch = "aarch64"), test))]
const fn uses_android_hwcap_ifunc_abi(api_level: i32, is_aarch64: bool) -> bool {
    api_level >= 30 && is_aarch64
}

pub(crate) unsafe fn invoke_ifunc_resolver(resolver_address: usize) -> usize {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        if uses_android_hwcap_ifunc_abi(crate::xdl::lzma::android_api_level(), true) {
            #[repr(C)]
            struct IfuncArgument {
                size: libc::c_ulong,
                hwcap: libc::c_ulong,
                hwcap2: libc::c_ulong,
            }
            const AT_HWCAP: libc::c_ulong = 16;
            const AT_HWCAP2: libc::c_ulong = 26;
            const IFUNC_ARG_HWCAP: u64 = 1u64 << 62;
            let mut argument = IfuncArgument {
                size: std::mem::size_of::<IfuncArgument>() as libc::c_ulong,
                hwcap: unsafe { libc::getauxval(AT_HWCAP) },
                hwcap2: unsafe { libc::getauxval(AT_HWCAP2) },
            };
            let resolver: unsafe extern "C" fn(u64, *mut IfuncArgument) -> *mut c_void =
                unsafe { core::mem::transmute(resolver_address) };
            return (unsafe { resolver(argument.hwcap as u64 | IFUNC_ARG_HWCAP, &mut argument) })
                as usize;
        }
    }

    #[cfg(all(target_os = "android", target_arch = "arm"))]
    if crate::xdl::lzma::android_api_level() >= 30 {
        const AT_HWCAP: libc::c_ulong = 16;
        let resolver: unsafe extern "C" fn(libc::c_ulong) -> *mut c_void =
            unsafe { core::mem::transmute(resolver_address) };
        return (unsafe { resolver(libc::getauxval(AT_HWCAP)) }) as usize;
    }

    let resolver: unsafe extern "C" fn() -> *mut c_void =
        unsafe { core::mem::transmute(resolver_address) };
    (unsafe { resolver() }) as usize
}

fn find_sysv_symbol(
    context: &SymbolContext<'_>,
    hash_value: u64,
) -> Result<Option<DynamicSymbol>, XdlError> {
    let hash_address = context.ranges.resolve(context.load_bias, hash_value, 8)?;
    let bucket_count: u32 = context.ranges.read(hash_address)?;
    let chain_count: u32 = context
        .ranges
        .read(hash_address.checked_add(4).ok_or(XdlError::MalformedElf)?)?;
    let bucket_count = usize::try_from(bucket_count).map_err(|_| XdlError::MalformedElf)?;
    let chain_count = usize::try_from(chain_count).map_err(|_| XdlError::MalformedElf)?;
    if bucket_count == 0
        || chain_count == 0
        || bucket_count > MAX_HASH_ENTRIES
        || chain_count > MAX_HASH_ENTRIES
    {
        return Err(XdlError::MalformedElf);
    }
    let words = 2usize
        .checked_add(bucket_count)
        .and_then(|value| value.checked_add(chain_count))
        .ok_or(XdlError::MalformedElf)?;
    if !context.ranges.contains(
        hash_address,
        words.checked_mul(4).ok_or(XdlError::MalformedElf)?,
    ) {
        return Err(XdlError::MalformedElf);
    }
    let bucket = usize::try_from(elf_hash(context.name) % bucket_count as u32)
        .map_err(|_| XdlError::MalformedElf)?;
    let buckets = hash_address.checked_add(8).ok_or(XdlError::MalformedElf)?;
    let chains = buckets
        .checked_add(bucket_count.checked_mul(4).ok_or(XdlError::MalformedElf)?)
        .ok_or(XdlError::MalformedElf)?;
    let mut index = usize::try_from(
        context.ranges.read::<u32>(
            buckets
                .checked_add(bucket.checked_mul(4).ok_or(XdlError::MalformedElf)?)
                .ok_or(XdlError::MalformedElf)?,
        )?,
    )
    .map_err(|_| XdlError::MalformedElf)?;
    for _ in 0..chain_count {
        if index == 0 {
            return Ok(None);
        }
        if index >= chain_count {
            return Err(XdlError::MalformedElf);
        }
        if let Some(symbol) = context.symbol(index)? {
            return Ok(Some(symbol));
        }
        index = usize::try_from(
            context.ranges.read::<u32>(
                chains
                    .checked_add(index.checked_mul(4).ok_or(XdlError::MalformedElf)?)
                    .ok_or(XdlError::MalformedElf)?,
            )?,
        )
        .map_err(|_| XdlError::MalformedElf)?;
    }
    Err(XdlError::MalformedElf)
}

fn find_gnu_symbol(
    context: &SymbolContext<'_>,
    hash_value: u64,
) -> Result<Option<DynamicSymbol>, XdlError> {
    let hash_address = context.ranges.resolve(context.load_bias, hash_value, 16)?;
    let bucket_count = usize::try_from(context.ranges.read::<u32>(hash_address)?)
        .map_err(|_| XdlError::MalformedElf)?;
    let symbol_offset = usize::try_from(
        context
            .ranges
            .read::<u32>(hash_address.checked_add(4).ok_or(XdlError::MalformedElf)?)?,
    )
    .map_err(|_| XdlError::MalformedElf)?;
    let bloom_count = usize::try_from(
        context
            .ranges
            .read::<u32>(hash_address.checked_add(8).ok_or(XdlError::MalformedElf)?)?,
    )
    .map_err(|_| XdlError::MalformedElf)?;
    let bloom_shift = context
        .ranges
        .read::<u32>(hash_address.checked_add(12).ok_or(XdlError::MalformedElf)?)?;
    if bucket_count == 0
        || bloom_count == 0
        || bucket_count > MAX_HASH_ENTRIES
        || bloom_count > MAX_HASH_ENTRIES
        || symbol_offset >= MAX_HASH_ENTRIES
        || bloom_shift >= u32::BITS
    {
        return Err(XdlError::MalformedElf);
    }
    let hash = gnu_hash(context.name);
    let bloom = hash_address.checked_add(16).ok_or(XdlError::MalformedElf)?;
    let word_bits = usize::BITS;
    let bloom_index =
        usize::try_from(hash / word_bits).map_err(|_| XdlError::MalformedElf)? % bloom_count;
    let bloom_word_address = bloom
        .checked_add(
            bloom_index
                .checked_mul(size_of::<usize>())
                .ok_or(XdlError::MalformedElf)?,
        )
        .ok_or(XdlError::MalformedElf)?;
    let bloom_word: usize = context.ranges.read(bloom_word_address)?;
    let first_bit = hash % word_bits;
    let second_bit = (hash >> bloom_shift) % word_bits;
    if bloom_word & (1usize << first_bit) == 0 || bloom_word & (1usize << second_bit) == 0 {
        return Ok(None);
    }
    let buckets = bloom
        .checked_add(
            bloom_count
                .checked_mul(size_of::<usize>())
                .ok_or(XdlError::MalformedElf)?,
        )
        .ok_or(XdlError::MalformedElf)?;
    let bucket = usize::try_from(
        context.ranges.read::<u32>(
            buckets
                .checked_add(
                    (usize::try_from(hash).map_err(|_| XdlError::MalformedElf)? % bucket_count)
                        .checked_mul(4)
                        .ok_or(XdlError::MalformedElf)?,
                )
                .ok_or(XdlError::MalformedElf)?,
        )?,
    )
    .map_err(|_| XdlError::MalformedElf)?;
    if bucket < symbol_offset {
        return Ok(None);
    }
    let chains = buckets
        .checked_add(bucket_count.checked_mul(4).ok_or(XdlError::MalformedElf)?)
        .ok_or(XdlError::MalformedElf)?;
    for step in 0..MAX_HASH_ENTRIES {
        let index = bucket.checked_add(step).ok_or(XdlError::MalformedElf)?;
        let chain_index = index
            .checked_sub(symbol_offset)
            .ok_or(XdlError::MalformedElf)?;
        let chain_hash = context.ranges.read::<u32>(
            chains
                .checked_add(chain_index.checked_mul(4).ok_or(XdlError::MalformedElf)?)
                .ok_or(XdlError::MalformedElf)?,
        )?;
        if chain_hash | 1 == hash | 1 {
            if let Some(symbol) = context.symbol(index)? {
                return Ok(Some(symbol));
            }
        }
        if chain_hash & 1 != 0 {
            return Ok(None);
        }
    }
    Err(XdlError::MalformedElf)
}

/// Finds the first dynamic symbol whose declared range contains `address`.
///
/// # Safety
///
/// The mapped ranges described by `phdrs` must remain readable for the whole
/// call and the module must not be unloaded concurrently.
pub(crate) unsafe fn dynamic_symbol_by_address(
    load_bias: usize,
    phdrs: &[Elf64Phdr],
    address: usize,
) -> Result<Option<AddressSymbol>, XdlError> {
    let ranges = LoadedRanges::new(load_bias, phdrs)?;
    let dynamic = phdrs
        .iter()
        .find(|header| header.p_type == PT_DYNAMIC)
        .ok_or(XdlError::MalformedElf)?;
    let dynamic_size = usize::try_from(dynamic.p_memsz).map_err(|_| XdlError::MalformedElf)?;
    if dynamic_size == 0 || dynamic_size % size_of::<Elf64Dyn>() != 0 {
        return Err(XdlError::MalformedElf);
    }
    let dynamic_count = dynamic_size / size_of::<Elf64Dyn>();
    if dynamic_count > MAX_DYNAMIC_ENTRIES {
        return Err(XdlError::MalformedElf);
    }
    let dynamic_address = add_u64(load_bias, dynamic.p_vaddr)?;
    if !ranges.contains(dynamic_address, dynamic_size) {
        return Err(XdlError::MalformedElf);
    }

    let mut info = DynamicInfo::default();
    let mut terminated = false;
    for index in 0..dynamic_count {
        let entry_address = dynamic_address
            .checked_add(
                index
                    .checked_mul(size_of::<Elf64Dyn>())
                    .ok_or(XdlError::MalformedElf)?,
            )
            .ok_or(XdlError::MalformedElf)?;
        let entry: Elf64Dyn = ranges.read(entry_address)?;
        match entry.d_tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_HASH => info.sysv_hash = Some(entry.d_val),
            DT_GNU_HASH => info.gnu_hash = Some(entry.d_val),
            DT_SYMTAB => info.symtab = Some(entry.d_val),
            DT_STRTAB => info.strtab = Some(entry.d_val),
            DT_STRSZ => {
                info.strsz = Some(usize::try_from(entry.d_val).map_err(|_| XdlError::MalformedElf)?)
            }
            DT_SYMENT => {
                info.syment =
                    Some(usize::try_from(entry.d_val).map_err(|_| XdlError::MalformedElf)?)
            }
            _ => {}
        }
    }
    if !terminated || info.syment.unwrap_or(size_of::<Elf64Sym>()) != size_of::<Elf64Sym>() {
        return Err(XdlError::MalformedElf);
    }
    let symtab = ranges.resolve(
        load_bias,
        info.symtab.ok_or(XdlError::MalformedElf)?,
        size_of::<Elf64Sym>(),
    )?;
    let strsz = info.strsz.ok_or(XdlError::MalformedElf)?;
    if strsz == 0 {
        return Err(XdlError::MalformedElf);
    }
    let strtab = ranges.resolve(load_bias, info.strtab.ok_or(XdlError::MalformedElf)?, strsz)?;

    let mut found = None;
    let mut visit = |index| {
        let symbol = address_symbol_at(&ranges, load_bias, symtab, strtab, strsz, address, index)?;
        if symbol.is_some() {
            found = symbol;
            Ok(true)
        } else {
            Ok(false)
        }
    };
    if let Some(hash) = info.gnu_hash {
        visit_gnu_symbol_indices(&ranges, load_bias, hash, &mut visit)?;
    } else if let Some(hash) = info.sysv_hash {
        visit_sysv_symbol_indices(&ranges, load_bias, hash, &mut visit)?;
    } else {
        return Err(XdlError::MalformedElf);
    }
    Ok(found)
}

fn address_symbol_at(
    ranges: &LoadedRanges,
    load_bias: usize,
    symtab: usize,
    strtab: usize,
    strsz: usize,
    address: usize,
    index: usize,
) -> Result<Option<AddressSymbol>, XdlError> {
    if index >= MAX_HASH_ENTRIES {
        return Err(XdlError::MalformedElf);
    }
    let symbol_address = symtab
        .checked_add(
            index
                .checked_mul(size_of::<Elf64Sym>())
                .ok_or(XdlError::MalformedElf)?,
        )
        .ok_or(XdlError::MalformedElf)?;
    let symbol: Elf64Sym = ranges.read(symbol_address)?;
    if symbol.st_shndx == SHN_UNDEF || symbol.st_info & 0x0f == STT_TLS {
        return Ok(None);
    }
    let size = usize::try_from(symbol.st_size).map_err(|_| XdlError::MalformedElf)?;
    if size == 0 {
        return Ok(None);
    }
    let value = usize::try_from(symbol.st_value).map_err(|_| XdlError::MalformedElf)?;
    let start = load_bias.checked_add(value).ok_or(XdlError::MalformedElf)?;
    let end = start.checked_add(size).ok_or(XdlError::MalformedElf)?;
    if address < start || address >= end {
        return Ok(None);
    }
    let name_offset = usize::try_from(symbol.st_name).map_err(|_| XdlError::MalformedElf)?;
    if name_offset >= strsz {
        return Err(XdlError::MalformedElf);
    }
    let name_address = strtab
        .checked_add(name_offset)
        .ok_or(XdlError::MalformedElf)?;
    let available = strsz - name_offset;
    if !ranges.contains(name_address, available) {
        return Err(XdlError::MalformedElf);
    }
    let bytes = unsafe { std::slice::from_raw_parts(name_address as *const u8, available) };
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(XdlError::MalformedElf)?;
    let name = std::ffi::CString::new(&bytes[..nul]).map_err(|_| XdlError::MalformedElf)?;
    Ok(Some(AddressSymbol {
        name,
        address: start,
        size,
    }))
}

fn visit_sysv_symbol_indices(
    ranges: &LoadedRanges,
    load_bias: usize,
    hash_value: u64,
    visit: &mut impl FnMut(usize) -> Result<bool, XdlError>,
) -> Result<(), XdlError> {
    let address = ranges.resolve(load_bias, hash_value, 8)?;
    let bucket_count =
        usize::try_from(ranges.read::<u32>(address)?).map_err(|_| XdlError::MalformedElf)?;
    let chain_count =
        usize::try_from(ranges.read::<u32>(address.checked_add(4).ok_or(XdlError::MalformedElf)?)?)
            .map_err(|_| XdlError::MalformedElf)?;
    if bucket_count == 0 || chain_count == 0 || chain_count > MAX_HASH_ENTRIES {
        return Err(XdlError::MalformedElf);
    }
    let words = 2usize
        .checked_add(bucket_count)
        .and_then(|value| value.checked_add(chain_count))
        .ok_or(XdlError::MalformedElf)?;
    if !ranges.contains(address, words.checked_mul(4).ok_or(XdlError::MalformedElf)?) {
        return Err(XdlError::MalformedElf);
    }
    for index in 0..chain_count {
        if visit(index)? {
            break;
        }
    }
    Ok(())
}

fn visit_gnu_symbol_indices(
    ranges: &LoadedRanges,
    load_bias: usize,
    hash_value: u64,
    visit: &mut impl FnMut(usize) -> Result<bool, XdlError>,
) -> Result<(), XdlError> {
    let address = ranges.resolve(load_bias, hash_value, 16)?;
    let bucket_count =
        usize::try_from(ranges.read::<u32>(address)?).map_err(|_| XdlError::MalformedElf)?;
    let symbol_offset =
        usize::try_from(ranges.read::<u32>(address.checked_add(4).ok_or(XdlError::MalformedElf)?)?)
            .map_err(|_| XdlError::MalformedElf)?;
    let bloom_count =
        usize::try_from(ranges.read::<u32>(address.checked_add(8).ok_or(XdlError::MalformedElf)?)?)
            .map_err(|_| XdlError::MalformedElf)?;
    if bucket_count == 0
        || bloom_count == 0
        || bucket_count > MAX_HASH_ENTRIES
        || bloom_count > MAX_HASH_ENTRIES
        || symbol_offset >= MAX_HASH_ENTRIES
    {
        return Err(XdlError::MalformedElf);
    }
    let bloom = address.checked_add(16).ok_or(XdlError::MalformedElf)?;
    let buckets = bloom
        .checked_add(
            bloom_count
                .checked_mul(size_of::<usize>())
                .ok_or(XdlError::MalformedElf)?,
        )
        .ok_or(XdlError::MalformedElf)?;
    let chains = buckets
        .checked_add(bucket_count.checked_mul(4).ok_or(XdlError::MalformedElf)?)
        .ok_or(XdlError::MalformedElf)?;
    if !ranges.contains(
        buckets,
        bucket_count.checked_mul(4).ok_or(XdlError::MalformedElf)?,
    ) {
        return Err(XdlError::MalformedElf);
    }
    for bucket_index in 0..bucket_count {
        let bucket = usize::try_from(
            ranges.read::<u32>(
                buckets
                    .checked_add(bucket_index.checked_mul(4).ok_or(XdlError::MalformedElf)?)
                    .ok_or(XdlError::MalformedElf)?,
            )?,
        )
        .map_err(|_| XdlError::MalformedElf)?;
        if bucket < symbol_offset {
            continue;
        }
        for step in 0..MAX_HASH_ENTRIES {
            let index = bucket.checked_add(step).ok_or(XdlError::MalformedElf)?;
            if index >= MAX_HASH_ENTRIES {
                return Err(XdlError::MalformedElf);
            }
            if visit(index)? {
                return Ok(());
            }
            let chain_index = index
                .checked_sub(symbol_offset)
                .ok_or(XdlError::MalformedElf)?;
            let hash = ranges.read::<u32>(
                chains
                    .checked_add(chain_index.checked_mul(4).ok_or(XdlError::MalformedElf)?)
                    .ok_or(XdlError::MalformedElf)?,
            )?;
            if hash & 1 != 0 {
                break;
            }
            if step + 1 == MAX_HASH_ENTRIES {
                return Err(XdlError::MalformedElf);
            }
        }
    }
    Ok(())
}

fn elf_hash(name: &[u8]) -> u32 {
    let mut value = 0u32;
    for byte in name {
        value = value.wrapping_shl(4).wrapping_add(u32::from(*byte));
        let high = value & 0xf000_0000;
        if high != 0 {
            value ^= high >> 24;
            value &= !high;
        }
    }
    value
}

fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |value, byte| {
        value.wrapping_mul(33).wrapping_add(u32::from(*byte))
    })
}

fn add_u64(base: usize, value: u64) -> Result<usize, XdlError> {
    base.checked_add(usize::try_from(value).map_err(|_| XdlError::MalformedElf)?)
        .ok_or(XdlError::MalformedElf)
}

#[cfg(test)]
mod ifunc_tests {
    use super::{
        is_linker_request, uses_android_hwcap_ifunc_abi, visit_gnu_symbol_indices,
        visit_sysv_symbol_indices, LoadedRanges, SymbolContext,
    };
    use crate::xdl::XdlError;

    #[test]
    fn ifunc_resolver_outside_the_relative_load_range_is_rejected() {
        let ranges = LoadedRanges {
            ranges: vec![(0x1000, 0x2000)],
            executable_ranges: vec![(0x1000, 0x2000)],
        };
        let context = SymbolContext {
            load_bias: 0x1000,
            ranges: &ranges,
            symtab: 0,
            strtab: 0,
            strsz: 0,
            name: b"",
        };

        assert_eq!(
            context.resolve_ifunc_address(0x5000),
            Err(XdlError::MalformedElf)
        );
    }

    #[test]
    fn sysv_address_lookup_stops_after_the_first_matching_index() {
        let mut table = vec![0u32; 100_003];
        table[0] = 1;
        table[1] = 100_000;
        let ranges = LoadedRanges {
            ranges: vec![(
                table.as_ptr() as usize,
                table.as_ptr() as usize + std::mem::size_of_val(table.as_slice()),
            )],
            executable_ranges: Vec::new(),
        };
        let mut calls = 0;

        visit_sysv_symbol_indices(&ranges, 0, table.as_ptr() as usize as u64, &mut |_| {
            calls += 1;
            Ok(true)
        })
        .unwrap();

        assert_eq!(calls, 1);
    }

    #[test]
    fn gnu_address_lookup_stops_after_the_first_matching_index() {
        let mut table = [0u8; 36];
        table[0..4].copy_from_slice(&1u32.to_ne_bytes());
        table[4..8].copy_from_slice(&1u32.to_ne_bytes());
        table[8..12].copy_from_slice(&1u32.to_ne_bytes());
        table[12..16].copy_from_slice(&5u32.to_ne_bytes());
        table[24..28].copy_from_slice(&1u32.to_ne_bytes());
        table[28..32].copy_from_slice(&0u32.to_ne_bytes());
        table[32..36].copy_from_slice(&1u32.to_ne_bytes());
        let ranges = LoadedRanges {
            ranges: vec![(
                table.as_ptr() as usize,
                table.as_ptr() as usize + table.len(),
            )],
            executable_ranges: Vec::new(),
        };
        let mut calls = 0;

        visit_gnu_symbol_indices(&ranges, 0, table.as_ptr() as usize as u64, &mut |_| {
            calls += 1;
            Ok(true)
        })
        .unwrap();

        assert_eq!(calls, 1);
    }

    #[test]
    fn aarch64_ifunc_switches_to_hwcap_abi_on_android_11() {
        assert!(!uses_android_hwcap_ifunc_abi(29, true));
        assert!(uses_android_hwcap_ifunc_abi(30, true));
        assert!(!uses_android_hwcap_ifunc_abi(35, false));
    }

    #[test]
    fn linker_auxv_lookup_requires_a_complete_platform_basename() {
        assert!(is_linker_request(c"linker64", true));
        assert!(is_linker_request(c"/system/bin/linker64", true));
        assert!(!is_linker_request(c"evil-linker64", true));
        assert!(!is_linker_request(c"linker", true));
        assert!(is_linker_request(c"linker", false));
    }
}
