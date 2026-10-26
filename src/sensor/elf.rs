use std::ffi::CStr;

use super::SensorError;

pub use crate::xdl::Elf64Phdr;

pub const TARGET_LIBRARY: &CStr = c"libsensorservice.so";
pub const TARGET_SYMBOL: &[u8] = b"_ZN7android8hardware7sensors14implementation20convertToSensorEventERKN4aidl7android8hardware7sensors5EventEP15sensors_event_t\0";
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const RELA: u64 = 7;
const MAX_DYNAMIC_ENTRIES: usize = 16 * 1024;
const MAX_RELOCATIONS: usize = 16 * 1024;
const MAX_SYMBOL_INDEX: usize = MAX_RELOCATIONS;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

#[derive(Clone, Copy)]
struct DynamicInfo {
    symtab: usize,
    strtab: usize,
    strsz: usize,
    jmprel: usize,
    relasz: usize,
    pltrel_seen: bool,
}

/// Finds the target relocation in an ELF image that is already loaded.
///
/// # Safety
///
/// `program_headers` must reference `count` readable headers, and every
/// address reachable through the image's dynamic tables must remain mapped
/// and readable for the duration of this call.
pub unsafe fn find_relocation(
    loaded_base: usize,
    program_headers: *const Elf64Phdr,
    count: usize,
) -> Result<usize, SensorError> {
    unsafe {
        find_relocation_with_resolver(loaded_base, program_headers, count, |base, value| {
            add_base(base, value)
        })
    }
}

/// Finds the target relocation while delegating dynamic-address fixups.
///
/// # Safety
///
/// `program_headers` must reference `count` readable headers. Every address
/// returned by `resolver` for a dynamic table, symbol table, string table, or
/// relocation table must remain mapped and readable for this call.
pub unsafe fn find_relocation_with_resolver<F: Fn(usize, u64) -> Result<usize, SensorError>>(
    loaded_base: usize,
    program_headers: *const Elf64Phdr,
    count: usize,
    resolver: F,
) -> Result<usize, SensorError> {
    unsafe {
        find_relocation_for_symbol_with_resolver(
            loaded_base,
            program_headers,
            count,
            TARGET_SYMBOL,
            resolver,
        )
    }
}

/// Finds a PLT relocation for an arbitrary symbol in an already loaded ELF.
///
/// This is shared by the sensor and framework-input hooks. Keeping the ELF
/// validation in one place prevents the second hook from accepting malformed
/// dynamic tables that the sensor hook would reject.
///
/// # Safety
///
/// The same requirements as [`find_relocation_with_resolver`] apply.
pub unsafe fn find_relocation_for_symbol_with_resolver<
    F: Fn(usize, u64) -> Result<usize, SensorError>,
>(
    loaded_base: usize,
    program_headers: *const Elf64Phdr,
    count: usize,
    target_symbol: &[u8],
    resolver: F,
) -> Result<usize, SensorError> {
    if program_headers.is_null() || count == 0 || count > MAX_DYNAMIC_ENTRIES {
        return Err(SensorError::MalformedElf);
    }
    let phdrs = unsafe { std::slice::from_raw_parts(program_headers, count) };
    let dynamic = phdrs
        .iter()
        .find(|p| p.p_type == PT_DYNAMIC)
        .ok_or(SensorError::MissingDynamic)?;
    let entries = usize::try_from(dynamic.p_filesz / std::mem::size_of::<Elf64Dyn>() as u64)
        .map_err(|_| SensorError::MalformedElf)?;
    if entries == 0
        || entries > MAX_DYNAMIC_ENTRIES
        || dynamic.p_filesz % std::mem::size_of::<Elf64Dyn>() as u64 != 0
    {
        return Err(SensorError::MalformedElf);
    }
    let dynamic_addr = resolver(loaded_base, dynamic.p_vaddr)?;
    let dyns = unsafe { std::slice::from_raw_parts(dynamic_addr as *const Elf64Dyn, entries) };
    let mut info = DynamicInfo {
        symtab: 0,
        strtab: 0,
        strsz: 0,
        jmprel: 0,
        relasz: 0,
        pltrel_seen: false,
    };
    let mut terminated = false;
    for entry in dyns {
        match entry.d_tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_SYMTAB => info.symtab = resolver(loaded_base, entry.d_val)?,
            DT_STRTAB => info.strtab = resolver(loaded_base, entry.d_val)?,
            DT_STRSZ => {
                info.strsz = usize::try_from(entry.d_val).map_err(|_| SensorError::MalformedElf)?
            }
            DT_JMPREL => info.jmprel = resolver(loaded_base, entry.d_val)?,
            DT_PLTRELSZ => {
                info.relasz = usize::try_from(entry.d_val).map_err(|_| SensorError::MalformedElf)?
            }
            DT_PLTREL => {
                info.pltrel_seen = true;
                if entry.d_val != RELA {
                    return Err(SensorError::UnsupportedRelocation);
                }
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(SensorError::UnterminatedDynamic);
    }
    if info.symtab == 0
        || info.strtab == 0
        || info.jmprel == 0
        || info.strsz == 0
        || info.relasz == 0
        || !info.pltrel_seen
    {
        return Err(SensorError::MissingDynamicEntry);
    }
    if !info.relasz.is_multiple_of(std::mem::size_of::<Elf64Rela>()) {
        return Err(SensorError::MalformedElf);
    }
    let reloc_count = info.relasz / std::mem::size_of::<Elf64Rela>();
    if reloc_count == 0 || reloc_count > MAX_RELOCATIONS {
        return Err(SensorError::MalformedElf);
    }
    let relas = unsafe { std::slice::from_raw_parts(info.jmprel as *const Elf64Rela, reloc_count) };
    for rela in relas {
        let symbol_index =
            usize::try_from(rela.r_info >> 32).map_err(|_| SensorError::MalformedElf)?;
        if symbol_index >= MAX_SYMBOL_INDEX {
            return Err(SensorError::MalformedElf);
        }
        let symbol_addr = info
            .symtab
            .checked_add(
                symbol_index
                    .checked_mul(std::mem::size_of::<Elf64Sym>())
                    .ok_or(SensorError::MalformedElf)?,
            )
            .ok_or(SensorError::MalformedElf)?;
        let symbol = unsafe { (symbol_addr as *const Elf64Sym).read() };
        let name_offset = usize::try_from(symbol.st_name).map_err(|_| SensorError::MalformedElf)?;
        if name_offset >= info.strsz || target_symbol.len() > info.strsz - name_offset {
            continue;
        }
        let name_addr = info
            .strtab
            .checked_add(name_offset)
            .ok_or(SensorError::MalformedElf)?;
        let name =
            unsafe { std::slice::from_raw_parts(name_addr as *const u8, target_symbol.len()) };
        if name == target_symbol {
            return add_base(loaded_base, rela.r_offset);
        }
    }
    Err(SensorError::SymbolNotFound)
}

fn add_base(base: usize, value: u64) -> Result<usize, SensorError> {
    base.checked_add(usize::try_from(value).map_err(|_| SensorError::MalformedElf)?)
        .ok_or(SensorError::MalformedElf)
}
