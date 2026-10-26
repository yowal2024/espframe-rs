use std::{convert::TryFrom, ops::Range, path::Path};

use crate::soloader::error::{LoaderError, Result};
use crate::soloader::reloc::{
    decode_android_packed_relocations, decode_relr_offsets, Relocation as GenericRelocation,
};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const SHN_UNDEF: usize = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;
const STV_DEFAULT: u8 = 0;
const STV_PROTECTED: u8 = 3;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_RELRENT: u64 = 37;
const DT_ANDROID_REL: u64 = 0x6000_000f;
const DT_ANDROID_RELSZ: u64 = 0x6000_0010;
const DT_ANDROID_RELA: u64 = 0x6000_0011;
const DT_ANDROID_RELASZ: u64 = 0x6000_0012;
const DT_ANDROID_RELR: u64 = 0x6fff_e000;
const DT_ANDROID_RELRSZ: u64 = 0x6fff_e001;
const DT_ANDROID_RELRENT: u64 = 0x6fff_e003;

#[derive(Debug, Clone)]
pub struct ElfImage {
    name: String,
    bytes: Vec<u8>,
    base: usize,
    bias: usize,
    machine: u16,
    word_size: usize,
    little_endian: bool,
    program_headers: Vec<goblin::elf::ProgramHeader>,
    dynamic_entries: Vec<DynamicEntry>,
    needed_libraries: Vec<String>,
    dynamic_symbols: Vec<SymbolInfo>,
    symtab_symbols: Vec<SymbolInfo>,
    rela_relocations: Vec<GenericRelocation>,
    rel_relocations: Vec<GenericRelocation>,
    plt_relocations: Vec<GenericRelocation>,
    relr_offsets: Vec<usize>,
    android_relocations: Option<AndroidRelocationInfo>,
    init: Option<usize>,
    fini: Option<usize>,
    init_array: Option<ArrayInfo>,
    fini_array: Option<ArrayInfo>,
    preinit_array: Option<ArrayInfo>,
    tls: Option<TlsInfo>,
    eh_frame: Option<RegionInfo>,
    eh_frame_hdr: Option<RegionInfo>,
    gcc_except_table: Option<RegionInfo>,
}

impl ElfImage {
    pub fn parse_file(path: impl AsRef<Path>, base: usize) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        Self::parse_memory(path.to_string_lossy(), &bytes, base)
    }

    pub fn parse_memory(name: impl Into<String>, bytes: &[u8], base: usize) -> Result<Self> {
        if bytes.len() < ELF_MAGIC.len() || &bytes[..ELF_MAGIC.len()] != ELF_MAGIC {
            return Err(LoaderError::InvalidElf("invalid ELF magic".into()));
        }

        let name = name.into();
        let parsed = goblin::elf::Elf::parse(bytes)
            .map_err(|err| LoaderError::InvalidElf(format!("failed to parse ELF {name}: {err}")))?;
        let bias = calculate_bias(&parsed);
        let machine = parsed.header.e_machine;
        let is_64 = parsed.is_64;
        let word_size = word_size(is_64);
        let little_endian = parsed.little_endian;
        let program_headers = parsed.program_headers.clone();
        let dynamic_entries = collect_dynamic_entries(&parsed);
        let dynamic_symbols = collect_symbols(&parsed.dynsyms, &parsed.dynstrtab);
        let symtab_symbols = collect_symbols(&parsed.syms, &parsed.strtab);
        let relocations = collect_relocations(&parsed, bytes, is_64, little_endian, &name)?;
        let mut dynamic = DynamicInfo::default();
        collect_dynamic_info(&parsed, &mut dynamic);
        collect_section_regions(&parsed, &mut dynamic);

        Ok(Self {
            name,
            bytes: bytes.to_vec(),
            base,
            bias,
            machine,
            word_size,
            little_endian,
            program_headers,
            dynamic_entries,
            needed_libraries: parsed.libraries.iter().map(|s| (*s).to_owned()).collect(),
            dynamic_symbols,
            symtab_symbols,
            rela_relocations: relocations.rela_relocations,
            rel_relocations: relocations.rel_relocations,
            plt_relocations: relocations.plt_relocations,
            relr_offsets: relocations.relr_offsets,
            android_relocations: relocations.android_relocations,
            init: dynamic.init,
            fini: dynamic.fini,
            init_array: dynamic.init_array,
            fini_array: dynamic.fini_array,
            preinit_array: dynamic.preinit_array,
            tls: dynamic.tls,
            eh_frame: dynamic.eh_frame,
            eh_frame_hdr: dynamic.eh_frame_hdr,
            gcc_except_table: dynamic.gcc_except_table,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn set_base(&mut self, base: usize) {
        self.base = base;
    }

    pub fn bias(&self) -> usize {
        self.bias
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn word_size(&self) -> usize {
        self.word_size
    }

    pub fn is_little_endian(&self) -> bool {
        self.little_endian
    }

    pub fn needed_libraries(&self) -> &[String] {
        &self.needed_libraries
    }

    pub fn program_headers(&self) -> &[goblin::elf::ProgramHeader] {
        &self.program_headers
    }

    pub fn dynamic_entries(&self) -> &[DynamicEntry] {
        &self.dynamic_entries
    }

    pub fn dynamic_symbols(&self) -> &[SymbolInfo] {
        &self.dynamic_symbols
    }

    pub fn dynamic_symbol(&self, index: usize) -> Option<&SymbolInfo> {
        self.dynamic_symbols.get(index)
    }

    pub fn rela_relocations(&self) -> &[GenericRelocation] {
        &self.rela_relocations
    }

    pub fn rel_relocations(&self) -> &[GenericRelocation] {
        &self.rel_relocations
    }

    pub fn plt_relocations(&self) -> &[GenericRelocation] {
        &self.plt_relocations
    }

    pub fn relr_offsets(&self) -> &[usize] {
        &self.relr_offsets
    }

    pub fn android_relocations(&self) -> Option<&AndroidRelocationInfo> {
        self.android_relocations.as_ref()
    }

    pub fn file_range_for_vaddr(&self, vaddr: usize, size: usize) -> Option<Range<usize>> {
        file_range_for_vaddr_in_phdrs(&self.program_headers, self.bytes.len(), vaddr, size)
    }

    pub fn symtab_symbols(&self) -> &[SymbolInfo] {
        &self.symtab_symbols
    }

    pub fn init(&self) -> Option<usize> {
        self.init.map(|value| self.absolute_address(value as u64))
    }

    pub fn fini(&self) -> Option<usize> {
        self.fini.map(|value| self.absolute_address(value as u64))
    }

    pub fn init_array(&self) -> Option<ArrayInfo> {
        self.init_array.map(|info| ArrayInfo {
            address: self.absolute_address(info.address as u64),
            count: info.count,
        })
    }

    pub fn fini_array(&self) -> Option<ArrayInfo> {
        self.fini_array.map(|info| ArrayInfo {
            address: self.absolute_address(info.address as u64),
            count: info.count,
        })
    }

    pub fn preinit_array(&self) -> Option<ArrayInfo> {
        self.preinit_array.map(|info| ArrayInfo {
            address: self.absolute_address(info.address as u64),
            count: info.count,
        })
    }

    pub fn tls(&self) -> Option<TlsInfo> {
        self.tls.map(|info| TlsInfo {
            address: self.absolute_address(info.address as u64),
            mem_size: info.mem_size,
            file_size: info.file_size,
            align: info.align,
        })
    }

    pub fn eh_frame(&self) -> Option<RegionInfo> {
        self.eh_frame.map(|info| RegionInfo {
            address: self.absolute_address(info.address as u64),
            size: info.size,
        })
    }

    pub fn eh_frame_hdr(&self) -> Option<RegionInfo> {
        self.eh_frame_hdr.map(|info| RegionInfo {
            address: self.absolute_address(info.address as u64),
            size: info.size,
        })
    }

    pub fn gcc_except_table(&self) -> Option<RegionInfo> {
        self.gcc_except_table.map(|info| RegionInfo {
            address: self.absolute_address(info.address as u64),
            size: info.size,
        })
    }

    pub fn symbol_offset(&self, name: &str, exported_only: bool) -> Option<SymbolInfo> {
        self.dynamic_symbols
            .iter()
            .find(|sym| sym.name == name && sym.is_dynamic_visible(exported_only))
            .cloned()
    }

    pub fn symbol_address(&self, name: &str) -> Option<usize> {
        self.symbol_offset(name, false)
            .map(|sym| self.absolute_address(sym.value))
    }

    pub fn exported_symbol_address(&self, name: &str) -> Option<usize> {
        self.symbol_offset(name, true)
            .map(|sym| self.absolute_address(sym.value))
    }

    pub fn symbol_address_by_prefix(&self, prefix: &str) -> Option<usize> {
        if prefix.is_empty() {
            return None;
        }

        self.symtab_symbols
            .iter()
            .find(|sym| {
                sym.name.starts_with(prefix)
                    && sym.shndx != SHN_UNDEF
                    && sym.size > 0
                    && sym.value != 0
            })
            .map(|sym| self.absolute_address(sym.value))
    }

    pub fn get_symbol_for_address(&self, addr: usize) -> Option<ResolvedSymbol> {
        self.symtab_symbols.iter().find_map(|sym| {
            if sym.value == 0 || sym.size == 0 {
                return None;
            }

            let start = self.absolute_address(sym.value);
            let end = start.saturating_add(sym.size as usize);
            (addr >= start && addr < end).then(|| ResolvedSymbol {
                name: sym.name.clone(),
                address: start,
            })
        })
    }

    pub fn absolute_address(&self, value: u64) -> usize {
        self.base
            .wrapping_add(value as usize)
            .wrapping_sub(self.bias)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    pub index: usize,
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DynamicEntry {
    pub tag: u64,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidRelocationInfo {
    pub relocations: Vec<GenericRelocation>,
    pub is_rela: bool,
}

impl SymbolInfo {
    pub fn st_type(&self) -> u8 {
        self.info & 0x0f
    }

    pub fn bind(&self) -> u8 {
        self.info >> 4
    }

    pub fn visibility(&self) -> u8 {
        self.other & 0x03
    }

    pub fn is_ifunc(&self) -> bool {
        self.st_type() == STT_GNU_IFUNC
    }

    fn is_dynamic_visible(&self, exported_only: bool) -> bool {
        if self.shndx == SHN_UNDEF {
            return false;
        }
        if !exported_only {
            return true;
        }

        matches!(self.bind(), STB_GLOBAL | STB_WEAK)
            && matches!(self.visibility(), STV_DEFAULT | STV_PROTECTED)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ArrayInfo {
    pub address: usize,
    pub count: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    pub address: usize,
    pub mem_size: usize,
    pub file_size: usize,
    pub align: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RegionInfo {
    pub address: usize,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSymbol {
    pub name: String,
    pub address: usize,
}

#[derive(Debug, Default)]
struct DynamicInfo {
    init: Option<usize>,
    fini: Option<usize>,
    init_array_addr: Option<usize>,
    init_array_size: Option<usize>,
    fini_array_addr: Option<usize>,
    fini_array_size: Option<usize>,
    preinit_array_addr: Option<usize>,
    preinit_array_size: Option<usize>,
    init_array: Option<ArrayInfo>,
    fini_array: Option<ArrayInfo>,
    preinit_array: Option<ArrayInfo>,
    tls: Option<TlsInfo>,
    eh_frame: Option<RegionInfo>,
    eh_frame_hdr: Option<RegionInfo>,
    gcc_except_table: Option<RegionInfo>,
}

#[derive(Debug, Default)]
struct CollectedRelocations {
    rela_relocations: Vec<GenericRelocation>,
    rel_relocations: Vec<GenericRelocation>,
    plt_relocations: Vec<GenericRelocation>,
    relr_offsets: Vec<usize>,
    android_relocations: Option<AndroidRelocationInfo>,
}

pub fn elf_hash(name: &str) -> u32 {
    let mut h = 0u32;

    for byte in name.bytes() {
        h = (h << 4).wrapping_add(byte as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }

    h
}

pub fn gnu_hash(name: &str) -> u32 {
    let mut h = 5381u32;

    for byte in name.bytes() {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(byte as u32);
    }

    h
}

fn collect_symbols(
    symbols: &goblin::elf::sym::Symtab,
    strings: &goblin::strtab::Strtab,
) -> Vec<SymbolInfo> {
    symbols
        .iter()
        .enumerate()
        .map(|(index, sym)| SymbolInfo {
            index,
            name: strings.get_at(sym.st_name).unwrap_or("").to_owned(),
            value: sym.st_value,
            size: sym.st_size,
            info: sym.st_info,
            other: sym.st_other,
            shndx: sym.st_shndx,
        })
        .collect()
}

fn collect_dynamic_entries(elf: &goblin::elf::Elf<'_>) -> Vec<DynamicEntry> {
    elf.dynamic
        .as_ref()
        .map(|dynamic| {
            dynamic
                .dyns
                .iter()
                .map(|entry| DynamicEntry {
                    tag: entry.d_tag,
                    value: entry.d_val,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn file_range_for_vaddr_in_phdrs(
    program_headers: &[goblin::elf::ProgramHeader],
    file_len: usize,
    vaddr: usize,
    size: usize,
) -> Option<Range<usize>> {
    let end_vaddr = vaddr.checked_add(size)?;

    for phdr in program_headers
        .iter()
        .filter(|phdr| phdr.p_type == goblin::elf::program_header::PT_LOAD)
    {
        let seg_start = usize::try_from(phdr.p_vaddr).ok()?;
        let file_size = usize::try_from(phdr.p_filesz).ok()?;
        let seg_file_end = seg_start.checked_add(file_size)?;

        if vaddr < seg_start || end_vaddr > seg_file_end {
            continue;
        }

        let file_start = usize::try_from(phdr.p_offset)
            .ok()?
            .checked_add(vaddr - seg_start)?;
        let file_end = file_start.checked_add(size)?;
        if file_end <= file_len {
            return Some(file_start..file_end);
        }
    }

    None
}

fn collect_relocations(
    elf: &goblin::elf::Elf<'_>,
    bytes: &[u8],
    is_64: bool,
    little_endian: bool,
    name: &str,
) -> Result<CollectedRelocations> {
    let rela_relocations = elf.dynrelas.iter().map(goblin_reloc_to_rela).collect();
    let rel_relocations = elf.dynrels.iter().map(goblin_reloc_to_rel).collect();
    let plt_relocations = elf
        .pltrelocs
        .iter()
        .map(|reloc| goblin_reloc_to_generic(reloc, reloc.r_addend.is_some()))
        .collect();

    let relr_entries = collect_relr_entries(elf, bytes, is_64, little_endian, name)?;
    let relr_offsets = decode_relr_offsets(&relr_entries, word_size(is_64));
    let android_relocations = collect_android_relocations(elf, bytes, name)?;

    Ok(CollectedRelocations {
        rela_relocations,
        rel_relocations,
        plt_relocations,
        relr_offsets,
        android_relocations,
    })
}

fn goblin_reloc_to_rela(reloc: goblin::elf::reloc::Reloc) -> GenericRelocation {
    goblin_reloc_to_generic(reloc, true)
}

fn goblin_reloc_to_rel(reloc: goblin::elf::reloc::Reloc) -> GenericRelocation {
    goblin_reloc_to_generic(reloc, false)
}

fn goblin_reloc_to_generic(
    reloc: goblin::elf::reloc::Reloc,
    has_addend: bool,
) -> GenericRelocation {
    GenericRelocation {
        sym_idx: reloc.r_sym,
        kind: reloc.r_type,
        offset: reloc.r_offset as usize,
        addend: reloc.r_addend.unwrap_or(0),
        has_addend,
    }
}

fn collect_relr_entries(
    elf: &goblin::elf::Elf<'_>,
    bytes: &[u8],
    is_64: bool,
    little_endian: bool,
    name: &str,
) -> Result<Vec<usize>> {
    let mut relr_vaddr = None;
    let mut relr_size = None;
    let mut relr_ent = word_size(is_64);

    for entry in collect_dynamic_entries(elf) {
        match entry.tag {
            DT_RELR | DT_ANDROID_RELR => relr_vaddr = Some(entry.value as usize),
            DT_RELRSZ | DT_ANDROID_RELRSZ => relr_size = Some(entry.value as usize),
            DT_RELRENT | DT_ANDROID_RELRENT => relr_ent = entry.value as usize,
            _ => {}
        }
    }

    let Some(vaddr) = relr_vaddr else {
        return Ok(Vec::new());
    };
    let size = relr_size.unwrap_or(0);
    if size == 0 {
        return Ok(Vec::new());
    }
    let expected_ent = word_size(is_64);
    if relr_ent != expected_ent {
        return Err(LoaderError::InvalidElf(format!(
            "unsupported RELR entry size {relr_ent} in {name}"
        )));
    }

    let range = file_range_for_vaddr_in_phdrs(&elf.program_headers, bytes.len(), vaddr, size)
        .ok_or_else(|| LoaderError::InvalidElf(format!("invalid RELR range in {name}")))?;
    read_words(&bytes[range], is_64, little_endian, name)
}

fn collect_android_relocations(
    elf: &goblin::elf::Elf<'_>,
    bytes: &[u8],
    name: &str,
) -> Result<Option<AndroidRelocationInfo>> {
    let mut packed_vaddr = None;
    let mut packed_size = None;
    let mut is_rela = false;

    for entry in collect_dynamic_entries(elf) {
        match entry.tag {
            DT_ANDROID_RELA => {
                packed_vaddr = Some(entry.value as usize);
                is_rela = true;
            }
            DT_ANDROID_RELASZ => packed_size = Some(entry.value as usize),
            DT_ANDROID_REL => {
                packed_vaddr = Some(entry.value as usize);
                is_rela = false;
            }
            DT_ANDROID_RELSZ => packed_size = Some(entry.value as usize),
            _ => {}
        }
    }

    let Some(vaddr) = packed_vaddr else {
        return Ok(None);
    };
    let size = packed_size.unwrap_or(0);
    let range = file_range_for_vaddr_in_phdrs(&elf.program_headers, bytes.len(), vaddr, size)
        .ok_or_else(|| {
            LoaderError::InvalidElf(format!("invalid Android packed relocation range in {name}"))
        })?;
    let relocations = decode_android_packed_relocations(&bytes[range], is_rela)?;
    Ok(Some(AndroidRelocationInfo {
        relocations,
        is_rela,
    }))
}

fn word_size(is_64: bool) -> usize {
    if is_64 {
        8
    } else {
        4
    }
}

fn read_words(bytes: &[u8], is_64: bool, little_endian: bool, name: &str) -> Result<Vec<usize>> {
    let word_size = word_size(is_64);
    if !bytes.len().is_multiple_of(word_size) {
        return Err(LoaderError::InvalidElf(format!(
            "unaligned RELR data in {name}"
        )));
    }

    bytes
        .chunks_exact(word_size)
        .map(|chunk| {
            if is_64 {
                let array = <[u8; 8]>::try_from(chunk).expect("chunk size checked");
                let value = if little_endian {
                    u64::from_le_bytes(array)
                } else {
                    u64::from_be_bytes(array)
                };
                usize::try_from(value).map_err(|_| {
                    LoaderError::InvalidElf(format!("RELR entry overflows usize in {name}"))
                })
            } else {
                let array = <[u8; 4]>::try_from(chunk).expect("chunk size checked");
                let value = if little_endian {
                    u32::from_le_bytes(array)
                } else {
                    u32::from_be_bytes(array)
                };
                Ok(value as usize)
            }
        })
        .collect()
}

fn calculate_bias(elf: &goblin::elf::Elf<'_>) -> usize {
    if let Some(phdr) = elf
        .program_headers
        .iter()
        .find(|phdr| phdr.p_type == goblin::elf::program_header::PT_LOAD && phdr.p_offset == 0)
    {
        return phdr.p_vaddr.saturating_sub(phdr.p_offset) as usize;
    }

    elf.program_headers
        .iter()
        .find(|phdr| phdr.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|phdr| phdr.p_vaddr.saturating_sub(phdr.p_offset) as usize)
        .unwrap_or(0)
}

fn collect_dynamic_info(elf: &goblin::elf::Elf<'_>, out: &mut DynamicInfo) {
    if let Some(dynamic) = &elf.dynamic {
        for dynent in &dynamic.dyns {
            let ptr = dynent.d_val as usize;
            match dynent.d_tag {
                goblin::elf::dynamic::DT_INIT => out.init = Some(ptr),
                goblin::elf::dynamic::DT_FINI => out.fini = Some(ptr),
                goblin::elf::dynamic::DT_INIT_ARRAY => out.init_array_addr = Some(ptr),
                goblin::elf::dynamic::DT_INIT_ARRAYSZ => {
                    out.init_array_size = Some(dynent.d_val as usize)
                }
                goblin::elf::dynamic::DT_FINI_ARRAY => out.fini_array_addr = Some(ptr),
                goblin::elf::dynamic::DT_FINI_ARRAYSZ => {
                    out.fini_array_size = Some(dynent.d_val as usize)
                }
                goblin::elf::dynamic::DT_PREINIT_ARRAY => out.preinit_array_addr = Some(ptr),
                goblin::elf::dynamic::DT_PREINIT_ARRAYSZ => {
                    out.preinit_array_size = Some(dynent.d_val as usize)
                }
                _ => {}
            }
        }
    }

    out.init_array = make_array_info(out.init_array_addr, out.init_array_size);
    out.fini_array = make_array_info(out.fini_array_addr, out.fini_array_size);
    out.preinit_array = make_array_info(out.preinit_array_addr, out.preinit_array_size);

    for phdr in &elf.program_headers {
        match phdr.p_type {
            goblin::elf::program_header::PT_TLS => {
                out.tls = Some(TlsInfo {
                    address: phdr.p_vaddr as usize,
                    mem_size: phdr.p_memsz as usize,
                    file_size: phdr.p_filesz as usize,
                    align: phdr.p_align as usize,
                });
            }
            goblin::elf::program_header::PT_GNU_EH_FRAME => {
                out.eh_frame_hdr = Some(RegionInfo {
                    address: phdr.p_vaddr as usize,
                    size: phdr.p_memsz as usize,
                });
            }
            _ => {}
        }
    }
}

fn collect_section_regions(elf: &goblin::elf::Elf<'_>, out: &mut DynamicInfo) {
    for section in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
            continue;
        };
        let region = RegionInfo {
            address: section.sh_addr as usize,
            size: section.sh_size as usize,
        };

        match name {
            ".eh_frame" => out.eh_frame = Some(region),
            ".eh_frame_hdr" => out.eh_frame_hdr = Some(region),
            ".gcc_except_table" => out.gcc_except_table = Some(region),
            _ => {}
        }
    }
}

fn make_array_info(address: Option<usize>, size: Option<usize>) -> Option<ArrayInfo> {
    Some(ArrayInfo {
        address: address?,
        count: size? / core::mem::size_of::<usize>(),
    })
}
