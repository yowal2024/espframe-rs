use crate::soloader::error::{LoaderError, Result};
use crate::soloader::sleb128::Sleb128Decoder;
use crate::soloader::tls::TlsIndex;

pub const RELOCATION_GROUPED_BY_INFO: u64 = 1;
pub const RELOCATION_GROUPED_BY_OFFSET_DELTA: u64 = 2;
pub const RELOCATION_GROUPED_BY_ADDEND: u64 = 4;
pub const RELOCATION_GROUP_HAS_ADDEND: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    pub sym_idx: usize,
    pub kind: u32,
    pub offset: usize,
    pub addend: i64,
    pub has_addend: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RelocationApplyConfig {
    pub load_bias: usize,
    pub memory_base_vaddr: usize,
    pub word_size: usize,
    pub little_endian: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SymbolResolution {
    Resolved(usize),
    UnresolvedWeak,
}

pub trait SymbolResolver {
    fn resolve(&self, sym_idx: usize) -> Result<SymbolResolution>;

    fn resolve_ifunc(&self, _address: usize) -> Result<usize> {
        Err(LoaderError::Link(
            "IRELATIVE relocation requires an unsafe ifunc resolver".into(),
        ))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TlsSymbolResolution {
    Resolved { module: usize, offset: usize },
    UnresolvedWeak,
}

pub trait TlsRelocationContext: SymbolResolver {
    fn resolve_tls(&self, sym_idx: usize, addend: i64) -> Result<TlsSymbolResolution>;
    fn allocate_tls_index(&mut self, index: TlsIndex) -> Result<*mut TlsIndex>;

    fn tls_get_addr(&self, index: TlsIndex) -> Option<*mut u8> {
        crate::soloader::tls::global_tls_registry().get_addr(index)
    }

    fn thread_pointer(&self) -> usize {
        platform_thread_pointer()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GenericRelocationKind {
    None,
    Copy,
    IRelative,
    Relative,
    GlobDat,
    Absolute,
    JumpSlot,
    TlsDtpMod,
    TlsDtpRel,
    TlsTpRel,
    TlsDesc,
    X86_64_32,
    X86_64Pc32,
    I386Pc32,
    Unsupported(u32),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RelocationKinds {
    none: u32,
    jump_slot: u32,
    absolute: u32,
    glob_dat: u32,
    relative: u32,
    irelative: u32,
    copy: u32,
    tls_dtpmod: u32,
    tls_dtprel: u32,
    tls_tprel: u32,
    tlsdesc: u32,
    x86_64_32: Option<u32>,
    x86_64_pc32: Option<u32>,
    i386_pc32: Option<u32>,
}

impl RelocationKinds {
    pub fn for_machine(machine: u16) -> Option<Self> {
        use goblin::elf::reloc::*;

        match machine {
            goblin::elf::header::EM_X86_64 => Some(Self {
                none: R_X86_64_NONE,
                jump_slot: R_X86_64_JUMP_SLOT,
                absolute: R_X86_64_64,
                glob_dat: R_X86_64_GLOB_DAT,
                relative: R_X86_64_RELATIVE,
                irelative: R_X86_64_IRELATIVE,
                copy: R_X86_64_COPY,
                tls_dtpmod: R_X86_64_DTPMOD64,
                tls_dtprel: R_X86_64_DTPOFF64,
                tls_tprel: R_X86_64_TPOFF64,
                tlsdesc: R_X86_64_TLSDESC,
                x86_64_32: Some(R_X86_64_32),
                x86_64_pc32: Some(R_X86_64_PC32),
                i386_pc32: None,
            }),
            goblin::elf::header::EM_386 => Some(Self {
                none: R_386_NONE,
                jump_slot: R_386_JMP_SLOT,
                absolute: R_386_32,
                glob_dat: R_386_GLOB_DAT,
                relative: R_386_RELATIVE,
                irelative: R_386_IRELATIVE,
                copy: R_386_COPY,
                tls_dtpmod: R_386_TLS_DTPMOD32,
                tls_dtprel: R_386_TLS_DTPOFF32,
                tls_tprel: R_386_TLS_TPOFF,
                tlsdesc: R_386_TLS_DESC,
                x86_64_32: None,
                x86_64_pc32: None,
                i386_pc32: Some(R_386_PC32),
            }),
            goblin::elf::header::EM_AARCH64 => Some(Self {
                none: R_AARCH64_NONE,
                jump_slot: R_AARCH64_JUMP_SLOT,
                absolute: R_AARCH64_ABS64,
                glob_dat: R_AARCH64_GLOB_DAT,
                relative: R_AARCH64_RELATIVE,
                irelative: R_AARCH64_IRELATIVE,
                copy: R_AARCH64_COPY,
                tls_dtpmod: R_AARCH64_TLS_DTPMOD,
                tls_dtprel: R_AARCH64_TLS_DTPREL,
                tls_tprel: R_AARCH64_TLS_TPREL,
                tlsdesc: R_AARCH64_TLSDESC,
                x86_64_32: None,
                x86_64_pc32: None,
                i386_pc32: None,
            }),
            goblin::elf::header::EM_ARM => Some(Self {
                none: R_ARM_NONE,
                jump_slot: R_ARM_JUMP_SLOT,
                absolute: R_ARM_ABS32,
                glob_dat: R_ARM_GLOB_DAT,
                relative: R_ARM_RELATIVE,
                irelative: R_ARM_IRELATIVE,
                copy: R_ARM_COPY,
                tls_dtpmod: R_ARM_TLS_DTPMOD32,
                tls_dtprel: R_ARM_TLS_DTPOFF32,
                tls_tprel: R_ARM_TLS_TPOFF32,
                tlsdesc: R_ARM_TLS_DESC,
                x86_64_32: None,
                x86_64_pc32: None,
                i386_pc32: None,
            }),
            goblin::elf::header::EM_RISCV => Some(Self {
                none: R_RISCV_NONE,
                jump_slot: R_RISCV_JUMP_SLOT,
                absolute: R_RISCV_64,
                glob_dat: R_RISCV_64,
                relative: R_RISCV_RELATIVE,
                irelative: R_RISCV_IRELATIVE,
                copy: R_RISCV_COPY,
                tls_dtpmod: R_RISCV_TLS_DTPMOD64,
                tls_dtprel: R_RISCV_TLS_DTPREL64,
                tls_tprel: R_RISCV_TLS_TPREL64,
                tlsdesc: R_RISCV_TLSDESC_HI20,
                x86_64_32: None,
                x86_64_pc32: None,
                i386_pc32: None,
            }),
            _ => None,
        }
    }

    pub fn classify(&self, kind: u32) -> GenericRelocationKind {
        if kind == self.none {
            GenericRelocationKind::None
        } else if kind == self.copy {
            GenericRelocationKind::Copy
        } else if kind == self.irelative {
            GenericRelocationKind::IRelative
        } else if kind == self.relative {
            GenericRelocationKind::Relative
        } else if kind == self.glob_dat {
            GenericRelocationKind::GlobDat
        } else if kind == self.absolute {
            GenericRelocationKind::Absolute
        } else if kind == self.jump_slot {
            GenericRelocationKind::JumpSlot
        } else if kind == self.tls_dtpmod {
            GenericRelocationKind::TlsDtpMod
        } else if kind == self.tls_dtprel {
            GenericRelocationKind::TlsDtpRel
        } else if kind == self.tls_tprel {
            GenericRelocationKind::TlsTpRel
        } else if kind == self.tlsdesc {
            GenericRelocationKind::TlsDesc
        } else if self.x86_64_32 == Some(kind) {
            GenericRelocationKind::X86_64_32
        } else if self.x86_64_pc32 == Some(kind) {
            GenericRelocationKind::X86_64Pc32
        } else if self.i386_pc32 == Some(kind) {
            GenericRelocationKind::I386Pc32
        } else {
            GenericRelocationKind::Unsupported(kind)
        }
    }
}

pub fn apply_relocation(
    memory: &mut [u8],
    relocation: &Relocation,
    kinds: &RelocationKinds,
    config: RelocationApplyConfig,
    resolver: &dyn SymbolResolver,
) -> Result<()> {
    let target_offset = relocation
        .offset
        .checked_sub(config.memory_base_vaddr)
        .ok_or_else(|| LoaderError::Link("relocation target precedes mapped image base".into()))?;
    let current = read_word_at(memory, target_offset, config)?;
    let target_address = config.load_bias.wrapping_add(relocation.offset);

    let relocation_kind = kinds.classify(relocation.kind);

    match relocation_kind {
        GenericRelocationKind::None | GenericRelocationKind::Copy => Ok(()),
        GenericRelocationKind::IRelative => {
            let addend = if relocation.has_addend {
                relocation.addend as isize as usize
            } else {
                current
            };
            let resolver_address = config.load_bias.wrapping_add(addend);
            let value = resolver.resolve_ifunc(resolver_address)?;
            write_word_at(memory, target_offset, config, value)
        }
        GenericRelocationKind::Relative => {
            let addend = if relocation.has_addend {
                relocation.addend as isize as usize
            } else {
                current
            };
            write_word_at(
                memory,
                target_offset,
                config,
                config.load_bias.wrapping_add(addend),
            )
        }
        GenericRelocationKind::GlobDat | GenericRelocationKind::JumpSlot => {
            let value = match resolver.resolve(relocation.sym_idx)? {
                SymbolResolution::Resolved(address) => address,
                SymbolResolution::UnresolvedWeak => {
                    return write_word_at(
                        memory,
                        target_offset,
                        config,
                        weak_fallback_value(relocation_kind, relocation, current),
                    );
                }
            };
            write_word_at(
                memory,
                target_offset,
                config,
                value.wrapping_add(if relocation.has_addend {
                    relocation.addend as isize as usize
                } else {
                    0
                }),
            )
        }
        GenericRelocationKind::Absolute => {
            let value = match resolver.resolve(relocation.sym_idx)? {
                SymbolResolution::Resolved(address) => address,
                SymbolResolution::UnresolvedWeak => {
                    return write_word_at(
                        memory,
                        target_offset,
                        config,
                        weak_fallback_value(relocation_kind, relocation, current),
                    );
                }
            };
            let addend = if relocation.has_addend {
                relocation.addend as isize as usize
            } else {
                current
            };
            write_word_at(memory, target_offset, config, value.wrapping_add(addend))
        }
        GenericRelocationKind::X86_64_32 => {
            let value = match resolver.resolve(relocation.sym_idx)? {
                SymbolResolution::Resolved(address) => address,
                SymbolResolution::UnresolvedWeak => {
                    return write_word_at(
                        memory,
                        target_offset,
                        config,
                        weak_fallback_value(relocation_kind, relocation, current),
                    );
                }
            };
            write_word_at(
                memory,
                target_offset,
                config,
                value.wrapping_add(relocation.addend as isize as usize),
            )
        }
        GenericRelocationKind::X86_64Pc32 | GenericRelocationKind::I386Pc32 => {
            let value = match resolver.resolve(relocation.sym_idx)? {
                SymbolResolution::Resolved(address) => address,
                SymbolResolution::UnresolvedWeak => {
                    return write_word_at(
                        memory,
                        target_offset,
                        config,
                        weak_fallback_value(relocation_kind, relocation, current),
                    );
                }
            };
            let addend = if relocation.has_addend {
                relocation.addend as isize as usize
            } else {
                current
            };
            write_word_at(
                memory,
                target_offset,
                config,
                value.wrapping_add(addend).wrapping_sub(target_address),
            )
        }
        GenericRelocationKind::TlsDtpMod
        | GenericRelocationKind::TlsDtpRel
        | GenericRelocationKind::TlsTpRel
        | GenericRelocationKind::TlsDesc => Err(LoaderError::Link(
            "TLS relocation requires loader TLS context".into(),
        )),
        GenericRelocationKind::Unsupported(kind) => Err(LoaderError::Link(format!(
            "unsupported relocation type {kind}"
        ))),
    }
}

pub fn apply_relocation_with_tls(
    memory: &mut [u8],
    relocation: &Relocation,
    kinds: &RelocationKinds,
    config: RelocationApplyConfig,
    resolver: &mut dyn TlsRelocationContext,
) -> Result<()> {
    let relocation_kind = kinds.classify(relocation.kind);
    if !matches!(
        relocation_kind,
        GenericRelocationKind::TlsDtpMod
            | GenericRelocationKind::TlsDtpRel
            | GenericRelocationKind::TlsTpRel
            | GenericRelocationKind::TlsDesc
    ) {
        return apply_relocation(memory, relocation, kinds, config, resolver);
    }

    let target_offset = relocation
        .offset
        .checked_sub(config.memory_base_vaddr)
        .ok_or_else(|| LoaderError::Link("relocation target precedes mapped image base".into()))?;

    match relocation_kind {
        GenericRelocationKind::TlsDtpMod => {
            let module = match resolver.resolve_tls(relocation.sym_idx, relocation.addend)? {
                TlsSymbolResolution::Resolved { module, .. } => module,
                TlsSymbolResolution::UnresolvedWeak => 0,
            };
            write_word_at(memory, target_offset, config, module)
        }
        GenericRelocationKind::TlsDtpRel => {
            let offset = match resolver.resolve_tls(relocation.sym_idx, relocation.addend)? {
                TlsSymbolResolution::Resolved { offset, .. } => offset,
                TlsSymbolResolution::UnresolvedWeak => {
                    if relocation.has_addend {
                        relocation.addend as isize as usize
                    } else {
                        0
                    }
                }
            };
            write_word_at(memory, target_offset, config, offset)
        }
        GenericRelocationKind::TlsTpRel => {
            let value = match resolver.resolve_tls(relocation.sym_idx, relocation.addend)? {
                TlsSymbolResolution::Resolved { module, offset } => {
                    let index = TlsIndex { module, offset };
                    let addr = resolver.tls_get_addr(index).ok_or_else(|| {
                        LoaderError::Link("failed to resolve TLS address for TPREL".into())
                    })?;
                    (addr as usize).wrapping_sub(resolver.thread_pointer())
                }
                TlsSymbolResolution::UnresolvedWeak => 0,
            };
            write_word_at(memory, target_offset, config, value)
        }
        GenericRelocationKind::TlsDesc => {
            let desc_offset_end = target_offset
                .checked_add(config.word_size.saturating_mul(2))
                .ok_or_else(|| LoaderError::Link("TLSDESC relocation offset overflow".into()))?;
            if desc_offset_end > memory.len() {
                return Err(LoaderError::Link(
                    "TLSDESC relocation target out of bounds".into(),
                ));
            }

            match resolver.resolve_tls(relocation.sym_idx, relocation.addend)? {
                TlsSymbolResolution::Resolved { module, offset } => {
                    let index = resolver.allocate_tls_index(TlsIndex { module, offset })?;
                    write_word_at(
                        memory,
                        target_offset,
                        config,
                        dynamic_tls_resolver as *const () as usize,
                    )?;
                    write_word_at(
                        memory,
                        target_offset + config.word_size,
                        config,
                        index as usize,
                    )
                }
                TlsSymbolResolution::UnresolvedWeak => {
                    write_word_at(
                        memory,
                        target_offset,
                        config,
                        tlsdesc_resolver_unresolved_weak as *const () as usize,
                    )?;
                    write_word_at(
                        memory,
                        target_offset + config.word_size,
                        config,
                        relocation.addend as isize as usize,
                    )
                }
            }
        }
        _ => unreachable!("non-TLS relocation handled above"),
    }
}

pub fn apply_relr_offset(
    memory: &mut [u8],
    offset: usize,
    config: RelocationApplyConfig,
) -> Result<()> {
    let target_offset = offset
        .checked_sub(config.memory_base_vaddr)
        .ok_or_else(|| LoaderError::Link("relocation target precedes mapped image base".into()))?;
    let current = read_word_at(memory, target_offset, config)?;
    write_word_at(
        memory,
        target_offset,
        config,
        config.load_bias.wrapping_add(current),
    )
}

fn weak_fallback_value(
    kind: GenericRelocationKind,
    relocation: &Relocation,
    current: usize,
) -> usize {
    if kind == GenericRelocationKind::Absolute {
        if relocation.has_addend {
            relocation.addend as isize as usize
        } else {
            current
        }
    } else if relocation.has_addend {
        relocation.addend as isize as usize
    } else {
        0
    }
}

fn read_word_at(memory: &[u8], offset: usize, config: RelocationApplyConfig) -> Result<usize> {
    let end = offset
        .checked_add(config.word_size)
        .ok_or_else(|| LoaderError::Link("relocation offset overflow".into()))?;
    let bytes = memory
        .get(offset..end)
        .ok_or_else(|| LoaderError::Link("relocation target out of bounds".into()))?;

    match config.word_size {
        4 => {
            let mut array = [0u8; 4];
            array.copy_from_slice(bytes);
            Ok(if config.little_endian {
                u32::from_le_bytes(array) as usize
            } else {
                u32::from_be_bytes(array) as usize
            })
        }
        8 => {
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            let value = if config.little_endian {
                u64::from_le_bytes(array)
            } else {
                u64::from_be_bytes(array)
            };
            usize::try_from(value)
                .map_err(|_| LoaderError::Link("relocation word overflows usize".into()))
        }
        _ => Err(LoaderError::Link(format!(
            "unsupported relocation word size {}",
            config.word_size
        ))),
    }
}

fn write_word_at(
    memory: &mut [u8],
    offset: usize,
    config: RelocationApplyConfig,
    value: usize,
) -> Result<()> {
    let end = offset
        .checked_add(config.word_size)
        .ok_or_else(|| LoaderError::Link("relocation offset overflow".into()))?;
    let bytes = memory
        .get_mut(offset..end)
        .ok_or_else(|| LoaderError::Link("relocation target out of bounds".into()))?;

    match config.word_size {
        4 => {
            let encoded = if config.little_endian {
                (value as u32).to_le_bytes()
            } else {
                (value as u32).to_be_bytes()
            };
            bytes.copy_from_slice(&encoded);
            Ok(())
        }
        8 => {
            let encoded = if config.little_endian {
                (value as u64).to_le_bytes()
            } else {
                (value as u64).to_be_bytes()
            };
            bytes.copy_from_slice(&encoded);
            Ok(())
        }
        _ => Err(LoaderError::Link(format!(
            "unsupported relocation word size {}",
            config.word_size
        ))),
    }
}

unsafe extern "C" fn dynamic_tls_resolver(desc: *mut usize) -> usize {
    if desc.is_null() {
        return 0;
    }

    let index_ptr = unsafe { *desc.add(1) as *const TlsIndex };
    if index_ptr.is_null() {
        return 0;
    }

    let index = unsafe { *index_ptr };
    let Some(addr) = crate::soloader::tls::global_tls_registry().get_addr(index) else {
        return 0;
    };

    (addr as usize).wrapping_sub(platform_thread_pointer())
}

unsafe extern "C" fn tlsdesc_resolver_unresolved_weak(desc: *mut usize) -> usize {
    if desc.is_null() {
        return 0;
    }

    let addend = unsafe { *desc.add(1) };
    addend.wrapping_sub(platform_thread_pointer())
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
fn platform_thread_pointer() -> usize {
    let value: usize;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) value);
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c13, c0, 3", out(reg) value);
    }
    value
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
fn platform_thread_pointer() -> usize {
    0
}

pub fn decode_relr_offsets(entries: &[usize], word_size: usize) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut base_offset = 0usize;
    let bits_per_entry = word_size.saturating_mul(8);

    for &entry in entries {
        if entry & 1 == 0 {
            offsets.push(entry);
            base_offset = entry.saturating_add(word_size);
            continue;
        }

        let mut bitmap = entry >> 1;
        for bit in 0..bits_per_entry.saturating_sub(1) {
            if bitmap & 1 != 0 {
                offsets.push(base_offset.saturating_add(bit.saturating_mul(word_size)));
            }
            bitmap >>= 1;
            if bitmap == 0 {
                break;
            }
        }
        base_offset =
            base_offset.saturating_add(word_size.saturating_mul(bits_per_entry.saturating_sub(1)));
    }

    offsets
}

pub fn decode_android_packed_relocations(bytes: &[u8], is_rela: bool) -> Result<Vec<Relocation>> {
    if bytes.len() < 4 || &bytes[..4] != b"APS2" {
        return Err(LoaderError::InvalidElf(
            "invalid Android packed relocation magic".into(),
        ));
    }

    let mut decoder = Sleb128Decoder::new(&bytes[4..]);
    let num_relocs = decoder.decode()?;
    if num_relocs < 0 {
        return Err(LoaderError::InvalidElf(
            "negative packed relocation count".into(),
        ));
    }
    let num_relocs = num_relocs as u64;
    let mut relocations = Vec::with_capacity(num_relocs.min(usize::MAX as u64) as usize);

    let mut current_offset = decoder.decode()? as usize;
    let mut done = 0u64;
    while done < num_relocs {
        let group_size = decoder.decode()?;
        if group_size < 0 {
            return Err(LoaderError::InvalidElf(
                "negative packed relocation group size".into(),
            ));
        }
        let group_size = group_size as u64;
        let group_flags = decoder.decode()? as u64;

        let mut group_offset_delta = 0usize;
        if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA != 0 {
            group_offset_delta = decoder.decode()? as usize;
        }

        let mut shared_sym_idx = 0usize;
        let mut shared_kind = 0u32;
        if group_flags & RELOCATION_GROUPED_BY_INFO != 0 {
            let info = decoder.decode()? as u64;
            shared_sym_idx = (info >> 32) as usize;
            shared_kind = info as u32;
        }

        let is_rela_group = if is_rela {
            group_flags & (RELOCATION_GROUP_HAS_ADDEND | RELOCATION_GROUPED_BY_ADDEND)
        } else {
            if group_flags & RELOCATION_GROUP_HAS_ADDEND != 0 {
                return Err(LoaderError::InvalidElf(
                    "REL packed relocation group contains addend".into(),
                ));
            }
            0
        };

        let mut group_addend = 0i64;
        for _ in 0..group_size {
            if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA != 0 {
                current_offset = current_offset.saturating_add(group_offset_delta);
            } else {
                current_offset = current_offset.saturating_add(decoder.decode()? as usize);
            }

            let mut sym_idx = shared_sym_idx;
            let mut kind = shared_kind;
            if group_flags & RELOCATION_GROUPED_BY_INFO == 0 {
                let info = decoder.decode()? as u64;
                sym_idx = (info >> 32) as usize;
                kind = info as u32;
            }

            let mut addend = 0i64;
            let mut has_addend = false;
            if is_rela {
                has_addend = true;
                if is_rela_group & RELOCATION_GROUP_HAS_ADDEND != 0 {
                    group_addend = group_addend.saturating_add(decoder.decode()?);
                } else {
                    group_addend = 0;
                }
                addend = group_addend;
            }

            relocations.push(Relocation {
                sym_idx,
                kind,
                offset: current_offset,
                addend,
                has_addend,
            });
        }

        done = done.saturating_add(group_size);
    }

    Ok(relocations)
}
