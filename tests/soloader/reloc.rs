use espframe::soloader::reloc::{
    apply_relocation, apply_relocation_with_tls, decode_android_packed_relocations,
    decode_relr_offsets, GenericRelocationKind, Relocation, RelocationApplyConfig, RelocationKinds,
    SymbolResolution, SymbolResolver, TlsRelocationContext, TlsSymbolResolution,
    RELOCATION_GROUPED_BY_ADDEND, RELOCATION_GROUPED_BY_INFO, RELOCATION_GROUPED_BY_OFFSET_DELTA,
    RELOCATION_GROUP_HAS_ADDEND,
};
use espframe::soloader::tls::TlsIndex;
use espframe::soloader::Result;

#[test]
fn x86_64_relocation_kinds_match_c_generic_mapping() {
    let kinds = RelocationKinds::for_machine(goblin::elf::header::EM_X86_64).unwrap();

    assert_eq!(kinds.classify(8), GenericRelocationKind::Relative);
    assert_eq!(kinds.classify(6), GenericRelocationKind::GlobDat);
    assert_eq!(kinds.classify(7), GenericRelocationKind::JumpSlot);
    assert_eq!(kinds.classify(1), GenericRelocationKind::Absolute);
    assert_eq!(kinds.classify(37), GenericRelocationKind::IRelative);
    assert_eq!(kinds.classify(16), GenericRelocationKind::TlsDtpMod);
    assert_eq!(kinds.classify(17), GenericRelocationKind::TlsDtpRel);
    assert_eq!(kinds.classify(18), GenericRelocationKind::TlsTpRel);
    assert_eq!(kinds.classify(36), GenericRelocationKind::TlsDesc);
}

#[test]
fn relr_bitmap_entries_expand_from_previous_direct_relocation() {
    let offsets = decode_relr_offsets(&[0x20, 0b1011], 8);

    assert_eq!(offsets, vec![0x20, 0x28, 0x38]);
}

#[test]
fn android_packed_rela_uses_cumulative_offsets_and_addends() {
    let mut bytes = b"APS2".to_vec();
    push_sleb(&mut bytes, 2);
    push_sleb(&mut bytes, 0x100);
    push_sleb(&mut bytes, 2);
    push_sleb(
        &mut bytes,
        (RELOCATION_GROUPED_BY_INFO
            | RELOCATION_GROUPED_BY_OFFSET_DELTA
            | RELOCATION_GROUPED_BY_ADDEND
            | RELOCATION_GROUP_HAS_ADDEND) as i64,
    );
    push_sleb(&mut bytes, 8);
    push_sleb(&mut bytes, (3i64 << 32) | 8);
    push_sleb(&mut bytes, 4);
    push_sleb(&mut bytes, 5);

    let relocs = decode_android_packed_relocations(&bytes, true).unwrap();

    assert_eq!(
        relocs,
        vec![
            Relocation {
                sym_idx: 3,
                kind: 8,
                offset: 0x108,
                addend: 4,
                has_addend: true,
            },
            Relocation {
                sym_idx: 3,
                kind: 8,
                offset: 0x110,
                addend: 9,
                has_addend: true,
            },
        ]
    );
}

#[test]
fn android_packed_relocations_reject_negative_count() {
    let mut bytes = b"APS2".to_vec();
    push_sleb(&mut bytes, -1);
    assert!(decode_android_packed_relocations(&bytes, true).is_err());
}

#[test]
fn android_packed_rela_per_relocation_addends_are_cumulative() {
    let mut bytes = b"APS2".to_vec();
    push_sleb(&mut bytes, 2);
    push_sleb(&mut bytes, 0x100);
    push_sleb(&mut bytes, 2);
    push_sleb(
        &mut bytes,
        (RELOCATION_GROUPED_BY_INFO
            | RELOCATION_GROUPED_BY_OFFSET_DELTA
            | RELOCATION_GROUP_HAS_ADDEND) as i64,
    );
    push_sleb(&mut bytes, 8);
    push_sleb(&mut bytes, (3i64 << 32) | 8);
    push_sleb(&mut bytes, 4);
    push_sleb(&mut bytes, 5);

    let relocs = decode_android_packed_relocations(&bytes, true).unwrap();

    assert_eq!(
        relocs,
        vec![
            Relocation {
                sym_idx: 3,
                kind: 8,
                offset: 0x108,
                addend: 4,
                has_addend: true,
            },
            Relocation {
                sym_idx: 3,
                kind: 8,
                offset: 0x110,
                addend: 9,
                has_addend: true,
            },
        ]
    );
}

#[test]
fn apply_relocation_matches_c_address_semantics() {
    let kinds = RelocationKinds::for_machine(goblin::elf::header::EM_X86_64).unwrap();
    let config = RelocationApplyConfig {
        load_bias: 0x1000,
        memory_base_vaddr: 0,
        word_size: 8,
        little_endian: true,
    };
    let resolver = FakeResolver {
        symbol_address: 0x2000,
    };
    let mut memory = vec![0u8; 0x80];

    write_word(&mut memory, 0x10, 8, true, 0x22);
    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 0,
            kind: 8,
            offset: 0x10,
            addend: 0,
            has_addend: false,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x10, 8, true), 0x1022);

    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 6,
            offset: 0x18,
            addend: 5,
            has_addend: true,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x18, 8, true), 0x2005);

    write_word(&mut memory, 0x20, 8, true, 3);
    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 1,
            offset: 0x20,
            addend: 0,
            has_addend: false,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x20, 8, true), 0x2003);

    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 2,
            offset: 0x30,
            addend: -4,
            has_addend: true,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x30, 8, true), 0x0fcc);
}

#[test]
fn apply_irelative_calls_resolver_and_writes_result() {
    let kinds = RelocationKinds::for_machine(goblin::elf::header::EM_X86_64).unwrap();
    let config = RelocationApplyConfig {
        load_bias: 0x1000,
        memory_base_vaddr: 0,
        word_size: 8,
        little_endian: true,
    };
    let resolver = IfuncResolver;
    let mut memory = vec![0u8; 0x40];

    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 0,
            kind: 37,
            offset: 0x10,
            addend: 0x20,
            has_addend: true,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();

    assert_eq!(read_word(&memory, 0x10, 8, true), 0x3020);
}

#[test]
fn apply_relocation_uses_c_weak_fallbacks() {
    let kinds = RelocationKinds::for_machine(goblin::elf::header::EM_X86_64).unwrap();
    let config = RelocationApplyConfig {
        load_bias: 0x1000,
        memory_base_vaddr: 0,
        word_size: 8,
        little_endian: true,
    };
    let resolver = WeakResolver;
    let mut memory = vec![0u8; 0x40];

    write_word(&mut memory, 0x10, 8, true, 0x55);
    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 1,
            offset: 0x10,
            addend: 0,
            has_addend: false,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x10, 8, true), 0x55);

    apply_relocation(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 7,
            offset: 0x18,
            addend: 9,
            has_addend: true,
        },
        &kinds,
        config,
        &resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x18, 8, true), 9);
}

#[test]
fn apply_tls_relocations_write_module_offsets_and_descriptors() {
    let kinds = RelocationKinds::for_machine(goblin::elf::header::EM_X86_64).unwrap();
    let config = RelocationApplyConfig {
        load_bias: 0x1000,
        memory_base_vaddr: 0,
        word_size: 8,
        little_endian: true,
    };
    let mut resolver = FakeTlsResolver {
        module: 7,
        offset: 0x44,
        allocated: Vec::new(),
    };
    let mut memory = vec![0u8; 0x50];

    apply_relocation_with_tls(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 16,
            offset: 0x10,
            addend: 4,
            has_addend: true,
        },
        &kinds,
        config,
        &mut resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x10, 8, true), 7);

    apply_relocation_with_tls(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 17,
            offset: 0x18,
            addend: 4,
            has_addend: true,
        },
        &kinds,
        config,
        &mut resolver,
    )
    .unwrap();
    assert_eq!(read_word(&memory, 0x18, 8, true), 0x48);

    apply_relocation_with_tls(
        &mut memory,
        &Relocation {
            sym_idx: 1,
            kind: 36,
            offset: 0x20,
            addend: 4,
            has_addend: true,
        },
        &kinds,
        config,
        &mut resolver,
    )
    .unwrap();
    assert_ne!(read_word(&memory, 0x20, 8, true), 0);
    assert_ne!(read_word(&memory, 0x28, 8, true), 0);
    assert_eq!(
        resolver.allocated,
        vec![TlsIndex {
            module: 7,
            offset: 0x48
        }]
    );
}

struct FakeResolver {
    symbol_address: usize,
}

impl SymbolResolver for FakeResolver {
    fn resolve(&self, _sym_idx: usize) -> Result<SymbolResolution> {
        Ok(SymbolResolution::Resolved(self.symbol_address))
    }
}

struct WeakResolver;

impl SymbolResolver for WeakResolver {
    fn resolve(&self, _sym_idx: usize) -> Result<SymbolResolution> {
        Ok(SymbolResolution::UnresolvedWeak)
    }
}

struct IfuncResolver;

impl SymbolResolver for IfuncResolver {
    fn resolve(&self, _sym_idx: usize) -> Result<SymbolResolution> {
        Ok(SymbolResolution::Resolved(0))
    }

    fn resolve_ifunc(&self, address: usize) -> Result<usize> {
        Ok(address + 0x2000)
    }
}

struct FakeTlsResolver {
    module: usize,
    offset: usize,
    allocated: Vec<TlsIndex>,
}

impl SymbolResolver for FakeTlsResolver {
    fn resolve(&self, _sym_idx: usize) -> Result<SymbolResolution> {
        Ok(SymbolResolution::Resolved(0))
    }
}

impl TlsRelocationContext for FakeTlsResolver {
    fn resolve_tls(&self, _sym_idx: usize, addend: i64) -> Result<TlsSymbolResolution> {
        Ok(TlsSymbolResolution::Resolved {
            module: self.module,
            offset: self.offset.wrapping_add(addend as isize as usize),
        })
    }

    fn allocate_tls_index(&mut self, index: TlsIndex) -> Result<*mut TlsIndex> {
        self.allocated.push(index);
        Ok(self.allocated.last_mut().unwrap() as *mut TlsIndex)
    }
}

fn read_word(bytes: &[u8], offset: usize, word_size: usize, little_endian: bool) -> usize {
    match word_size {
        4 => {
            let mut array = [0u8; 4];
            array.copy_from_slice(&bytes[offset..offset + 4]);
            if little_endian {
                u32::from_le_bytes(array) as usize
            } else {
                u32::from_be_bytes(array) as usize
            }
        }
        8 => {
            let mut array = [0u8; 8];
            array.copy_from_slice(&bytes[offset..offset + 8]);
            if little_endian {
                u64::from_le_bytes(array) as usize
            } else {
                u64::from_be_bytes(array) as usize
            }
        }
        _ => unreachable!(),
    }
}

fn write_word(
    bytes: &mut [u8],
    offset: usize,
    word_size: usize,
    little_endian: bool,
    value: usize,
) {
    match word_size {
        4 => {
            let encoded = if little_endian {
                (value as u32).to_le_bytes()
            } else {
                (value as u32).to_be_bytes()
            };
            bytes[offset..offset + 4].copy_from_slice(&encoded);
        }
        8 => {
            let encoded = if little_endian {
                (value as u64).to_le_bytes()
            } else {
                (value as u64).to_be_bytes()
            };
            bytes[offset..offset + 8].copy_from_slice(&encoded);
        }
        _ => unreachable!(),
    }
}

fn push_sleb(bytes: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = (value as u8) & 0x7f;
        value >>= 7;
        let done = (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0);
        bytes.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}
