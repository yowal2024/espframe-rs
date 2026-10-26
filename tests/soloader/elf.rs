use espframe::soloader::elf::{elf_hash, gnu_hash, ElfImage};
use espframe::soloader::reloc::Relocation;

#[test]
fn elf_hashes_match_loader_algorithms() {
    assert_eq!(elf_hash("printf"), 0x077905a6);
    assert_eq!(gnu_hash("printf"), 0x156b2bb8);
}

#[test]
fn parse_rejects_invalid_magic() {
    let err = ElfImage::parse_memory("bad.so", &[0u8; 64], 0).unwrap_err();
    assert!(err.to_string().contains("invalid ELF"));
}

#[test]
fn parse_reads_needed_libraries_and_dynamic_symbols() {
    let bytes = synthetic_elf_with_dynsym();
    let img = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();

    assert_eq!(img.needed_libraries(), &["libdep.so"]);
    assert_eq!(img.machine(), goblin::elf::header::EM_X86_64);
    assert_eq!(img.word_size(), 8);
    assert!(img.is_little_endian());
    let sym = img.symbol_offset("shared_function", false).unwrap();
    assert_eq!(sym.value, 0x1234);
    assert_eq!(img.symbol_address("shared_function"), Some(0x7000_1234));
}

#[test]
fn parse_retains_runtime_tables_for_linking() {
    let bytes = synthetic_elf_with_runtime_metadata();
    let img = ElfImage::parse_memory("sample.so", &bytes, 0).unwrap();

    let tags: Vec<u64> = img
        .dynamic_entries()
        .iter()
        .map(|entry| entry.tag)
        .collect();
    assert_eq!(tags, vec![12, 25, 27, 26, 28, 13, 0]);

    assert_eq!(img.program_headers().len(), 4);
    assert_eq!(img.program_headers()[2].p_type, 7);
    assert_eq!(img.file_range_for_vaddr(0, 16), Some(0..16));
    assert_eq!(img.file_range_for_vaddr(0x3000, 16), None);

    let sym_img = ElfImage::parse_memory("symbols.so", &synthetic_elf_with_dynsym(), 0).unwrap();
    assert_eq!(sym_img.dynamic_symbol(1).unwrap().name, "shared_function");
}

#[test]
fn parse_reads_symtab_prefix_and_reverse_lookup() {
    let bytes = synthetic_elf_with_dynsym_and_symtab();
    let img = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();

    assert_eq!(img.symbol_address_by_prefix("main_"), Some(0x7000_4321));
    let resolved = img.get_symbol_for_address(0x7000_4324).unwrap();
    assert_eq!(resolved.name, "main_object");
    assert_eq!(resolved.address, 0x7000_4321);
}

#[test]
fn set_base_recomputes_cached_runtime_addresses() {
    let bytes = synthetic_elf_with_runtime_metadata();
    let mut img = ElfImage::parse_memory("sample.so", &bytes, 0).unwrap();

    assert_eq!(img.init(), Some(0x1110));
    assert_eq!(img.init_array().unwrap().address, 0x1200);
    assert_eq!(img.tls().unwrap().address, 0x2000);
    assert_eq!(img.eh_frame_hdr().unwrap().address, 0x3000);

    img.set_base(0x7000_0000);

    assert_eq!(img.init(), Some(0x7000_1110));
    assert_eq!(img.init_array().unwrap().address, 0x7000_1200);
    assert_eq!(img.tls().unwrap().address, 0x7000_2000);
    assert_eq!(img.eh_frame_hdr().unwrap().address, 0x7000_3000);
}

#[test]
fn parse_retains_relocation_tables_for_linking() {
    let bytes = synthetic_elf_with_relocations();
    let img = ElfImage::parse_memory("relocs.so", &bytes, 0).unwrap();

    assert_eq!(
        img.rela_relocations(),
        &[Relocation {
            sym_idx: 1,
            kind: 1,
            offset: 0x300,
            addend: 7,
            has_addend: true,
        }]
    );
    assert_eq!(
        img.rel_relocations(),
        &[Relocation {
            sym_idx: 1,
            kind: 6,
            offset: 0x318,
            addend: 0,
            has_addend: false,
        }]
    );
    assert_eq!(
        img.plt_relocations(),
        &[Relocation {
            sym_idx: 1,
            kind: 7,
            offset: 0x330,
            addend: 11,
            has_addend: true,
        }]
    );
    assert_eq!(img.relr_offsets(), &[0x500, 0x508]);

    let android = img.android_relocations().unwrap();
    assert!(android.is_rela);
    assert_eq!(
        android.relocations,
        vec![
            Relocation {
                sym_idx: 1,
                kind: 8,
                offset: 0x608,
                addend: 3,
                has_addend: true,
            },
            Relocation {
                sym_idx: 1,
                kind: 8,
                offset: 0x610,
                addend: 7,
                has_addend: true,
            },
        ]
    );
}

fn synthetic_elf_with_dynsym() -> Vec<u8> {
    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const SHDR_SIZE: usize = 64;
    const SYM_SIZE: usize = 24;
    const DYN_SIZE: usize = 16;

    let dynstr = b"\0shared_function\0libdep.so\0";
    let shared_name = 1u32;
    let needed_name = 17u64;
    let shstr = b"\0.dynsym\0.dynstr\0.hash\0.dynamic\0.shstrtab\0";

    let phoff = EHDR_SIZE;
    let dynsym_off = align(phoff + (PHDR_SIZE * 2), 8);
    let dynstr_off = align(dynsym_off + (SYM_SIZE * 2), 8);
    let hash_off = align(dynstr_off + dynstr.len(), 8);
    let dynamic_off = align(hash_off + 16, 8);
    let shstr_off = align(dynamic_off + (DYN_SIZE * 6), 8);
    let shoff = align(shstr_off + shstr.len(), 8);
    let size = shoff + (SHDR_SIZE * 6);

    let mut bytes = vec![0u8; size];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, phoff as u64);
    put_u64(&mut bytes, 40, shoff as u64);
    put_u16(&mut bytes, 52, EHDR_SIZE as u16);
    put_u16(&mut bytes, 54, PHDR_SIZE as u16);
    put_u16(&mut bytes, 56, 2);
    put_u16(&mut bytes, 58, SHDR_SIZE as u16);
    put_u16(&mut bytes, 60, 6);
    put_u16(&mut bytes, 62, 5);

    put_sym(
        &mut bytes,
        dynsym_off + SYM_SIZE,
        shared_name,
        0x12,
        1,
        0x1234,
        16,
    );
    bytes[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr);
    put_u32(&mut bytes, hash_off, 1);
    put_u32(&mut bytes, hash_off + 4, 2);
    put_u32(&mut bytes, hash_off + 8, 1);
    put_u32(&mut bytes, hash_off + 12, 0);
    put_dyn(&mut bytes, dynamic_off, 1, needed_name);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE, 5, dynstr_off as u64);
    put_dyn(
        &mut bytes,
        dynamic_off + DYN_SIZE * 2,
        10,
        dynstr.len() as u64,
    );
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 3, 6, dynsym_off as u64);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 4, 11, SYM_SIZE as u64);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 5, 4, hash_off as u64);
    bytes[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    put_phdr(&mut bytes, phoff, 1, 5, 0, 0, size as u64, size as u64, 8);
    put_phdr(
        &mut bytes,
        phoff + PHDR_SIZE,
        2,
        4,
        dynamic_off as u64,
        dynamic_off as u64,
        (DYN_SIZE * 6) as u64,
        (DYN_SIZE * 6) as u64,
        8,
    );

    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE,
        1,
        11,
        dynsym_off,
        SYM_SIZE * 2,
        2,
        SYM_SIZE,
    );
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 2,
        9,
        3,
        dynstr_off,
        dynstr.len(),
        0,
        1,
    );
    put_shdr(&mut bytes, shoff + SHDR_SIZE * 3, 17, 5, hash_off, 16, 0, 4);
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 4,
        23,
        6,
        dynamic_off,
        DYN_SIZE * 2,
        2,
        DYN_SIZE,
    );
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 5,
        32,
        3,
        shstr_off,
        shstr.len(),
        0,
        1,
    );

    bytes
}

fn synthetic_elf_with_dynsym_and_symtab() -> Vec<u8> {
    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const SHDR_SIZE: usize = 64;
    const SYM_SIZE: usize = 24;
    const DYN_SIZE: usize = 16;

    let dynstr = b"\0shared_function\0libdep.so\0";
    let strtab = b"\0main_object\0";
    let shared_name = 1u32;
    let needed_name = 17u64;
    let main_name = 1u32;
    let shstr = b"\0.dynsym\0.dynstr\0.hash\0.dynamic\0.symtab\0.strtab\0.shstrtab\0";

    let phoff = EHDR_SIZE;
    let dynsym_off = align(phoff + (PHDR_SIZE * 2), 8);
    let dynstr_off = align(dynsym_off + (SYM_SIZE * 2), 8);
    let hash_off = align(dynstr_off + dynstr.len(), 8);
    let dynamic_off = align(hash_off + 16, 8);
    let symtab_off = align(dynamic_off + (DYN_SIZE * 6), 8);
    let strtab_off = align(symtab_off + (SYM_SIZE * 2), 8);
    let shstr_off = align(strtab_off + strtab.len(), 8);
    let shoff = align(shstr_off + shstr.len(), 8);
    let size = shoff + (SHDR_SIZE * 8);

    let mut bytes = vec![0u8; size];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, phoff as u64);
    put_u64(&mut bytes, 40, shoff as u64);
    put_u16(&mut bytes, 52, EHDR_SIZE as u16);
    put_u16(&mut bytes, 54, PHDR_SIZE as u16);
    put_u16(&mut bytes, 56, 2);
    put_u16(&mut bytes, 58, SHDR_SIZE as u16);
    put_u16(&mut bytes, 60, 8);
    put_u16(&mut bytes, 62, 7);

    put_sym(
        &mut bytes,
        dynsym_off + SYM_SIZE,
        shared_name,
        0x12,
        1,
        0x1234,
        16,
    );
    put_sym(
        &mut bytes,
        symtab_off + SYM_SIZE,
        main_name,
        0x11,
        1,
        0x4321,
        8,
    );

    bytes[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr);
    bytes[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);

    put_u32(&mut bytes, hash_off, 1);
    put_u32(&mut bytes, hash_off + 4, 2);
    put_u32(&mut bytes, hash_off + 8, 1);
    put_u32(&mut bytes, hash_off + 12, 0);
    put_dyn(&mut bytes, dynamic_off, 1, needed_name);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE, 5, dynstr_off as u64);
    put_dyn(
        &mut bytes,
        dynamic_off + DYN_SIZE * 2,
        10,
        dynstr.len() as u64,
    );
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 3, 6, dynsym_off as u64);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 4, 11, SYM_SIZE as u64);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 5, 4, hash_off as u64);
    bytes[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    put_phdr(&mut bytes, phoff, 1, 5, 0, 0, size as u64, size as u64, 8);
    put_phdr(
        &mut bytes,
        phoff + PHDR_SIZE,
        2,
        4,
        dynamic_off as u64,
        dynamic_off as u64,
        (DYN_SIZE * 6) as u64,
        (DYN_SIZE * 6) as u64,
        8,
    );

    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE,
        1,
        11,
        dynsym_off,
        SYM_SIZE * 2,
        2,
        SYM_SIZE,
    );
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 2,
        9,
        3,
        dynstr_off,
        dynstr.len(),
        0,
        1,
    );
    put_shdr(&mut bytes, shoff + SHDR_SIZE * 3, 17, 5, hash_off, 16, 0, 4);
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 4,
        23,
        6,
        dynamic_off,
        DYN_SIZE * 6,
        2,
        DYN_SIZE,
    );
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 5,
        32,
        2,
        symtab_off,
        SYM_SIZE * 2,
        6,
        SYM_SIZE,
    );
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 6,
        40,
        3,
        strtab_off,
        strtab.len(),
        0,
        1,
    );
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 7,
        48,
        3,
        shstr_off,
        shstr.len(),
        0,
        1,
    );

    bytes
}

fn synthetic_elf_with_runtime_metadata() -> Vec<u8> {
    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const SHDR_SIZE: usize = 64;
    const DYN_SIZE: usize = 16;

    let shstr = b"\0.dynamic\0.eh_frame_hdr\0.shstrtab\0";
    let phoff = EHDR_SIZE;
    let dynamic_off = align(phoff + (PHDR_SIZE * 4), 8);
    let shstr_off = align(dynamic_off + (DYN_SIZE * 7), 8);
    let shoff = align(shstr_off + shstr.len(), 8);
    let size = shoff + (SHDR_SIZE * 4);

    let mut bytes = vec![0u8; size];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, phoff as u64);
    put_u64(&mut bytes, 40, shoff as u64);
    put_u16(&mut bytes, 52, EHDR_SIZE as u16);
    put_u16(&mut bytes, 54, PHDR_SIZE as u16);
    put_u16(&mut bytes, 56, 4);
    put_u16(&mut bytes, 58, SHDR_SIZE as u16);
    put_u16(&mut bytes, 60, 4);
    put_u16(&mut bytes, 62, 3);

    put_dyn(&mut bytes, dynamic_off, 12, 0x1110);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE, 25, 0x1200);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 2, 27, 16);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 3, 26, 0x1300);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 4, 28, 8);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 5, 13, 0x1400);
    put_dyn(&mut bytes, dynamic_off + DYN_SIZE * 6, 0, 0);
    bytes[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    put_phdr(&mut bytes, phoff, 1, 5, 0, 0, size as u64, 0x4000, 8);
    put_phdr(
        &mut bytes,
        phoff + PHDR_SIZE,
        2,
        4,
        dynamic_off as u64,
        dynamic_off as u64,
        (DYN_SIZE * 7) as u64,
        (DYN_SIZE * 7) as u64,
        8,
    );
    put_phdr(
        &mut bytes,
        phoff + PHDR_SIZE * 2,
        7,
        4,
        0,
        0x2000,
        16,
        32,
        16,
    );
    put_phdr(
        &mut bytes,
        phoff + PHDR_SIZE * 3,
        0x6474_e550,
        4,
        0,
        0x3000,
        32,
        32,
        4,
    );

    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE,
        1,
        6,
        dynamic_off,
        DYN_SIZE * 7,
        0,
        DYN_SIZE,
    );
    put_shdr(&mut bytes, shoff + SHDR_SIZE * 2, 10, 1, 0, 32, 0, 1);
    put_u64(&mut bytes, shoff + SHDR_SIZE * 2 + 16, 0x3000);
    put_shdr(
        &mut bytes,
        shoff + SHDR_SIZE * 3,
        24,
        3,
        shstr_off,
        shstr.len(),
        0,
        1,
    );

    bytes
}

fn synthetic_elf_with_relocations() -> Vec<u8> {
    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const SYM_SIZE: usize = 24;
    const DYN_SIZE: usize = 16;
    const REL_SIZE: usize = 16;
    const RELA_SIZE: usize = 24;

    const DT_PLTRELSZ: i64 = 2;
    const DT_STRTAB: i64 = 5;
    const DT_SYMTAB: i64 = 6;
    const DT_RELA: i64 = 7;
    const DT_RELASZ: i64 = 8;
    const DT_RELAENT: i64 = 9;
    const DT_STRSZ: i64 = 10;
    const DT_SYMENT: i64 = 11;
    const DT_REL: i64 = 17;
    const DT_RELSZ: i64 = 18;
    const DT_RELENT: i64 = 19;
    const DT_PLTREL: i64 = 20;
    const DT_JMPREL: i64 = 23;
    const DT_RELRSZ: i64 = 35;
    const DT_RELR: i64 = 36;
    const DT_RELRENT: i64 = 37;
    const DT_ANDROID_RELA: i64 = 0x6000_0011;
    const DT_ANDROID_RELASZ: i64 = 0x6000_0012;

    let phoff = EHDR_SIZE;
    let dynsym_off = align(phoff + (PHDR_SIZE * 2), 8);
    let dynstr = b"\0reloc_symbol\0";
    let dynstr_off = align(dynsym_off + (SYM_SIZE * 2), 8);
    let rela_off = align(dynstr_off + dynstr.len(), 8);
    let rel_off = align(rela_off + RELA_SIZE, 8);
    let plt_off = align(rel_off + REL_SIZE, 8);
    let relr_off = align(plt_off + RELA_SIZE, 8);
    let mut android = b"APS2".to_vec();
    push_sleb(&mut android, 2);
    push_sleb(&mut android, 0x600);
    push_sleb(&mut android, 2);
    push_sleb(
        &mut android,
        (espframe::soloader::reloc::RELOCATION_GROUPED_BY_INFO
            | espframe::soloader::reloc::RELOCATION_GROUPED_BY_OFFSET_DELTA
            | espframe::soloader::reloc::RELOCATION_GROUPED_BY_ADDEND
            | espframe::soloader::reloc::RELOCATION_GROUP_HAS_ADDEND) as i64,
    );
    push_sleb(&mut android, 8);
    push_sleb(&mut android, (1i64 << 32) | 8);
    push_sleb(&mut android, 3);
    push_sleb(&mut android, 4);
    let android_off = align(relr_off + 16, 8);
    let dynamic_off = align(android_off + android.len(), 8);
    let dynamic_count = 19;
    let size = align(dynamic_off + (DYN_SIZE * dynamic_count), 8);

    let mut bytes = vec![0u8; size];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, phoff as u64);
    put_u16(&mut bytes, 52, EHDR_SIZE as u16);
    put_u16(&mut bytes, 54, PHDR_SIZE as u16);
    put_u16(&mut bytes, 56, 2);
    put_u16(&mut bytes, 58, 64);

    put_sym(&mut bytes, dynsym_off + SYM_SIZE, 1, 0x12, 1, 0x700, 16);
    bytes[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr);

    put_rela(&mut bytes, rela_off, 0x300, 1, 1, 7);
    put_rel(&mut bytes, rel_off, 0x318, 1, 6);
    put_rela(&mut bytes, plt_off, 0x330, 1, 7, 11);
    put_u64(&mut bytes, relr_off, 0x500);
    put_u64(&mut bytes, relr_off + 8, 0b11);
    bytes[android_off..android_off + android.len()].copy_from_slice(&android);

    put_phdr(&mut bytes, phoff, 1, 6, 0, 0, size as u64, size as u64, 8);
    put_phdr(
        &mut bytes,
        phoff + PHDR_SIZE,
        2,
        4,
        dynamic_off as u64,
        dynamic_off as u64,
        (DYN_SIZE * dynamic_count) as u64,
        (DYN_SIZE * dynamic_count) as u64,
        8,
    );

    let mut dyn_cursor = dynamic_off;
    for (tag, value) in [
        (DT_STRTAB, dynstr_off as u64),
        (DT_STRSZ, dynstr.len() as u64),
        (DT_SYMTAB, dynsym_off as u64),
        (DT_SYMENT, SYM_SIZE as u64),
        (DT_RELA, rela_off as u64),
        (DT_RELASZ, RELA_SIZE as u64),
        (DT_RELAENT, RELA_SIZE as u64),
        (DT_REL, rel_off as u64),
        (DT_RELSZ, REL_SIZE as u64),
        (DT_RELENT, REL_SIZE as u64),
        (DT_JMPREL, plt_off as u64),
        (DT_PLTRELSZ, RELA_SIZE as u64),
        (DT_PLTREL, DT_RELA as u64),
        (DT_RELR, relr_off as u64),
        (DT_RELRSZ, 16),
        (DT_RELRENT, 8),
        (DT_ANDROID_RELA, android_off as u64),
        (DT_ANDROID_RELASZ, android.len() as u64),
        (0, 0),
    ] {
        put_dyn(&mut bytes, dyn_cursor, tag, value);
        dyn_cursor += DYN_SIZE;
    }

    bytes
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
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

fn put_dyn(bytes: &mut [u8], offset: usize, tag: i64, value: u64) {
    put_u64(bytes, offset, tag as u64);
    put_u64(bytes, offset + 8, value);
}

fn put_rel(bytes: &mut [u8], offset: usize, r_offset: u64, sym_idx: u64, kind: u64) {
    put_u64(bytes, offset, r_offset);
    put_u64(bytes, offset + 8, (sym_idx << 32) | kind);
}

fn put_rela(bytes: &mut [u8], offset: usize, r_offset: u64, sym_idx: u64, kind: u64, addend: i64) {
    put_rel(bytes, offset, r_offset, sym_idx, kind);
    put_u64(bytes, offset + 16, addend as u64);
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
