use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use espframe::xdl::{
    find_loaded_module, resolve_dynamic_symbol, DynamicSymbol, Elf64Phdr, LoadedModuleSnapshot,
    XdlError,
};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Dyn {
    tag: i64,
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Sym {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

fn write_value<T: Copy>(image: &mut [u8], offset: usize, value: T) {
    assert!(offset + std::mem::size_of::<T>() <= image.len());
    unsafe {
        (image.as_mut_ptr().add(offset) as *mut T).write_unaligned(value);
    }
}

fn write_slice<T: Copy>(image: &mut [u8], offset: usize, values: &[T]) {
    for (index, value) in values.iter().copied().enumerate() {
        write_value(image, offset + index * std::mem::size_of::<T>(), value);
    }
}

static IFUNC_TARGET: AtomicUsize = AtomicUsize::new(0);
static IFUNC_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn ifunc_resolver() -> *mut core::ffi::c_void {
    IFUNC_CALLS.fetch_add(1, Ordering::Relaxed);
    IFUNC_TARGET.load(Ordering::Relaxed) as *mut core::ffi::c_void
}

fn write_sysv_symbol_fixture(image: &mut [u8], symbol_value: usize, symbol_size: usize) -> usize {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;

    let names = b"\0range_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                shndx: 1,
                value: symbol_value as u64,
                size: symbol_size as u64,
                ..Default::default()
            },
        ],
    );
    write_slice(image, HASH, &[1u32, 2, 1, 0, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(image, DYNAMIC, &dynamic);
    dynamic.len() * std::mem::size_of::<Dyn>()
}

#[test]
fn finds_loaded_soname_and_preserves_module_info() {
    let first = [Elf64Phdr {
        p_type: PT_LOAD,
        ..Default::default()
    }];
    let target = [Elf64Phdr {
        p_type: PT_DYNAMIC,
        ..Default::default()
    }];
    let modules = [
        LoadedModuleSnapshot::new(c"/system/lib64/libc.so", 0x1000, &first),
        LoadedModuleSnapshot::new(c"/system_ext/lib64/libsensorservice.so", 0x2200, &target),
    ];

    let found = find_loaded_module(c"libsensorservice.so", modules).unwrap();
    assert_eq!(found.pathname(), c"/system_ext/lib64/libsensorservice.so");
    assert_eq!(found.load_bias(), 0x2200);
    assert_eq!(found.program_headers().as_ptr(), target.as_ptr());
    assert_eq!(found.program_headers().len(), 1);
}

#[test]
fn soname_match_requires_a_complete_basename() {
    let phdrs = [Elf64Phdr::default()];
    let modules = [
        LoadedModuleSnapshot::new(c"/system/lib64/libevilfoo.so", 0x1000, &phdrs),
        LoadedModuleSnapshot::new(c"/system/lib64/foo.so", 0x2000, &phdrs),
    ];

    let found = find_loaded_module(c"foo.so", modules).unwrap();
    assert_eq!(found.pathname(), c"/system/lib64/foo.so");
    assert_eq!(found.load_bias(), 0x2000);
}

#[test]
fn absolute_request_does_not_match_a_different_directory() {
    let phdrs = [Elf64Phdr::default()];
    let modules = [LoadedModuleSnapshot::new(
        c"/vendor/lib64/libsame.so",
        0x1000,
        &phdrs,
    )];

    assert!(find_loaded_module(c"/system/lib64/libsame.so", modules).is_none());
}

#[test]
fn empty_basename_and_root_module_names_never_match() {
    let phdrs = [Elf64Phdr::default()];

    for (requested, loaded) in [
        (c"", c""),
        (c"/", c""),
        (c"", c"/"),
        (c"/", c"/"),
        (c"/system/lib64/", c"/system/lib64/"),
    ] {
        let modules = [LoadedModuleSnapshot::new(loaded, 0x1000, &phdrs)];
        assert!(
            find_loaded_module(requested, modules).is_none(),
            "unexpected match for requested={requested:?}, loaded={loaded:?}"
        );
    }
}

#[test]
fn resolves_exported_dynamic_symbol_through_sysv_hash() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;
    const SYMBOL_VALUE: usize = 0x700;

    let mut image = vec![0u8; 0x1000];
    let names = b"\0target_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    let symbols = [
        Sym::default(),
        Sym {
            name: 1,
            shndx: 1,
            value: SYMBOL_VALUE as u64,
            size: 24,
            ..Default::default()
        },
    ];
    write_slice(&mut image, SYMTAB, &symbols);

    // nbucket=1, nchain=2, bucket[0]=1, chain[0]=0, chain[1]=0.
    write_slice(&mut image, HASH, &[1u32, 2, 1, 0, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_SYMENT,
            value: std::mem::size_of::<Sym>() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);

    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_vaddr: 0,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];
    let base = image.as_ptr() as usize;
    let symbol = unsafe { resolve_dynamic_symbol(base, &phdrs, c"target_symbol") }.unwrap();

    assert_eq!(symbol.address, base + SYMBOL_VALUE);
    assert_eq!(symbol.size, 24);
}

#[test]
fn sysv_hash_collision_skips_nonmatching_tls_symbol() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;
    const SYMBOL_VALUE: usize = 0x700;

    let mut image = vec![0u8; 0x1000];
    let names = b"\0tls_collision\0target_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                info: 6,
                shndx: 1,
                value: 0x680,
                ..Default::default()
            },
            Sym {
                name: 15,
                shndx: 1,
                value: SYMBOL_VALUE as u64,
                size: 16,
                ..Default::default()
            },
        ],
    );
    // One bucket forces both symbols into the requested name's bucket.
    write_slice(&mut image, HASH, &[1u32, 3, 1, 0, 2, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];
    let base = image.as_ptr() as usize;

    assert_eq!(
        unsafe { resolve_dynamic_symbol(base, &phdrs, c"target_symbol") },
        Ok(DynamicSymbol {
            address: base + SYMBOL_VALUE,
            size: 16,
        })
    );
}

#[test]
fn resolves_exported_dynamic_symbol_through_gnu_hash() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;
    const SYMBOL_VALUE: usize = 0x680;

    let mut image = vec![0u8; 0x1000];
    let names = b"\0gnu_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                shndx: 1,
                value: SYMBOL_VALUE as u64,
                size: 8,
                ..Default::default()
            },
        ],
    );

    let hash = b"gnu_symbol".iter().fold(5381u32, |value, byte| {
        value.wrapping_mul(33).wrapping_add(u32::from(*byte))
    });
    // nbuckets=1, symoffset=1, bloom_size=1, bloom_shift=5.
    write_slice(&mut image, HASH, &[1u32, 1, 1, 5]);
    write_value(&mut image, HASH + 16, u64::MAX);
    write_value(&mut image, HASH + 24, 1u32);
    write_value(&mut image, HASH + 28, hash | 1);

    let dynamic = [
        Dyn {
            tag: DT_GNU_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];
    let base = image.as_ptr() as usize;
    let symbol = unsafe { resolve_dynamic_symbol(base, &phdrs, c"gnu_symbol") }.unwrap();

    assert_eq!(symbol.address, base + SYMBOL_VALUE);
    assert_eq!(symbol.size, 8);
}

#[test]
fn gnu_hash_collision_skips_nonmatching_ifunc_symbol() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;
    const SYMBOL_VALUE: usize = 0x700;
    const COLLISION_HASH: u32 = 0x98c6_9b8f;

    let mut image = vec![0u8; 0x1000];
    // GNU hash("sym_0000r") == GNU hash("sym_00020").
    let names = b"\0sym_0000r\0sym_00020\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                info: 10,
                shndx: 1,
                value: 0x680,
                ..Default::default()
            },
            Sym {
                name: 11,
                shndx: 1,
                value: SYMBOL_VALUE as u64,
                size: 8,
                ..Default::default()
            },
        ],
    );
    // nbuckets=1, symoffset=1, bloom_size=1, bloom_shift=5.
    write_slice(&mut image, HASH, &[1u32, 1, 1, 5]);
    write_value(&mut image, HASH + 16, u64::MAX);
    write_value(&mut image, HASH + 24, 1u32);
    write_slice(
        &mut image,
        HASH + 28,
        &[COLLISION_HASH & !1, COLLISION_HASH | 1],
    );
    let dynamic = [
        Dyn {
            tag: DT_GNU_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];
    let base = image.as_ptr() as usize;

    assert_eq!(
        unsafe { resolve_dynamic_symbol(base, &phdrs, c"sym_00020") },
        Ok(DynamicSymbol {
            address: base + SYMBOL_VALUE,
            size: 8,
        })
    );
}

#[test]
fn rejects_gnu_hash_bloom_shift_outside_u32_width() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;

    let mut image = vec![0u8; 0x800];
    let names = b"\0gnu_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_value(&mut image, SYMTAB, Sym::default());

    // nbuckets=1, symoffset=1, bloom_size=1, bloom_shift=32.
    write_slice(&mut image, HASH, &[1u32, 1, 1, 32]);
    write_value(&mut image, HASH + 16, u64::MAX);

    let dynamic = [
        Dyn {
            tag: DT_GNU_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];

    assert_eq!(
        unsafe { resolve_dynamic_symbol(image.as_ptr() as usize, &phdrs, c"gnu_symbol") },
        Err(XdlError::MalformedElf)
    );
}

#[test]
fn rejects_nonzero_symbol_spanning_adjacent_load_segments() {
    const DYNAMIC: usize = 0x100;
    const SEGMENT_BOUNDARY: usize = 0x800;
    const SYMBOL_VALUE: usize = SEGMENT_BOUNDARY - 8;

    let mut image = vec![0u8; 0x1000];
    let dynamic_size = write_sysv_symbol_fixture(&mut image, SYMBOL_VALUE, 16);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: SEGMENT_BOUNDARY as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_LOAD,
            p_vaddr: SEGMENT_BOUNDARY as u64,
            p_memsz: (image.len() - SEGMENT_BOUNDARY) as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: dynamic_size as u64,
            ..Default::default()
        },
    ];

    assert_eq!(
        unsafe { resolve_dynamic_symbol(image.as_ptr() as usize, &phdrs, c"range_symbol") },
        Err(XdlError::MalformedElf)
    );
}

#[test]
fn rejects_nonzero_symbol_range_end_overflow() {
    const DYNAMIC: usize = 0x100;

    let mut image = vec![0u8; 0x800];
    let base = image.as_ptr() as usize;
    let symbol_value = usize::MAX - base - 4;
    let dynamic_size = write_sysv_symbol_fixture(&mut image, symbol_value, 8);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_LOAD,
            p_vaddr: symbol_value as u64,
            p_memsz: 4,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: dynamic_size as u64,
            ..Default::default()
        },
    ];

    assert_eq!(
        unsafe { resolve_dynamic_symbol(base, &phdrs, c"range_symbol") },
        Err(XdlError::MalformedElf)
    );
}

#[test]
fn accepts_zero_size_symbol_at_the_end_of_a_load_segment() {
    const DYNAMIC: usize = 0x100;

    let mut image = vec![0u8; 0x800];
    let symbol_value = image.len() - 1;
    let dynamic_size = write_sysv_symbol_fixture(&mut image, symbol_value, 0);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: dynamic_size as u64,
            ..Default::default()
        },
    ];
    let base = image.as_ptr() as usize;

    assert_eq!(
        unsafe { resolve_dynamic_symbol(base, &phdrs, c"range_symbol") },
        Ok(DynamicSymbol {
            address: base + symbol_value,
            size: 0,
        })
    );
}

#[test]
fn rejects_symbol_name_offset_at_dt_strsz_boundary_as_malformed() {
    const DYNAMIC: usize = 0x100;
    const SYMTAB: usize = 0x300;
    const STRSZ: u32 = 14;

    let mut image = vec![0u8; 0x800];
    let dynamic_size = write_sysv_symbol_fixture(&mut image, 0x600, 8);
    write_value(
        &mut image,
        SYMTAB + std::mem::size_of::<Sym>(),
        Sym {
            name: STRSZ,
            shndx: 1,
            value: 0x600,
            size: 8,
            ..Default::default()
        },
    );
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: dynamic_size as u64,
            ..Default::default()
        },
    ];

    assert_eq!(
        unsafe { resolve_dynamic_symbol(image.as_ptr() as usize, &phdrs, c"range_symbol") },
        Err(XdlError::MalformedElf)
    );
}

#[test]
fn rejects_dynamic_pointers_outside_load_segments() {
    let mut image = vec![0u8; 0x400];
    let dynamic = [
        Dyn {
            tag: DT_SYMTAB,
            value: 0x9000,
        },
        Dyn {
            tag: DT_STRTAB,
            value: 0x200,
        },
        Dyn {
            tag: DT_STRSZ,
            value: 8,
        },
        Dyn {
            tag: DT_HASH,
            value: 0x280,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, 0x100, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: 0x100,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];

    assert!(unsafe { resolve_dynamic_symbol(image.as_ptr() as usize, &phdrs, c"symbol") }.is_err());
}

#[test]
fn resolves_already_relocated_absolute_dynamic_pointers() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;
    const SYMBOL_VALUE: usize = 0x600;

    let mut image = vec![0u8; 0x800];
    let base = image.as_ptr() as usize;
    let names = b"\0absolute_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                shndx: 1,
                value: SYMBOL_VALUE as u64,
                size: 8,
                ..Default::default()
            },
        ],
    );
    write_slice(&mut image, HASH, &[1u32, 2, 1, 0, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: (base + HASH) as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: (base + SYMTAB) as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: (base + STRTAB) as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];

    assert_eq!(
        unsafe { resolve_dynamic_symbol(base, &phdrs, c"absolute_symbol") },
        Ok(DynamicSymbol {
            address: base + SYMBOL_VALUE,
            size: 8,
        })
    );
}

#[test]
fn rejects_tls_symbol_as_a_callable_address() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x380;
    let mut image = vec![0u8; 0x800];
    let names = b"\0tls_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                info: 6,
                shndx: 1,
                value: 0x500,
                ..Default::default()
            },
        ],
    );
    write_slice(&mut image, HASH, &[1u32, 2, 1, 0, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];

    assert_eq!(
        unsafe { resolve_dynamic_symbol(image.as_ptr() as usize, &phdrs, c"tls_symbol") },
        Err(XdlError::UnsupportedSymbol)
    );
}

#[test]
fn resolves_gnu_ifunc_symbol_through_an_executable_resolver_once() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;
    const TARGET_VALUE: usize = 0x680;

    let mut image = vec![0u8; 0x1000];
    let image_address = image.as_ptr() as usize;
    let resolver_address = ifunc_resolver as *const () as usize;
    let names = b"\0ifunc_symbol\0target_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                info: 10,
                shndx: 1,
                value: resolver_address as u64,
                ..Default::default()
            },
            Sym {
                name: 14,
                shndx: 1,
                value: TARGET_VALUE as u64,
                ..Default::default()
            },
        ],
    );
    write_slice(&mut image, HASH, &[1u32, 3, 1, 0, 2, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: (image_address + HASH) as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: (image_address + SYMTAB) as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: (image_address + STRTAB) as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_vaddr: image_address as u64,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: 1,
            p_vaddr: resolver_address as u64,
            p_memsz: 1,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: (image_address + DYNAMIC) as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];

    IFUNC_TARGET.store(image_address + TARGET_VALUE, Ordering::Relaxed);
    IFUNC_CALLS.store(0, Ordering::Relaxed);

    assert_eq!(
        unsafe { resolve_dynamic_symbol(0, &phdrs, c"ifunc_symbol") },
        Ok(DynamicSymbol {
            address: image_address + TARGET_VALUE,
            size: 0,
        })
    );
    assert_eq!(IFUNC_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn rejects_ifunc_resolver_outside_an_executable_load_segment_without_calling_it() {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;

    let mut image = vec![0u8; 0x1000];
    let base = image.as_ptr() as usize;
    let names = b"\0ifunc_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                info: 10,
                shndx: 1,
                value: ifunc_resolver as *const () as usize as u64,
                ..Default::default()
            },
        ],
    );
    write_slice(&mut image, HASH, &[1u32, 2, 1, 0, 0]);
    let dynamic = [
        Dyn {
            tag: DT_HASH,
            value: HASH as u64,
        },
        Dyn {
            tag: DT_SYMTAB,
            value: SYMTAB as u64,
        },
        Dyn {
            tag: DT_STRTAB,
            value: STRTAB as u64,
        },
        Dyn {
            tag: DT_STRSZ,
            value: names.len() as u64,
        },
        Dyn {
            tag: DT_NULL,
            value: 0,
        },
    ];
    write_slice(&mut image, DYNAMIC, &dynamic);
    let phdrs = [
        Elf64Phdr {
            p_type: PT_LOAD,
            p_memsz: image.len() as u64,
            ..Default::default()
        },
        Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_vaddr: DYNAMIC as u64,
            p_memsz: (dynamic.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        },
    ];

    IFUNC_CALLS.store(0, Ordering::Relaxed);
    assert_eq!(
        unsafe { resolve_dynamic_symbol(base, &phdrs, c"ifunc_symbol") },
        Err(XdlError::MalformedElf)
    );
    assert_eq!(IFUNC_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn symbol_name_is_a_c_string_contract() {
    let invalid = CStr::from_bytes_with_nul(b"target\0trailing");
    assert!(invalid.is_err());
}
