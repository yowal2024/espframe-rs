#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};

use espframe::xdl::{
    xdl_addr, xdl_addr4, xdl_addr_clean, xdl_close, xdl_dsym, xdl_info, xdl_open2, xdl_sym,
    DynamicSymbol, Elf64Phdr, LoadedModuleSnapshot, XdlAddressCache, XdlError,
    XDL_ALWAYS_FORCE_LOAD, XDL_DEFAULT, XDL_DI_DLINFO, XDL_FULL_PATHNAME, XDL_NON_SYM,
    XDL_TRY_FORCE_LOAD,
};
#[cfg(not(target_os = "android"))]
use espframe::xdl::{xdl_iterate_phdr, xdl_open};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;

#[cfg(windows)]
static DSYM_IFUNC_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
extern "C" fn dsym_ifunc_resolver() -> *mut core::ffi::c_void {
    DSYM_IFUNC_CALLS.fetch_add(1, Ordering::Relaxed);
    std::ptr::null_mut()
}

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
    unsafe { (image.as_mut_ptr().add(offset) as *mut T).write_unaligned(value) };
}

fn write_slice<T: Copy>(image: &mut [u8], offset: usize, values: &[T]) {
    for (index, value) in values.iter().copied().enumerate() {
        write_value(image, offset + index * std::mem::size_of::<T>(), value);
    }
}

fn loaded_symbol_fixture() -> (Vec<u8>, [Elf64Phdr; 2]) {
    const DYNAMIC: usize = 0x100;
    const HASH: usize = 0x200;
    const SYMTAB: usize = 0x300;
    const STRTAB: usize = 0x400;

    let mut image = vec![0u8; 0x800];
    let names = b"\0fixture_symbol\0";
    image[STRTAB..STRTAB + names.len()].copy_from_slice(names);
    write_slice(
        &mut image,
        SYMTAB,
        &[
            Sym::default(),
            Sym {
                name: 1,
                shndx: 1,
                value: 0x600,
                size: 16,
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
    (image, phdrs)
}

fn debug_symbol_elf(symbol_value: u64, symbol_type: u8) -> Vec<u8> {
    const SHOFF: usize = 0x100;
    const SHSTRTAB: usize = 0x300;
    const SYMTAB: usize = 0x380;
    const STRTAB: usize = 0x400;
    const SHENTSIZE: usize = 64;

    let mut elf = vec![0u8; 0x500];
    elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    write_value(&mut elf, 40, SHOFF as u64);
    write_value(&mut elf, 52, 64u16);
    write_value(&mut elf, 58, SHENTSIZE as u16);
    write_value(&mut elf, 60, 4u16);
    write_value(&mut elf, 62, 1u16);

    let section_names = b"\0.shstrtab\0.symtab\0.strtab\0";
    elf[SHSTRTAB..SHSTRTAB + section_names.len()].copy_from_slice(section_names);
    let symbols = b"\0hidden.llvm.123\0";
    elf[STRTAB..STRTAB + symbols.len()].copy_from_slice(symbols);

    write_value(&mut elf, SHOFF + SHENTSIZE, 1u32);
    write_value(&mut elf, SHOFF + SHENTSIZE + 4, 3u32);
    write_value(&mut elf, SHOFF + SHENTSIZE + 24, SHSTRTAB as u64);
    write_value(&mut elf, SHOFF + SHENTSIZE + 32, section_names.len() as u64);

    let symtab_shdr = SHOFF + SHENTSIZE * 2;
    write_value(&mut elf, symtab_shdr, 11u32);
    write_value(&mut elf, symtab_shdr + 4, 2u32);
    write_value(&mut elf, symtab_shdr + 24, SYMTAB as u64);
    write_value(&mut elf, symtab_shdr + 32, 48u64);
    write_value(&mut elf, symtab_shdr + 40, 3u32);
    write_value(&mut elf, symtab_shdr + 56, 24u64);

    let strtab_shdr = SHOFF + SHENTSIZE * 3;
    write_value(&mut elf, strtab_shdr, 19u32);
    write_value(&mut elf, strtab_shdr + 4, 3u32);
    write_value(&mut elf, strtab_shdr + 24, STRTAB as u64);
    write_value(&mut elf, strtab_shdr + 32, symbols.len() as u64);

    write_value(
        &mut elf,
        SYMTAB + 24,
        Sym {
            name: 1,
            info: symbol_type,
            shndx: 1,
            value: symbol_value,
            size: 24,
            ..Default::default()
        },
    );
    elf
}

#[test]
fn public_constants_match_xdl_2_3_contract() {
    assert_eq!(XDL_DEFAULT, 0);
    assert_eq!(XDL_TRY_FORCE_LOAD, 1);
    assert_eq!(XDL_ALWAYS_FORCE_LOAD, 2);
    assert_eq!(XDL_NON_SYM, 1);
    assert_eq!(XDL_FULL_PATHNAME, 1);
    assert_eq!(XDL_DI_DLINFO, 1);
}

#[test]
fn open2_sym_info_addr_and_cache_form_one_raii_api() {
    let (image, phdrs) = loaded_symbol_fixture();
    let base = image.as_ptr() as usize;
    let snapshot = LoadedModuleSnapshot::new(c"/system/lib64/libfixture.so", base, &phdrs);
    let handle = xdl_open2(snapshot).unwrap();

    assert_eq!(
        unsafe { xdl_sym(&handle, c"fixture_symbol") },
        Ok(DynamicSymbol {
            address: base + 0x600,
            size: 16,
        })
    );
    let info = xdl_info(&handle, XDL_DI_DLINFO).unwrap();
    assert_eq!(info.pathname(), c"/system/lib64/libfixture.so");
    assert_eq!(info.base(), base);
    assert_eq!(info.program_headers(), phdrs);
    assert_eq!(info.symbol_name(), None);
    assert!(matches!(
        xdl_info(&handle, XDL_DI_DLINFO + 1),
        Err(XdlError::InvalidRequest)
    ));

    let mut cache = XdlAddressCache::default();
    cache.insert(handle);
    let located = unsafe { xdl_addr(base + 0x608, &mut cache) }.unwrap();
    assert_eq!(located.symbol_name(), Some(c"fixture_symbol"));
    assert_eq!(located.symbol_address(), Some(base + 0x600));
    assert_eq!(located.symbol_size(), 16);

    let module_only = unsafe { xdl_addr4(base + 0x608, &mut cache, XDL_NON_SYM) }.unwrap();
    assert_eq!(module_only.pathname(), c"/system/lib64/libfixture.so");
    assert_eq!(module_only.symbol_name(), None);

    xdl_addr_clean(&mut cache);
    assert!(cache.is_empty());
}

#[test]
fn close_consumes_an_open2_handle() {
    let (image, phdrs) = loaded_symbol_fixture();
    let handle = xdl_open2(LoadedModuleSnapshot::new(
        c"libfixture.so",
        image.as_ptr() as usize,
        &phdrs,
    ))
    .unwrap();
    assert!(xdl_close(handle).is_none());
}

#[test]
fn dsym_reads_file_symtab_and_matches_llvm_canonical_suffix() {
    let (image, phdrs) = loaded_symbol_fixture();
    let path = std::env::temp_dir().join(format!("xdl-rs-dsym-{}.so", std::process::id()));
    std::fs::write(&path, debug_symbol_elf(0x620, 0)).unwrap();
    let path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let handle = xdl_open2(LoadedModuleSnapshot::new(
        &path,
        image.as_ptr() as usize,
        &phdrs,
    ))
    .unwrap();

    assert_eq!(
        unsafe { xdl_dsym(&handle, c"hidden") },
        Ok(DynamicSymbol {
            address: image.as_ptr() as usize + 0x620,
            size: 24,
        })
    );

    let mut cache = XdlAddressCache::default();
    cache.insert(handle);
    let info = unsafe { xdl_addr(image.as_ptr() as usize + 0x628, &mut cache) }.unwrap();
    assert_eq!(info.symbol_name(), Some(c"hidden.llvm.123"));
    assert_eq!(info.symbol_address(), Some(image.as_ptr() as usize + 0x620));
    assert_eq!(info.symbol_size(), 24);

    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[cfg(windows)]
#[test]
fn dsym_returns_ifunc_resolver_address_without_invoking_it() {
    let (image, phdrs) = loaded_symbol_fixture();
    let base = image.as_ptr() as usize;
    let resolver = dsym_ifunc_resolver as *const () as usize;
    let value = resolver
        .checked_sub(base)
        .expect("Windows image allocation must precede the test image resolver");
    let path = std::env::temp_dir().join(format!("xdl-rs-dsym-ifunc-{}.so", std::process::id()));
    std::fs::write(&path, debug_symbol_elf(value as u64, 10)).unwrap();
    let path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let handle = xdl_open2(LoadedModuleSnapshot::new(&path, base, &phdrs)).unwrap();
    DSYM_IFUNC_CALLS.store(0, Ordering::SeqCst);

    assert_eq!(
        unsafe { xdl_dsym(&handle, c"hidden") },
        Ok(DynamicSymbol {
            address: resolver,
            size: 24,
        })
    );
    assert_eq!(DSYM_IFUNC_CALLS.load(Ordering::SeqCst), 0);

    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[cfg(not(target_os = "android"))]
#[test]
fn runtime_open_and_iteration_fail_closed_off_android() {
    assert!(matches!(
        xdl_open(c"libfixture.so", XDL_DEFAULT),
        Err(XdlError::UnsupportedPlatform)
    ));
    assert_eq!(
        xdl_iterate_phdr(XDL_FULL_PATHNAME, |_| 0),
        Err(XdlError::UnsupportedPlatform)
    );
}
