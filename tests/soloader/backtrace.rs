#![cfg(unix)]

use espframe::soloader::backtrace::{locate_eh_frame, BacktraceRegistry};
use espframe::soloader::elf::ElfImage;
use std::ffi::{CStr, CString};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const REENTRANT_PROBE_ENV: &str = "CSOLOADER_REENTRANT_PHDR_PROBE";
const STALE_HANDLE_PROBE_ENV: &str = "CSOLOADER_STALE_HANDLE_PROBE";

#[test]
fn registry_resolves_address_to_registered_symtab_symbol() {
    let bytes = synthetic_elf_for_backtrace(true);
    let image = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();
    let registry = BacktraceRegistry::new();

    assert!(registry.register_image(&image, Some(7)).is_some());

    let resolved = registry.resolve_address(0x7000_0104).unwrap();
    assert_eq!(resolved.file_name, "sample.so");
    assert_eq!(resolved.file_base, 0x7000_0000);
    assert_eq!(resolved.symbol_name.as_deref(), Some("main_object"));
    assert_eq!(resolved.symbol_address, Some(0x7000_0100));
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

#[test]
fn custom_dl_iterate_phdr_allows_registry_reentry_from_callback() {
    run_isolated_probe(
        "custom_dl_iterate_phdr_reentrant_probe",
        REENTRANT_PROBE_ENV,
    );
}

#[test]
fn custom_dl_iterate_phdr_reentrant_probe() {
    if std::env::var_os(REENTRANT_PROBE_ENV).is_none() {
        return;
    }

    struct ReentrantContext {
        registry: *const BacktraceRegistry,
        handle: espframe::soloader::backtrace::BacktraceHandle,
        reentered: bool,
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let (Some(info), Some(context)) = (info.as_ref(), (data as *mut ReentrantContext).as_mut())
        else {
            return 0;
        };
        if info.dlpi_name.is_null() || CStr::from_ptr(info.dlpi_name).to_bytes() != b"sample.so" {
            return 0;
        }

        context.reentered = (*context.registry).unregister_image(context.handle);
        0
    }

    let bytes = synthetic_elf_for_backtrace(true);
    let image = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();
    let registry = BacktraceRegistry::new();
    let handle = registry.register_image(&image, Some(7)).unwrap();
    let mut context = ReentrantContext {
        registry: &registry,
        handle,
        reentered: false,
    };

    let result =
        registry.custom_dl_iterate_phdr(callback, (&mut context as *mut ReentrantContext).cast());

    assert_eq!(result, 0);
    assert!(context.reentered);
}

#[test]
fn stale_custom_handle_fails_closed_instead_of_reaching_libc() {
    run_isolated_probe("stale_custom_handle_probe", STALE_HANDLE_PROBE_ENV);
}

#[test]
fn stale_custom_handle_probe() {
    if std::env::var_os(STALE_HANDLE_PROBE_ENV).is_none() {
        return;
    }

    let bytes = synthetic_elf_for_backtrace(true);
    let image = ElfImage::parse_memory("sample.so", &bytes, 0x7000_0000).unwrap();
    let registry = BacktraceRegistry::new();
    let registration = registry.register_image(&image, Some(7)).unwrap();
    let filename = CString::new("sample.so").unwrap();
    let symbol = CString::new("main_object").unwrap();
    let handle = registry.dlopen_handle(Some(&filename), libc::RTLD_NOW);
    assert!(!handle.is_null());
    let second_handle = registry.dlopen_handle(Some(&filename), libc::RTLD_NOW);
    assert_eq!(second_handle, handle);
    assert_eq!(registry.dlclose_handle(handle), 0);
    assert!(registry.unregister_image(registration));

    assert!(registry.dlsym_handle(handle, Some(&symbol)).is_null());
    assert_ne!(registry.dlclose_handle(handle), 0);

    let replacement = ElfImage::parse_memory("replacement.so", &bytes, 0x7100_0000).unwrap();
    let replacement_registration = registry.register_image(&replacement, Some(8)).unwrap();
    assert!(registry.dlsym_handle(handle, Some(&symbol)).is_null());
    assert!(registry.unregister_image(replacement_registration));
}

fn run_isolated_probe(test_name: &str, marker: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(marker, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated probe {test_name} failed: {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("isolated probe {test_name} timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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
