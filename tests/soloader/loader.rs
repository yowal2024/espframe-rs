use espframe::soloader::{SoLoader, LoaderError};

#[test]
fn load_rejects_missing_file() {
    let mut loader = SoLoader::default();
    let err = loader.load("tests/fixtures/missing.so").unwrap_err();
    assert!(matches!(err, LoaderError::Io(_)));
}

#[test]
fn load_from_memory_rejects_invalid_elf_before_platform_work() {
    let mut loader = SoLoader::default();
    let err = loader
        .load_from_memory("bad.so", b"not an elf")
        .unwrap_err();
    assert!(matches!(err, LoaderError::InvalidElf(_)));
}

#[cfg(not(unix))]
#[test]
fn load_from_memory_reports_unsupported_platform_for_valid_elf_on_windows() {
    let mut loader = SoLoader::default();
    let bytes = minimal_elf_bytes();
    let err = loader.load_from_memory("tiny.so", &bytes).unwrap_err();
    assert!(matches!(err, LoaderError::UnsupportedPlatform));
}

#[cfg(not(unix))]
fn minimal_elf_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes
}
