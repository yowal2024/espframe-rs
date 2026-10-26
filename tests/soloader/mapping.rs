use espframe::soloader::mapping::{
    align_down, align_up, load_segment_protection_ranges, load_size, SegmentProtection, PF_R, PF_X,
    PT_LOAD,
};

#[test]
fn align_helpers_match_c_loader_macros() {
    assert_eq!(align_down(0x1234, 0x1000), 0x1000);
    assert_eq!(align_up(0x1234, 0x1000), 0x2000);
}

#[test]
fn load_size_returns_none_without_load_segments() {
    assert_eq!(load_size(&[]), None);
}

#[test]
fn load_size_rejects_segment_with_file_contents_larger_than_memory() {
    let phdr = espframe::soloader::mapping::ProgramHeader {
        p_type: PT_LOAD,
        p_filesz: 0x2000,
        p_memsz: 0x1000,
        ..Default::default()
    };

    assert_eq!(load_size(&[phdr]), None);
}

#[test]
fn load_size_rejects_segment_with_overflowing_virtual_address_range() {
    let phdr = espframe::soloader::mapping::ProgramHeader {
        p_type: PT_LOAD,
        p_vaddr: u64::MAX,
        p_memsz: 1,
        ..Default::default()
    };

    assert_eq!(load_size(&[phdr]), None);
}

#[test]
fn protection_ranges_align_pages_and_make_relocation_targets_writable() {
    let phdr = espframe::soloader::mapping::ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R | PF_X,
        p_vaddr: 0x1234,
        p_memsz: 0x20,
        ..Default::default()
    };

    assert_eq!(
        load_segment_protection_ranges(std::slice::from_ref(&phdr), 0x1000, true),
        vec![espframe::soloader::mapping::ProtectionRange {
            start: 0x2000,
            len: 0x1000,
            protection: SegmentProtection {
                read: true,
                write: true,
                execute: true,
            },
        }]
    );

    assert_eq!(
        load_segment_protection_ranges(&[phdr], 0x1000, false)[0].protection,
        SegmentProtection {
            read: true,
            write: false,
            execute: true,
        }
    );
}
