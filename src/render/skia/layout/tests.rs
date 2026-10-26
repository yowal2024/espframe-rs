use super::*;

fn words(bytes: &[u8]) -> Vec<u32> {
    assert_eq!(bytes.len() % 4, 0);
    bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect()
}

fn cache_fixture() -> (Vec<u32>, Vec<u32>) {
    (
        words(include_bytes!("fixtures/cache-pac-x20.bin")),
        words(include_bytes!("fixtures/compose-pac-x20.bin")),
    )
}

fn info_fixture() -> Vec<u32> {
    words(include_bytes!("fixtures/n32-extended-unsized.bin"))
}

fn with_offset(word: u32, offset: usize) -> u32 {
    (word & !0x003ffc00) | ((offset as u32 / 8) << 10)
}

#[test]
fn extracted_cache_and_consumer_agree() {
    let (cache, compose) = cache_fixture();
    assert_eq!(cache_offset(&cache, &compose), Ok(0x348));
}

#[test]
fn cache_member_is_derived_and_cross_checked() {
    for offset in [8, 0x248, 0x438, 4096] {
        let (mut cache, mut compose) = cache_fixture();
        for i in [12, 13, 28, 29] {
            cache[i] = with_offset(cache[i], offset);
        }
        assert!(cache_offset(&cache, &compose).is_err());
        for word in &mut compose {
            if pointer_offset(*word, 0xf9400000, 20, *word & 31) == Some(0x348) {
                *word = with_offset(*word, offset);
            }
        }
        assert_eq!(cache_offset(&cache, &compose), Ok(offset));
    }
}

#[test]
fn cache_rejects_mismatched_replacement_paths() {
    for index in [12, 13, 28, 29] {
        let (mut cache, compose) = cache_fixture();
        cache[index] = with_offset(cache[index], 0x350);
        assert!(cache_offset(&cache, &compose).is_err(), "word {index}");
    }
    for offset in [0, 4104] {
        let (mut cache, compose) = cache_fixture();
        for index in [12, 13, 28, 29] {
            cache[index] = with_offset(cache[index], offset);
        }
        assert!(cache_offset(&cache, &compose).is_err());
    }
}

#[test]
fn cache_checks_instruction_roles_and_internal_control_flow() {
    let (cache, compose) = cache_fixture();
    for index in 0..cache.len() {
        if call(cache[index]) || index == 56 {
            continue;
        }
        let mut changed = cache.clone();
        changed[index] ^= 1;
        assert!(cache_offset(&changed, &compose).is_err(), "word {index}");
    }
    // External relocations can move together; shared release targets must agree.
    let mut relocated = cache.clone();
    for (index, word) in relocated.iter_mut().enumerate() {
        if call(*word) || index == 56 {
            *word = (*word & 0xfc000000) | (word.wrapping_add(128) & 0x03ffffff);
        }
    }
    assert_eq!(cache_offset(&relocated, &compose), Ok(0x348));
    for index in [19, 32, 24, 37, 50, 56] {
        let mut changed = cache.clone();
        changed[index] ^= 1;
        assert!(cache_offset(&changed, &compose).is_err(), "helper {index}");
    }
}

#[test]
fn cache_requires_preserved_this_and_live_null_check() {
    let (cache, _) = cache_fixture();
    // Actual consumer sequence: preserve this, call accessor, load cache,
    // preserve accessor result in another register, then test loaded cache.
    let consumer = [0xaa0003f4, 0x94000000, 0xf941a688, 0xaa0003f9, 0xb4000d88];
    assert_eq!(cache_offset(&cache, &consumer), Ok(0x348));
    for (index, replacement) in [
        (0, 0xd503201f), // this was not saved
        (2, 0xf941a288), // different member
        (3, 0xaa0003e8), // overwrite the loaded x8
        (3, 0x94000000), // call may clobber x8
        (4, 0xb4000d89), // test the wrong register
    ] {
        let mut changed = consumer;
        changed[index] = replacement;
        assert!(cache_offset(&cache, &changed).is_err(), "word {index}");
    }
}

#[test]
fn cache_rejects_truncated_or_oversized_functions() {
    let (cache, compose) = cache_fixture();
    for end in 0..cache.len() {
        assert!(cache_offset(&cache[..end], &compose).is_err());
    }
    assert!(cache_offset(&cache, &[]).is_err());
    let mut extra = cache.clone();
    extra.push(0xd65f03c0);
    assert!(cache_offset(&extra, &compose).is_err());
    assert!(cache_offset(&cache, &vec![0; 16385]).is_err());
}

#[test]
fn extracted_n32_factory_requires_extended_destructor() {
    assert_eq!(n32_layout(&info_fixture()), Ok(false));
}

#[test]
fn n32_preserves_arguments_stores_and_release_control_flow() {
    let code = info_fixture();
    for index in 0..code.len() {
        let mut changed = code.clone();
        if call(changed[index]) {
            changed[index] = 0xd503201f;
        } else {
            changed[index] ^= 1;
        }
        assert!(n32_layout(&changed).is_err(), "word {index}");
    }
    let mut relocated = code;
    for word in &mut relocated {
        if call(*word) {
            *word = (*word & 0xfc000000) | (word.wrapping_add(128) & 0x03ffffff);
        }
    }
    assert_eq!(n32_layout(&relocated), Ok(false));
}

#[test]
fn n32_rejects_truncated_or_extended_factory() {
    let code = info_fixture();
    for end in 0..code.len() {
        assert!(n32_layout(&code[..end]).is_err());
    }
    let mut extra = code;
    extra.push(0xd503201f);
    assert!(n32_layout(&extra).is_err());
}

#[test]
fn compact_n32_retains_separate_ownership_classification() {
    let code = [
        0x2a0003e9, 0xd280008a, 0xaa018129, 0xf2c0004a, 0xa900291f, 0xf9000909, 0xd65f03c0,
    ];
    assert_eq!(n32_layout(&code), Ok(true));
    let mut bti = vec![0xd503245f];
    bti.extend_from_slice(&code);
    assert_eq!(n32_layout(&bti), Ok(true));
}

#[test]
fn short_virtual_base_loads_keep_all_dirty_layout_cross_checks() {
    let filter = words(include_bytes!("fixtures/dirty-short-filter.bin"));
    let size = words(include_bytes!("fixtures/dirty-short-size.bin"));
    let begin = words(include_bytes!("fixtures/dirty-short-begin.bin"));
    let region = words(include_bytes!("fixtures/dirty-short-region.bin"));
    assert_eq!(
        dirty_layout(&filter, &size, &begin, &region),
        Ok(DirtyLayout {
            virtual_base: 24,
            edit_slot: 208,
            region: 176,
            bounds: 100,
        })
    );
    // Every non-relocation instruction in the complete filter remains checked.
    for i in 0..filter.len() {
        if call(filter[i]) {
            continue;
        }
        let mut broken = filter.clone();
        broken[i] ^= 1;
        assert!(
            dirty_layout(&broken, &size, &begin, &region).is_err(),
            "filter {i}"
        );
    }
    for (which, index) in [(0, 56), (1, 15), (2, 12)] {
        let mut consumers = [size.clone(), begin.clone(), region.clone()];
        consumers[which][index] ^= 0x400;
        assert!(dirty_layout(&filter, &consumers[0], &consumers[1], &consumers[2]).is_err());
    }
    assert!(dirty_layout(&filter[..41], &size, &begin, &region).is_err());
}

#[test]
fn orientation_is_derived_from_both_consumers_and_rejects_disagreement() {
    let vendor = words(include_bytes!("fixtures/canvas-extended-direction.bin"));
    let common = words(include_bytes!("fixtures/canvas-common.bin"));
    for (code, expected, base, rotation) in [(&vendor, 208, 19, 12), (&common, 136, 20, 14)] {
        assert_eq!(display_orientation_offset(code), Ok(expected));
        let field_load = |word: u32| {
            [8, rotation]
                .iter()
                .any(|&register| word & !0x003ffc00 == 0xb9400000 | (base << 5) | register)
        };
        let sites: Vec<_> = code
            .iter()
            .enumerate()
            .filter_map(|(i, &word)| {
                (field_load(word) && ((word >> 10) & 0xfff) as usize * 4 == expected).then_some(i)
            })
            .collect();
        assert_eq!(sites.len(), 2);
        for &site in &sites {
            let mut broken = code.clone();
            broken[site] = (broken[site] & !0x003ffc00) | ((240 / 4) << 10);
            assert!(display_orientation_offset(&broken).is_err());
        }
        let mut relocated = code.clone();
        for &site in &sites {
            relocated[site] = (relocated[site] & !0x003ffc00) | ((240 / 4) << 10);
        }
        assert_eq!(display_orientation_offset(&relocated), Ok(240));
        let mut wrong_input = code.clone();
        let saved = wrong_input
            .iter()
            .position(|&w| w == 0xaa0203e0 | base)
            .unwrap();
        wrong_input[saved] = 0xaa0103e0 | base;
        assert!(display_orientation_offset(&wrong_input).is_err());
        assert!(display_orientation_offset(&code[..sites[1]]).is_err());
    }
    let mut wrong_rect = common.clone();
    for word in &mut wrong_rect {
        if matches!(*word, 0x29432289 | 0x29432688) {
            *word ^= 0x8000;
        }
    }
    assert!(display_orientation_offset(&wrong_rect).is_err());
}

#[test]
fn plain_vertices_delete_requires_last_reference_guards_and_matching_plt_slot() {
    let make = words(include_bytes!("fixtures/vertices-plain-make.bin"));
    let builder = words(include_bytes!("fixtures/vertices-plain-builder.bin"));
    let (make_site, builder_site) = vertices_delete_sites(&make, &builder).unwrap();
    assert_eq!((make_site, builder_site), (504, 176));
    for (code, site, is_make) in [(&make, make_site, true), (&builder, builder_site, false)] {
        for back in [1, 2, 3, 5, 6] {
            let mut broken = code.clone();
            broken[site / 4 - back] ^= 1;
            let result = if is_make {
                vertices_delete_sites(&broken, &builder)
            } else {
                vertices_delete_sites(&make, &broken)
            };
            assert!(result.is_err());
        }
    }
    assert_eq!(
        branch_address(0x4b3fe0 + make_site, make[make_site / 4]),
        Some(0x756fb0)
    );
    assert_eq!(
        branch_address(0x4b3b54 + builder_site, builder[builder_site / 4]),
        Some(0x756fb0)
    );
    assert_eq!(
        branch_address(0x4b41c8, make[make_site / 4 - 4]),
        Some(0x211c60)
    );
    let stub = [0xd00001f0, 0xf9475211, 0x913a8210, 0xd61f0220];
    assert_eq!(plt_slot(0x756fb0, &stub), Some(0x794ea0));
    for i in 1..4 {
        let mut broken = stub;
        broken[i] ^= 1;
        assert_eq!(plt_slot(0x756fb0, &broken), None);
    }
    assert_eq!(plt_slot(0x756fb0, &stub[..3]), None);
    assert_eq!(branch_address(0x756fb0, 0xd65f03c0), None);
}
