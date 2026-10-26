//! Bounded AArch64 instruction recognizers. Never inspect live object memory to
//! guess an offset. Unknown compiler forms and conflicting candidates fail closed.

#[path = "layout/display.rs"]
mod display;
pub use display::display_orientation_offset;
#[path = "layout/vertices.rs"]
mod vertices;
pub use vertices::{branch_address, plt_slot, vertices_delete_sites};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirtyLayout {
    pub virtual_base: usize,
    pub edit_slot: usize,
    pub region: usize,
    pub bounds: usize,
}

/// Recognize the bounded, inspected inlined dirtyEntireOutput in setLayerFilter.
/// All non-offset instructions are checked, including this preservation and the
/// Rect construction. Cross-check the accessor and a second inline copy.
pub fn dirty_layout(
    filter: &[u32],
    size: &[u32],
    begin: &[u32],
    region: &[u32],
) -> Result<DirtyLayout, &'static str> {
    // The short virtual-base load is equivalent to SUB + LDR. Normalize only
    // the inspected 42-word family, then require the same complete filter body
    // and all three independent consumers below. These words are never executed;
    // no branch spanning an expanded load is used as a relative address here.
    if filter.len() == 42 && size.len() <= 256 && begin.len() <= 256 && region.len() <= 64 {
        let expand = |code: &[u32]| {
            let mut result = Vec::with_capacity(code.len() + 4);
            for &word in code {
                let register = word & 31;
                let offset = ((word << 11) as i32 >> 23) as isize;
                if matches!(register, 8 | 9)
                    && word & !0x001ff000 == 0xf8400000 | (register << 5) | register
                    && (-256..=-8).contains(&offset)
                    && offset % 8 == 0
                {
                    result.push(0xd1000000 | ((-offset as u32) << 10) | (register << 5) | register);
                    result.push(0xf9400000 | (register << 5) | register);
                } else {
                    result.push(word);
                }
            }
            result
        };
        return dirty_layout_canonical(
            &expand(filter),
            &expand(size),
            &expand(begin),
            &expand(region),
        );
    }
    dirty_layout_canonical(filter, size, begin, region)
}

fn dirty_layout_canonical(
    filter: &[u32],
    size: &[u32],
    begin: &[u32],
    region: &[u32],
) -> Result<DirtyLayout, &'static str> {
    const FILTER: &[u32] = &[
        0xd503233f, 0xd10143ff, 0xa9027bfd, 0xf9001bf5, 0xa9044ff4, 0x910083fd, 0xd53bd055,
        0xaa0003f3, 0xaa0103f4, 0xf94016a8, 0xf81f83a8, 0xf9400008, 0xd1096108, 0xf9400108,
        0xf8686809, 0x8b080000, 0xf9405929, 0xd63f0120, 0xd360fe88, 0xb9000814, 0x39003008,
        0xf9400268, 0xd1096108, 0xf9400108, 0xf8686a69, 0x8b080260, 0xf9405929, 0xd63f0120,
        0xf8464008, 0x9102c000, 0x910023e1, 0xa900a3ff, 0x94000000, 0xf94016a8, 0xf85f83a9,
        0xeb09011f, 0x540000e1, 0xa9444ff4, 0xf9401bf5, 0xa9427bfd, 0x910143ff, 0xd50323bf,
        0xd65f03c0, 0x94000000,
    ];
    if filter.len() != FILTER.len() || size.len() > 256 || begin.len() > 256 || region.len() > 64 {
        return Err("dirty probe: unsupported function size");
    }
    for (i, (&actual, &expected)) in filter.iter().zip(FILTER).enumerate() {
        let mask = match i {
            12 | 22 | 29 => !0x003ffc00,
            16 | 26 => !0x003ffc00,
            28 => !0x001ff000,
            32 | 43 => 0xfc000000,
            _ => u32::MAX,
        };
        if actual & mask != expected & mask {
            return Err("dirty probe: unsupported inline body");
        }
    }
    let value = DirtyLayout {
        virtual_base: ((filter[22] >> 10) & 0xfff) as usize,
        edit_slot: ((filter[26] >> 10) & 0xfff) as usize * 8,
        region: ((filter[29] >> 10) & 0xfff) as usize,
        bounds: ((filter[28] >> 12) & 0x1ff) as usize,
    };
    if filter[12] != filter[22]
        || filter[16] != filter[26]
        || value.virtual_base == 0
        || value.virtual_base > 4096
        || value.virtual_base % 8 != 0
        || value.edit_slot == 0
        || value.edit_slot > 4096
        || value.region < 8
        || value.region > 4096
        || value.region % 8 != 0
        || value.bounds < 8
        || value.bounds >= 256
        || value.bounds % 4 != 0
        || value.bounds + 8 > value.region
    {
        return Err("dirty probe: inconsistent offsets");
    }
    // beginFrame's first virtual call must be the same editState accessor.
    let prefix = [
        0xd503233f, 0xd102c3ff, 0xa9077bfd, 0xf90043f7, 0xa90957f6, 0xa90a4ff4, 0x9101c3fd,
        0xd53bd056, 0xaa0003f3, 0xf94016c8, 0xf81f83a8,
    ];
    if !begin.starts_with(&prefix) || begin.get(11..18) != Some(&filter[11..18]) {
        return Err("dirty probe: editState cross-check failed");
    }
    // getDirtyRegion uses getState, then the same region member for intersect.
    let expected_region = [
        0xd503233f,
        0xa9be7bfd,
        0xf9000bf3,
        0x910003fd,
        0xf9400009,
        0xaa0803f3,
        0xd1000129 | ((value.virtual_base as u32) << 10),
        0xf9400129,
        0xf869680a,
        0x8b090000,
    ];
    if !region.starts_with(&expected_region)
        || region.get(11..14) != Some(&[0xd63f0140, 0xaa0003e8, filter[29]][..])
    {
        return Err("dirty probe: region cross-check failed");
    }
    // A second inline copy in setDisplaySize independently uses the same
    // accessor, bounds and dirty member, with Rect at sp instead of sp+8.
    let mut second = filter[21..32].to_vec();
    second[9] = 0x910003e1;
    second[10] = 0xa90023ff;
    if !size
        .windows(second.len() + 1)
        .any(|w| w[..second.len()] == second && call(w[second.len()]))
    {
        return Err("dirty probe: bounds cross-check failed");
    }
    Ok(value)
}

pub fn compact_n32(code: &[u32]) -> bool {
    let code = if code.first() == Some(&0xd503245f) {
        &code[1..]
    } else {
        code
    };
    code == [
        0x2a0003e9, 0xd280008a, 0xaa018129, 0xf2c0004a, 0xa900291f, 0xf9000909, 0xd65f03c0,
    ]
}

fn pointer_offset(word: u32, opcode: u32, base: u32, value: u32) -> Option<usize> {
    if word & 0xffc003ff != opcode | (base << 5) | value {
        return None;
    }
    let offset = ((word >> 10) & 0xfff) as usize * 8;
    (offset >= 8 && offset <= 4096).then_some(offset)
}
fn address_offset(word: u32) -> Option<usize> {
    // ADD x0, x19, #imm12 (unshifted).
    if word & 0xffc003ff != 0x91000260 {
        return None;
    }
    let offset = ((word >> 10) & 0xfff) as usize;
    (offset >= 8 && offset <= 4096 && offset % 8 == 0).then_some(offset)
}
fn branch_target(word: u32, at: usize, conditional: bool) -> isize {
    let delta = if conditional {
        ((word << 8) as i32 >> 13) as isize
    } else {
        ((word << 6) as i32 >> 6) as isize
    };
    at as isize + delta
}
fn call(word: u32) -> bool {
    word & 0xfc000000 == 0x94000000
}

fn known_entry(prefix: &[u32]) -> bool {
    let prefix = if matches!(prefix.first(), Some(0xd503233f | 0xd503245f)) {
        &prefix[1..]
    } else {
        prefix
    };
    // These prologues save this without modifying the capacity argument.
    prefix == [0xa9be7bfd, 0xa9014ff4, 0x910003fd, 0xaa0003f3]
        || prefix
            == [
                0xd10103ff, 0xa9017bfd, 0xf90013f5, 0xa9034ff4, 0x910043fd, 0xd53bd055, 0xaa0003f3,
                0xf94016a8, 0xf90007e8,
            ]
}

/// Recognize the inspected constructor/reset families, extracting immediates
/// rather than hardcoding Output's member offset. Deliberately not a general
/// disassembler: register roles are explicit constraints in each known family.
pub fn cache_offset(code: &[u32], compose: &[u32]) -> Result<usize, &'static str> {
    if code.len() > 128 || code.len() < 16 || compose.is_empty() || compose.len() > 16384 {
        return Err("cache probe: invalid function size");
    }
    if let Some(offset) =
        pac_x20_cache_offset(code, compose).or_else(|| legacy_cache_offset(code, compose))
    {
        return Ok(offset);
    }
    let mut result = None;
    for at in 1..code.len().saturating_sub(8) {
        // this saved before the zero-capacity branch; allocation of the known
        // 56-byte cache; capacity argument saved across operator new.
        if code[at] & 0xff00001f != 0x34000001
            || !known_entry(&code[..at])
            || code[at + 1] != 0x52800700
            || code[at + 2] != 0x2a0103f4
            || !call(code[at + 3])
            || code[at + 4] != 0x6f00e400
        {
            continue;
        }
        let zero = branch_target(code[at], at, true);
        if zero <= (at + 4) as isize || zero as usize >= code.len() {
            continue;
        }
        let zero = zero as usize;
        let init = at + 5;
        let mut candidates = Vec::new();
        if code.get(init) == Some(&0xb9000014) {
            // STR w20,[x0]; LDR old,[this+off]; STR new,[this+off].
            if let (Some(&load), Some(&store)) = (code.get(init + 1), code.get(init + 2)) {
                if let Some(off) = pointer_offset(load, 0xf9400000, 19, 20) {
                    let writes = pointer_offset(store, 0xf9000000, 19, 0) == Some(off);
                    let clears = code
                        .get(zero)
                        .and_then(|&w| pointer_offset(w, 0xf9400000, 19, 20))
                        == Some(off)
                        && code
                            .get(zero + 1)
                            .and_then(|&w| pointer_offset(w, 0xf9000000, 19, 31))
                            == Some(off);
                    if writes
                        && clears
                        && code.get(init + 3..init + 6)
                            == Some(&[0x3c808000, 0x3c818000, 0x3c828000][..])
                    {
                        candidates.push(off);
                    }
                }
            }
        } else if code.get(init..init + 2) == Some(&[0xaa0003e1, 0xb9000014][..]) {
            // Outlined unique_ptr::reset: positive and zero paths must pass
            // the same member address to the same helper. x1 holds new/null.
            for positive in init + 2..zero {
                let Some(off) = address_offset(code[positive]) else {
                    continue;
                };
                for clear in zero..code.len().saturating_sub(1) {
                    if address_offset(code[clear]) != Some(off) || code[clear + 1] != 0xaa1f03e1 {
                        continue;
                    }
                    let destination = |start: usize| {
                        (start..(start + 10).min(code.len())).find_map(|i| {
                            let w = code[i];
                            ((w & 0x7c000000) == 0x14000000).then(|| branch_target(w, i, false))
                        })
                    };
                    let Some(a) = destination(positive + 1) else {
                        continue;
                    };
                    let Some(mut b) = destination(clear + 2) else {
                        continue;
                    };
                    // API 35's zero path joins the shared epilogue first.
                    if b >= 0 && (b as usize) < code.len() {
                        if let Some(next) = destination(b as usize) {
                            b = next;
                        }
                    }
                    if a == b {
                        candidates.push(off);
                    }
                }
            }
        }
        for off in candidates {
            // Independent consumer evidence: composeSurfaces must load the
            // candidate member via a preserved object register.
            let entry_end = compose.iter().position(|&w| call(w)).unwrap_or(0).min(64);
            let consumer = compose.iter().enumerate().any(|(i, &w)| {
                let base = (w >> 5) & 31;
                let value = w & 31;
                (19..=28).contains(&base)
                    && compose[..entry_end].contains(&(0xaa0003e0 | base))
                    && pointer_offset(w, 0xf9400000, base, value) == Some(off)
                    && compose[i + 1..(i + 9).min(compose.len())]
                        .iter()
                        .any(|&next| next & 0xff00001f == 0xb4000000 | value)
            });
            if !consumer {
                continue;
            }
            if result.is_some_and(|old| old != off) {
                return Err("cache probe: ambiguous member");
            }
            result = Some(off);
        }
    }
    result.ok_or("cache probe: unsupported constructor/reset instructions")
}

// PAC-enabled x20=this / w19=capacity family. Check the entire body, including
// both release paths and internal branches; only external branch relocations
// and the four copies of the member immediate may differ. No ROM/model gate.
fn pac_x20_cache_offset(code: &[u32], compose: &[u32]) -> Option<usize> {
    const BODY: &[u32] = &[
        0xd503233f, 0xa9bd7bfd, 0xf9000bf5, 0xa9024ff4, 0x910003fd, 0xaa0003f4, 0x340002c1,
        0x52800700, 0x2a0103f3, 0x94000000, 0x6f00e400, 0xb9000013, 0xf9400293, 0xf9000280,
        0x3c808000, 0x3c818000, 0x3c828000, 0xb4000513, 0x91002260, 0x94000000, 0xa9415674,
        0xeb15029f, 0x54000340, 0xf8408680, 0x94000000, 0xeb15029f, 0x54ffffa1, 0x1400000d,
        0xf9400293, 0xf900029f, 0xb4000373, 0x91002260, 0x94000000, 0xa9415674, 0xeb15029f,
        0x540001a0, 0xf8408680, 0x94000000, 0xeb15029f, 0x54ffffa1, 0xa9412269, 0xeb09011f,
        0x540000c0, 0xcb080129, 0x91001d29, 0x927df129, 0x8b090108, 0xf9000e68, 0xf8408260,
        0xb4000040, 0x94000000, 0xaa1303e0, 0xa9424ff4, 0xf9400bf5, 0xa8c37bfd, 0xd50323bf,
        0x14000000, 0xa9424ff4, 0xf9400bf5, 0xa8c37bfd, 0xd50323bf, 0xd65f03c0,
    ];
    if code.len() != BODY.len()
        || !code.iter().zip(BODY).enumerate().all(|(i, (&a, &b))| {
            let mask = match i {
                12 | 13 | 28 | 29 => !0x003ffc00,
                56 => 0xfc000000,
                _ if call(b) => 0xfc000000,
                _ => u32::MAX,
            };
            a & mask == b & mask
        })
    {
        return None;
    }
    let offset = pointer_offset(code[12], 0xf9400000, 20, 19)?;
    if pointer_offset(code[13], 0xf9000000, 20, 0) != Some(offset)
        || code[28] != code[12]
        || pointer_offset(code[29], 0xf9000000, 20, 31) != Some(offset)
        || branch_target(code[19], 19, false) != branch_target(code[32], 32, false)
        || [37, 50, 56]
            .iter()
            .any(|&i| branch_target(code[i], i, false) != branch_target(code[24], 24, false))
    {
        return None;
    }
    // Independently require compose to preserve this before its first call,
    // then load and test this same member without clobbering the loaded value.
    let entry_end = compose.iter().position(|&w| call(w)).unwrap_or(0).min(64);
    if !compose[..entry_end].contains(&0xaa0003f4) {
        return None;
    }
    compose
        .iter()
        .enumerate()
        .any(|(i, &word)| {
            let value = word & 31;
            pointer_offset(word, 0xf9400000, 20, value) == Some(offset)
                && compose.get(i + 1..).is_some_and(|tail| {
                    let null_check = |w: u32| w & 0xff00001f == 0xb4000000 | value;
                    // The optional MOV must leave the loaded register intact.
                    tail.first().is_some_and(|&w| null_check(w))
                        || (tail.len() >= 2
                            && tail[0] & 0xffe0ffe0 == 0xaa0003e0
                            && tail[0] & 31 != value
                            && null_check(tail[1]))
                })
        })
        .then_some(offset)
}

// Older compiler families use x20=this/w19=capacity or a preindexed load.
// Check allocation, initialization and both pointer replacement paths, extract
// only the member immediate, and independently require its compose consumer.
fn legacy_cache_offset(code: &[u32], compose: &[u32]) -> Option<usize> {
    let offset = if code.len() == 61
        && code.get(..5) == Some(&[0xa9bd7bfd, 0xa90157f6, 0xa9024ff4, 0x910003fd, 0xaa0003f4])
        && code.get(5..9).is_some_and(|s| {
            s[0] == 0x340002e1 && s[1] == 0x52800700 && s[2] == 0x2a0103f3 && call(s[3])
        })
        && code.get(9..14) == Some(&[0x6f00e400, 0xb9000013, 0x3c808000, 0x3c818000, 0x3c828000])
    {
        let off = pointer_offset(code[14], 0xf9400000, 20, 19)?;
        if pointer_offset(code[15], 0xf9000000, 20, 0) != Some(off)
            || code[28] != code[14]
            || pointer_offset(code[29], 0xf9000000, 20, 31) != Some(off)
        {
            return None;
        }
        off
    } else if code.len() == 21
        && code[..4] == [0xa9be7bfd, 0xa9014ff4, 0x910003fd, 0xaa0003f4]
        && code[4..7] == [0x340001c1, 0x52800700, 0x2a0103f3]
        && call(code[7])
        && code[8..10] == [0x6f00e400, 0xaa0003e1]
        && code[11..17]
            == [
                0xb9000033, 0x3c808020, 0x3c818020, 0x3c828020, 0xa9414ff4, 0xa8c27bfd,
            ]
        && code[17] == 0x14000004
        && code[18] == code[10]
        && code[19..] == [0xaa1f03e1, 0x17fffffb]
        && code[10] & !0x003ffc00 == 0x91000280
    {
        ((code[10] >> 10) & 0xfff) as usize
    } else if code.len() == 26
        && code[..4] == [0xa9be7bfd, 0xa9014ff4, 0x910003fd, 0xaa0003f3]
        && code[4..7] == [0x340001e1, 0x52800700, 0x2a0103f4]
        && call(code[7])
        && code[8..10] == [0x6f00e400, 0xb9000014]
        && code[10] & !0x001ff000 == 0xf8400e61
        && code[11..18]
            == [
                0xf9000260, 0x3c808000, 0x3c818000, 0x3c828000, 0xb50000e1, 0xa9414ff4, 0xa8c27bfd,
            ]
        && code[18] == 0xd65f03c0
        && code[19] == code[10]
        && code[20..25] == [0xf900027f, 0xb4ffff61, 0xaa1303e0, 0xa9414ff4, 0xa8c27bfd]
        && code[25] & 0xfc000000 == 0x14000000
    {
        ((code[10] >> 12) & 0x1ff) as usize
    } else {
        return None;
    };
    if offset == 0 || offset > 4096 || offset % 8 != 0 {
        return None;
    }
    let end = compose.iter().position(|&w| call(w)).unwrap_or(0).min(64);
    compose
        .iter()
        .enumerate()
        .any(|(i, &w)| {
            let r = (w >> 5) & 31;
            let v = w & 31;
            (19..=28).contains(&r)
                && compose[..end].contains(&(0xaa0003e0 | r))
                && pointer_offset(w, 0xf9400000, r, v) == Some(offset)
                && compose[i + 1..(i + 9).min(compose.len())]
                    .iter()
                    .any(|&n| n & 0xff00001f == 0xb4000000 | v)
        })
        .then_some(offset)
}

/// Locate the unique final destination flush inside drawLayers. This is a
/// semantic call-site check, never a fixed address or an endCapture dependency.
pub fn legacy_flush_site(code: &[u32]) -> Result<usize, &'static str> {
    let mut found = None;
    for i in 14..code.len() {
        if code[i] != 0xd63f0100 {
            continue;
        }
        let block = &code[i - 14..i];
        let Some(m) = block.iter().position(|&w| w & 0xffe0ffff == 0xaa0003e0) else {
            continue;
        };
        let surface = (block[m] >> 16) & 31;
        if !(19..=28).contains(&surface)
            || !block.contains(&(0xf9400008 | surface << 5))
            || !block.contains(&0x2a1f03e1)
            || !block.contains(&0xaa1f03e3)
            || !block.contains(&0x6f00e400)
        {
            continue;
        }
        let Some(cmp) = block.iter().position(|&w| w == (0xeb08001f | surface << 5)) else {
            continue;
        };
        if block
            .get(cmp + 1)
            .is_none_or(|&w| w & 0xff00001f != 0x54000001)
            || block[m..].iter().any(|&w| w & 0xfc000000 == 0x94000000)
            || !block
                .iter()
                .any(|&w| w & !0x003ffc00 == 0xf9400108 && ((w >> 10) & 0xfff) > 0)
            || !block
                .iter()
                .any(|&w| w & !0x003fffff == 0x91000000 && w & 31 == 2)
        {
            continue;
        }
        if found.replace((i + 1) * 4).is_some() {
            return Err("legacy final flush is ambiguous");
        }
    }
    found.ok_or("legacy final destination flush not recognized")
}

/// Validate RGBA/premul and the inspected 32-byte extended factories.
/// BL destinations are relocated; all argument setup and stores remain exact.
pub fn n32_layout(code: &[u32]) -> Result<bool, &'static str> {
    if compact_n32(code) {
        return Ok(true);
    }
    const EXTENDED_16: &[u32] = &[
        0xd503233f, 0xd10143ff, 0xa9027bfd, 0xf9001bf5, 0xa9044ff4, 0x910083fd, 0xd53bd054,
        0xaa0803f3, 0x2a0003e9, 0xf9401688, 0xaa018135, 0x910023e0, 0x910003e3, 0x52800081,
        0x52800042, 0xf81f83a8, 0xf90003ff, 0x940e7847, 0x910023e1, 0xaa1303e0, 0x940e6e5a,
        0x910023e0, 0xa9017e75, 0x940e3fcb, 0xf94003f3, 0xb4000133, 0x12800000, 0xaa1303e1,
        0x97f4c47c, 0x7100041f, 0x54000081, 0xaa1303e0, 0x52801201, 0x940e2e39, 0xf9401688,
        0xf85f83a9, 0xeb09011f, 0x540000e1, 0xa9444ff4, 0xf9401bf5, 0xa9427bfd, 0x910143ff,
        0xd50323bf, 0xd65f03c0, 0x940e87e6,
    ];
    const EXTENDED_17: &[u32] = &[
        0xd503233f, 0xd10103ff, 0xa9027bfd, 0xa9034ff4, 0x910083fd, 0xaa0803f3, 0x2a0003e8,
        0x910043e0, 0xaa018114, 0x910023e3, 0x52800081, 0x52800042, 0xf90007ff, 0x941458b2,
        0x910043e1, 0xaa1303e0, 0x941459a5, 0x910043e0, 0xa9017e74, 0x94142dc2, 0xf94007f3,
        0xb4000133, 0x12800000, 0xaa1303e1, 0x97f1290d, 0x7100041f, 0x54000081, 0xaa1303e0,
        0x52801201, 0x94141978, 0xa9434ff4, 0xa9427bfd, 0x910103ff, 0xd50323bf, 0xd65f03c0,
    ];
    // Same 32-byte extended layout, with unsized operator delete in the
    // temporary colorspace release. Both shorter branch distances are exact;
    // the ROM ImageInfo destructor remains required (Ok(false)).
    const EXTENDED_UNSIZED_DELETE: &[u32] = &[
        0xd503233f, 0xd10143ff, 0xa9027bfd, 0xf9001bf5, 0xa9044ff4, 0x910083fd, 0xd53bd054,
        0xaa0803f3, 0x2a0003e9, 0xf9401688, 0xaa018135, 0x910023e0, 0x910003e3, 0x52800081,
        0x52800042, 0xf81f83a8, 0xf90003ff, 0x94000000, 0x910023e1, 0xaa1303e0, 0x94000000,
        0x910023e0, 0xa9017e75, 0x94000000, 0xf94003f3, 0xb4000113, 0x12800000, 0xaa1303e1,
        0x94000000, 0x7100041f, 0x54000061, 0xaa1303e0, 0x94000000, 0xf9401688, 0xf85f83a9,
        0xeb09011f, 0x540000e1, 0xa9444ff4, 0xf9401bf5, 0xa9427bfd, 0x910143ff, 0xd50323bf,
        0xd65f03c0, 0x94000000,
    ];
    for expected in [EXTENDED_16, EXTENDED_17, EXTENDED_UNSIZED_DELETE] {
        if code.len() == expected.len()
            && code.iter().zip(expected).all(|(&a, &b)| {
                let mask = if call(b) { 0xfc000000 } else { u32::MAX };
                a & mask == b & mask
            })
        {
            return Ok(false);
        }
    }
    Err("ImageInfo probe: unsupported N32 factory")
}

#[cfg(test)]
#[path = "layout/tests.rs"]
mod tests;
