//! Validate the plain-delete fallback against two actual last-reference paths.

/// Return byte offsets of the two delete calls, not guessed allocator addresses.
pub fn vertices_delete_sites(
    make: &[u32],
    builder: &[u32],
) -> Result<(usize, usize), &'static str> {
    const MAKE: &[u32] = &[
        0xf85d83b3, 0xb4000113, 0x12800000, 0xaa1303e1, 0x94000000, 0x7100041f, 0x54000061,
        0xaa1303e0, 0x94000000,
    ];
    const BUILDER: &[u32] = &[
        0xf9400276, 0x52800028, 0xa902febf, 0xb90002a8, 0xf9000275, 0xb4000116, 0x12800000,
        0xaa1603e1, 0x94000000, 0x7100041f, 0x54000061, 0xaa1603e0, 0x94000000,
    ];
    fn site(code: &[u32], pattern: &[u32]) -> Option<usize> {
        if code.is_empty() || code.len() > 2048 {
            return None;
        }
        let mut hits = code
            .windows(pattern.len())
            .enumerate()
            .filter_map(|(i, block)| {
                block
                    .iter()
                    .zip(pattern)
                    .all(|(&a, &b)| {
                        let mask = if b == 0x94000000 {
                            0xfc000000
                        } else {
                            u32::MAX
                        };
                        a & mask == b & mask
                    })
                    .then_some((i + pattern.len() - 1) * 4)
            });
        let result = hits.next()?;
        hits.next().is_none().then_some(result)
    }
    site(make, MAKE)
        .zip(site(builder, BUILDER))
        .ok_or("vertices probe: unsupported last-reference release")
}

pub fn branch_address(pc: usize, word: u32) -> Option<usize> {
    if word & 0xfc000000 != 0x94000000 {
        return None;
    }
    pc.checked_add_signed(((word << 6) as i32 >> 4) as isize)
}

/// Only the ordinary ARM64 ADRP/LDR/ADD/BR import stub is accepted. The caller
/// bounds both instruction reads and the returned GOT slot to mapped segments.
pub fn plt_slot(pc: usize, code: &[u32]) -> Option<usize> {
    if code.len() != 4
        || code[0] & 0x9f00001f != 0x90000010
        || code[1] & !0x003ffc00 != 0xf9400211
        || code[2] & !0x003ffc00 != 0x91000210
        || code[3] != 0xd61f0220
    {
        return None;
    }
    let offset = ((code[1] >> 10) & 0xfff) as usize * 8;
    if ((code[2] >> 10) & 0xfff) as usize != offset {
        return None;
    }
    let immediate = (((code[0] >> 5) & 0x7ffff) << 2) | ((code[0] >> 29) & 3);
    let delta = ((immediate << 11) as i32 >> 11) as isize * 4096;
    (pc & !4095).checked_add_signed(delta)?.checked_add(offset)
}
