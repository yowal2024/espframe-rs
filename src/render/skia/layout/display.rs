//! Extract only the orientation field, with independent size-swap and angle
//! consumers. Physical/clip rectangles remain checked at +24/+40.

use super::branch_target;

pub fn display_orientation_offset(code: &[u32]) -> Result<usize, &'static str> {
    if code.is_empty() || code.len() > 4096 {
        return Err("display probe: invalid initCanvas size");
    }
    // Register roles are constrained to the inspected compiler families. The
    // preserved register holds the incoming DisplaySettings (x2), not Canvas.
    const VENDOR: &[u32] = &[
        0x29452e68, 0x29462a69, 0xb940026c, 0xaa1403e0, 0x4b080137, 0x4b0b0156, 0x721e019f,
        0x29442668, 0x29432a6d, 0x1a9602f8, 0x1a9702d9,
    ];
    const COMMON: &[u32] = &[
        0x29462e8a, 0x2945368c, 0xb940028e, 0x4b0c0157, 0x4b0d0176, 0x721e01df, 0x29442a8f,
        0x1a9602f8, 0x1a9702d9,
    ];
    let mut android15 = COMMON.to_vec();
    android15[4] = 0x4b0d0175;
    android15[7] = 0x1a9502f9;
    android15[8] = 0x1a9702b8;
    let mut alternate = COMMON.to_vec();
    alternate[3] = 0x4b0c0155;
    alternate[7] = 0x1a9602b7;
    alternate[8] = 0x1a9502d8;
    let mut found = None;
    for (pattern, base) in [
        (VENDOR, 19),
        (COMMON, 20),
        (&android15, 20),
        (&alternate, 20),
    ] {
        let entry_end = code
            .iter()
            .position(|w| w & 0xfc000000 == 0x94000000 || w & 0xfffffc1f == 0xd63f0000)
            .unwrap_or(0)
            .min(64);
        if !code[..entry_end].contains(&(0xaa0203e0 | base)) {
            continue;
        }
        for (at, block) in code.windows(pattern.len()).enumerate() {
            if !block.iter().zip(pattern).enumerate().all(|(i, (&a, &b))| {
                let mask = if i == 2 { !0x003ffc00 } else { u32::MAX };
                a & mask == b & mask
            }) {
                continue;
            }
            // x19's block already includes the physical origin at +24. The
            // x20 family loads it just before this block; require that too.
            if base == 20
                && !code[at.saturating_sub(16)..at]
                    .iter()
                    .any(|&word| matches!(word, 0x29432289 | 0x29432688))
            {
                return Err("display probe: unrecognized physical rectangle");
            }
            let offset = ((block[2] >> 10) & 0xfff) as usize * 4;
            if !(56..=512).contains(&offset) {
                return Err("display probe: orientation outside bounded layout");
            }
            // Independent angle switch: load, clear FP result, subtract ROT_180,
            // range check, then read a bounded rotation table. The table may be
            // inline (B.HI) or outlined (B.LS); its address is never hardcoded.
            let load = 0xb9400008 | (base << 5) | ((offset as u32 / 4) << 10);
            let mut angles = 0;
            for i in at + pattern.len()..code.len() {
                if code[i] & !0x003ffc00 != load & !0x003ffc00 {
                    continue;
                }
                let mut next = i + 1;
                if code.get(next) == Some(&0x2f00e408) {
                    next += 1;
                }
                if code.get(next..next + 3) != Some(&[0x2f00e400, 0x51000d08, 0x7100111f]) {
                    continue;
                }
                let branch = next + 3;
                let Some(&word) = code.get(branch) else {
                    continue;
                };
                let target = branch_target(word, branch, true);
                let table = match word & 0xff00001f {
                    0x54000008 if target == (branch + 4) as isize => branch + 1,
                    0x54000009 if target >= 0 => target as usize,
                    _ => continue,
                };
                let Some(table) = code.get(table..table + 3) else {
                    continue;
                };
                if table[0] & 0x9f00001f != 0x90000009
                    || table[1] & !0x003ffc00 != 0x91000129
                    || table[2] != 0xbc685920
                {
                    continue;
                }
                if code[i] != load {
                    return Err("display probe: conflicting angle and size-swap fields");
                }
                angles += 1;
            }
            if angles != 1 {
                return Err("display probe: missing or ambiguous angle consumer");
            }
            if found.replace(offset).is_some() {
                return Err("display probe: ambiguous orientation field");
            }
        }
    }
    found.ok_or("display probe: unsupported initCanvas instructions")
}
