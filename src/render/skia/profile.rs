//! Android API level selects the compatibility adapters; symbols select entry points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rom {
    Android12,
    Android12L,
    Android13,
    Android14,
    Android16,
    Android15,
    Android17,
}

pub fn for_sdk(sdk: i32) -> Option<Rom> {
    match sdk {
        31 => Some(Rom::Android12),
        32 => Some(Rom::Android12L),
        33 => Some(Rom::Android13),
        34 => Some(Rom::Android14),
        35 => Some(Rom::Android15),
        36 => Some(Rom::Android16),
        37 => Some(Rom::Android17),
        _ => None,
    }
}

impl Rom {
    pub fn legacy(self) -> bool {
        matches!(
            self,
            Self::Android12 | Self::Android12L | Self::Android13 | Self::Android14
        )
    }
    pub fn android12(self) -> bool {
        matches!(self, Self::Android12 | Self::Android12L)
    }
    pub fn physical_output(self, name: &[u8]) -> bool {
        // Android 15 Output::setName formats "%s (%s)" with a decimal DisplayId.
        // Display::isVirtual tests bit 63 of that ID (0x2da2a8).
        // Android 16/17 use a variant internally, but its HAL/GPU virtual ID
        // generators still set bit 63 (0x551178 / 0x541428).
        let Some(prefix) = name.strip_suffix(b")") else {
            return false;
        };
        let Some(start) = prefix.windows(2).rposition(|s| s == b" (") else {
            return false;
        };
        let digits = &prefix[start + 2..];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return false;
        }
        let Some(id) = digits.iter().try_fold(0u64, |id, digit| {
            id.checked_mul(10)?.checked_add((digit - b'0') as u64)
        }) else {
            return false;
        };
        id & (1 << 63) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_android_version() {
        assert_eq!(for_sdk(35), Some(Rom::Android15));
        assert_eq!(for_sdk(36), Some(Rom::Android16));
        assert_eq!(for_sdk(37), Some(Rom::Android17));
        for sdk in [0, 30, 38, i32::MAX] {
            assert_eq!(for_sdk(sdk), None);
        }
    }
    #[test]
    fn physical_ids_are_not_tied_to_one_panel() {
        for name in [
            b" (4630946359962947715)".as_slice(),
            b"Built-in Screen (1234)",
        ] {
            assert!(Rom::Android15.physical_output(name));
            assert!(Rom::Android17.physical_output(name));
        }
        for name in [
            b"RegionSampling".as_slice(),
            b"Screenshot",
            b"Virtual (9223372036854775808)",
            b"GPU Virtual (11529215046068469761)",
            b" (18446744073709551616)",
            b" ()",
            b" (-1)",
        ] {
            assert!(!Rom::Android15.physical_output(name));
            assert!(!Rom::Android17.physical_output(name));
        }
        assert!(Rom::Android16.physical_output(b"Built-in Screen (1234)"));
    }
}
