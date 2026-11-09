use super::abi::{SignsRedirectGroupEntry, SpoofType, SIGNS_REDIRECT_GROUP_MAX, SIGNS_REDIRECT_MAX_ENTRY};

/// Borrowed, equal-length encoded resource bytes. The kernel copies both slices
/// during SET and locates a unique complete match overlapping an actual regular
/// file read by a selected UID. It then binds that file and discovered position.
/// This API does not open the target file, take an offset or use a descriptor.
///
/// For encrypted resources these slices must contain the correct original and
/// replacement on-disk encoded bytes, with any required SO XOR encoding or PAK
/// metadata supplied by the caller. A group can include an independently loaded
/// root, but cannot affect a load that never traverses the existing vfs_read hook.
/// This transport does not manufacture signatures or bypass verification.
/// RSA and Signs modes are mutually exclusive; SET returns EBUSY while occupied.
#[derive(Clone, Copy)]
pub struct SignsRedirectConfig<'a> {
    pub original_entry: &'a [u8],
    pub replacement_entry: &'a [u8],
}

pub(super) fn group_entries(
    configs: &[SignsRedirectConfig<'_>],
) -> Result<[SignsRedirectGroupEntry; SIGNS_REDIRECT_GROUP_MAX], isize> {
    if configs.is_empty() || configs.len() > SIGNS_REDIRECT_GROUP_MAX {
        return Err(-22);
    }
    let mut entries = [SignsRedirectGroupEntry::default(); SIGNS_REDIRECT_GROUP_MAX];
    for (index, config) in configs.iter().enumerate() {
        let args = config.arguments()?;
        if configs[..index]
            .iter()
            .any(|previous| previous.original_entry == config.original_entry)
        {
            return Err(-22);
        }
        entries[index] = SignsRedirectGroupEntry {
            original_ptr: args[2] as u64,
            replacement_ptr: args[3] as u64,
            length: args[1] as u32,
            reserved: 0,
        };
    }
    Ok(entries)
}

impl SignsRedirectConfig<'_> {
    pub(super) fn arguments(&self) -> Result<[usize; 5], isize> {
        let length = self.original_entry.len();
        if length == 0
            || length > SIGNS_REDIRECT_MAX_ENTRY
            || length != self.replacement_entry.len()
        {
            return Err(-22);
        }
        Ok([
            SpoofType::Dfm as usize,
            length,
            self.original_entry.as_ptr() as usize,
            self.replacement_entry.as_ptr() as usize,
            0,
        ])
    }
}

pub(super) fn status(result: isize) -> Result<(), isize> {
    match result {
        0 => Ok(()),
        error if error < 0 => Err(error),
        _ => Err(-71),
    }
}
