use super::abi::{RsaRedirectSetRequest, RSA_REDIRECT_F_FILE, RSA_REDIRECT_MAX_ENTRY};

/// Borrowed RSA-2048 / PKCS#1 DER configuration; no package name, UID or file
/// descriptor. The existing kernel UID list selects applications.
/// SET copies all buffers synchronously and validates the DER/modulus CRCs.
#[derive(Clone, Copy, Default)]
pub struct RsaRedirectConfig<'a> {
    /// CRC32 of the replacement key's 256-byte little-endian modulus.
    pub expected_crc: u32,
    /// CRC32 of the original business public key's modulus in the same format.
    pub original_crc: u32,
    pub key_id: u8,
    /// 0 records all matches and works before process startup. A positive PID
    /// filters result capture only, never rewrap; 1 and negative values are invalid.
    pub capture_pid: i32,
    pub private_der: &'a [u8],
    pub public_der: &'a [u8],
    /// None performs only rewrap. Some enables deferred file validation/binding.
    pub file: Option<RsaRedirectFile<'a>>,
}

/// Original and replacement byte patterns, with no caller file open or offset.
/// The kernel searches near the actual read returned for a selected UID and
/// binds only a unique matching profile/location. Ambiguous matches fail with
/// ENOTUNIQ without a new binding or rewrite. Only read/pread are covered;
/// SET success does not mean a file has already been matched.
#[derive(Clone, Copy)]
pub struct RsaRedirectFile<'a> {
    pub original_entry: &'a [u8],
    pub replacement_entry: &'a [u8],
}

impl RsaRedirectConfig<'_> {
    pub(super) fn request(&self) -> Result<RsaRedirectSetRequest, isize> {
        if self.expected_crc == self.original_crc
            || self.capture_pid < 0
            || self.capture_pid == 1
            || self.private_der.is_empty()
            || self.private_der.len() > 2048
            || self.public_der.is_empty()
            || self.public_der.len() > 512
        {
            return Err(-22);
        }
        let mut request = RsaRedirectSetRequest {
            expected_crc: self.expected_crc,
            original_crc: self.original_crc,
            key_id: u32::from(self.key_id),
            capture_pid: self.capture_pid,
            private_der: self.private_der.as_ptr() as u64,
            public_der: self.public_der.as_ptr() as u64,
            private_der_len: self.private_der.len() as u32,
            public_der_len: self.public_der.len() as u32,
            ..Default::default()
        };
        if let Some(file) = self.file {
            let length = file.original_entry.len();
            if length == 0
                || length > RSA_REDIRECT_MAX_ENTRY
                || length != file.replacement_entry.len()
            {
                return Err(-22);
            }
            request.flags = RSA_REDIRECT_F_FILE;
            request.entry_len = length as u32;
            request.original_entry = file.original_entry.as_ptr() as u64;
            request.replacement_entry = file.replacement_entry.as_ptr() as u64;
        }
        Ok(request)
    }
}

pub(super) fn status(result: isize) -> Result<(), isize> {
    match result {
        0 => Ok(()),
        error if error < 0 => Err(error),
        _ => Err(-71), // EPROTO: SET, DEL and STATS return zero on success.
    }
}
