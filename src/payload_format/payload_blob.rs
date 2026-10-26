use thiserror::Error;
use crate::xdl::{xdl_lzma_decompress, LzmaError};

const HEADER_SIZE: usize = 20;
const FILE_MAGIC: &[u8; 4] = b"DCFE";
const XZ_MAGIC: &[u8; 6] = b"\xFD7zXZ\0";

const CUSTOM_SBOX: [u8; 256] = [
    0x4b, 0x8c, 0x0a, 0x8b, 0x07, 0xcb, 0xca, 0x60, 0x1d, 0x79, 0x4a, 0xdb, 0x86, 0x22, 0xd3, 0x0e,
    0xe7, 0x77, 0xe1, 0x88, 0x87, 0xa9, 0x6a, 0x05, 0xd0, 0x24, 0x57, 0xd2, 0xb4, 0x54, 0x0f, 0x65,
    0x12, 0x80, 0x33, 0x5e, 0x1e, 0x9a, 0x02, 0xe4, 0x1c, 0x50, 0x40, 0x01, 0x09, 0xa5, 0x19, 0x38,
    0x7c, 0x62, 0x5b, 0x63, 0xbd, 0x36, 0x78, 0xb7, 0x7a, 0x3f, 0x75, 0x47, 0xc3, 0x5a, 0x17, 0x08,
    0xf9, 0x73, 0xdc, 0xbf, 0xbb, 0xce, 0xaf, 0x55, 0x2f, 0x9b, 0x26, 0x13, 0xd9, 0x43, 0xda, 0x74,
    0x2b, 0x21, 0x7d, 0xc0, 0x5d, 0x84, 0x11, 0xab, 0xcf, 0xe3, 0x96, 0x99, 0xef, 0xec, 0xad, 0xe2,
    0x25, 0xc2, 0xd7, 0x83, 0x6b, 0xe8, 0x1b, 0x70, 0x68, 0x81, 0x7f, 0x8a, 0x2d, 0x9c, 0xb2, 0xd5,
    0x29, 0x53, 0x6d, 0xf2, 0x37, 0xb0, 0x9d, 0x00, 0x94, 0x16, 0xa7, 0x59, 0x3d, 0x82, 0x03, 0x27,
    0xe0, 0xfc, 0x3b, 0xc4, 0xaa, 0x32, 0x6c, 0x3a, 0x64, 0x52, 0x8e, 0x98, 0x4c, 0xa8, 0xb9, 0x0b,
    0x4d, 0x71, 0xea, 0xa4, 0x5f, 0xdf, 0x35, 0xf5, 0x6e, 0xc6, 0x95, 0x3c, 0xa6, 0xae, 0xfb, 0xa3,
    0x45, 0x1f, 0x9f, 0xff, 0xe9, 0x7e, 0x5c, 0xac, 0x67, 0x23, 0xd4, 0x4f, 0x31, 0x30, 0x44, 0x89,
    0x42, 0xe5, 0x1a, 0xc8, 0xf0, 0x20, 0xee, 0xd1, 0xcc, 0x2e, 0x04, 0xc7, 0x48, 0x8f, 0xd6, 0xfd,
    0x97, 0x8d, 0x58, 0xde, 0xbc, 0x56, 0x14, 0x66, 0xc5, 0xa0, 0x0c, 0xba, 0xeb, 0x90, 0xf3, 0xf7,
    0x0d, 0x9e, 0x10, 0x4e, 0xed, 0x7b, 0x06, 0xfe, 0x49, 0x18, 0x2a, 0x91, 0x76, 0x61, 0xb8, 0xb6,
    0x41, 0x85, 0xb5, 0x39, 0xc9, 0xa1, 0xf6, 0x34, 0xb3, 0xbe, 0x72, 0xc1, 0xe6, 0x28, 0xdd, 0xa2,
    0xf4, 0x51, 0xf1, 0xf8, 0x92, 0x46, 0x6f, 0xcd, 0x69, 0xb1, 0xd8, 0xfa, 0x15, 0x2c, 0x93, 0x3e,
];

const CUSTOM_RCON: [u8; 11] = [
    0x00, 0x24, 0x10, 0x0d, 0x0c, 0x12, 0x21, 0x40, 0xcb, 0x3e, 0x24,
];

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PayloadError {
    #[error("DCFE header is truncated")]
    TruncatedHeader,
    #[error("DCFE magic is invalid")]
    BadMagic,
    #[error("declared payload size exceeds the configured maximum")]
    DeclaredSizeExceedsMaximum,
    #[error("DCFE ciphertext is truncated")]
    TruncatedCiphertext,
    #[error("decrypted payload does not start with an XZ header")]
    InvalidCompressedHeader,
    #[error("decrypted XZ payload is invalid")]
    InvalidCompressedPayload,
    #[error("XZ output size {actual} does not match declared size {declared}")]
    OutputSizeMismatch { actual: usize, declared: usize },
}

pub fn decode_payload(
    blob: &[u8],
    key: &[u8; 16],
    max_size: usize,
) -> Result<Vec<u8>, PayloadError> {
    if blob.len() < HEADER_SIZE {
        return Err(PayloadError::TruncatedHeader);
    }
    if &blob[..4] != FILE_MAGIC {
        return Err(PayloadError::BadMagic);
    }

    let declared_size = u64::from_be_bytes(blob[4..12].try_into().expect("header is checked"));
    if declared_size > max_size as u64 {
        return Err(PayloadError::DeclaredSizeExceedsMaximum);
    }
    let declared_size = declared_size as usize;
    let ciphertext = &blob[HEADER_SIZE..];
    if ciphertext.len() < XZ_MAGIC.len() {
        return Err(PayloadError::TruncatedCiphertext);
    }
    let compressed = aes_ctr(ciphertext, key, &blob[12..20]);
    if !compressed.starts_with(XZ_MAGIC) {
        return Err(PayloadError::InvalidCompressedHeader);
    }

    let raw = match xdl_lzma_decompress(&compressed) {
        Ok(raw) => raw,
        Err(LzmaError::Truncated) => return Err(PayloadError::TruncatedCiphertext),
        Err(_) => return Err(PayloadError::InvalidCompressedPayload),
    };

    if raw.len() != declared_size {
        return Err(PayloadError::OutputSizeMismatch {
            actual: raw.len(),
            declared: declared_size,
        });
    }
    Ok(raw)
}

fn aes_ctr(data: &[u8], key: &[u8; 16], nonce: &[u8]) -> Vec<u8> {
    let round_keys = key_expand(key);
    let mut output = Vec::with_capacity(data.len());

    for (counter, chunk) in data.chunks(16).enumerate() {
        let mut counter_block = [0u8; 16];
        counter_block[..8].copy_from_slice(nonce);
        counter_block[8..].copy_from_slice(&(counter as u64).to_be_bytes());
        let keystream = aes_encrypt_block(counter_block, &round_keys);
        output.extend(
            chunk
                .iter()
                .zip(keystream)
                .map(|(byte, stream)| byte ^ stream),
        );
    }
    output
}

fn key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut words = [0u8; 176];
    words[..16].copy_from_slice(key);
    for index in 4..44 {
        let previous = (index - 1) * 4;
        let mut temp = [
            words[previous],
            words[previous + 1],
            words[previous + 2],
            words[previous + 3],
        ];
        if index % 4 == 0 {
            temp = [
                CUSTOM_SBOX[temp[1] as usize] ^ CUSTOM_RCON[index / 4],
                CUSTOM_SBOX[temp[2] as usize],
                CUSTOM_SBOX[temp[3] as usize],
                CUSTOM_SBOX[temp[0] as usize],
            ];
        }
        let prior = (index - 4) * 4;
        for offset in 0..4 {
            words[index * 4 + offset] = words[prior + offset] ^ temp[offset];
        }
    }

    let mut keys = [[0u8; 16]; 11];
    for (index, round_key) in keys.iter_mut().enumerate() {
        round_key.copy_from_slice(&words[index * 16..(index + 1) * 16]);
    }
    keys
}

fn aes_encrypt_block(mut state: [u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    add_round_key(&mut state, &round_keys[0]);
    for round_key in &round_keys[1..10] {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[10]);
    state
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for (byte, key_byte) in state.iter_mut().zip(round_key) {
        *byte ^= key_byte;
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = CUSTOM_SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let input = *state;
    *state = [
        input[0], input[5], input[10], input[15], input[4], input[9], input[14], input[3],
        input[8], input[13], input[2], input[7], input[12], input[1], input[6], input[11],
    ];
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in state.chunks_exact_mut(4) {
        let input = [column[0], column[1], column[2], column[3]];
        column.copy_from_slice(&[
            gmul(input[0], 2) ^ gmul(input[1], 3) ^ input[2] ^ input[3],
            input[0] ^ gmul(input[1], 2) ^ gmul(input[2], 3) ^ input[3],
            input[0] ^ input[1] ^ gmul(input[2], 2) ^ gmul(input[3], 3),
            gmul(input[0], 3) ^ input[1] ^ input[2] ^ gmul(input[3], 2),
        ]);
    }
}

fn gmul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            product ^= left;
        }
        right >>= 1;
        let high_bit = left & 0x80;
        left <<= 1;
        if high_bit != 0 {
            left ^= 0x1b;
        }
    }
    product
}
