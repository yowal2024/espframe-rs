use crc32fast::Hasher;

use super::DfcolError;

const HEADER_SIZE: usize = 64;
const ACTOR_SIZE: u64 = 92;
const MAX_FILE_SIZE: u64 = 1 << 30;
const MAX_GEOMETRY_RECORDS: u32 = 100_000;
const MAX_ACTORS: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfcolHeader {
    pub version: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub flags: u32,
    pub triangle_meshes: u32,
    pub height_fields: u32,
    pub boxes: u32,
    pub convexes: u32,
    pub actor_count: u32,
    pub payload_bytes: u64,
    pub payload_crc32: u32,
    pub header_crc32: u32,
}

impl DfcolHeader {
    #[allow(non_snake_case)] // PascalCase preserves the native DFCOL parser compatibility API.
    pub fn Parse(bytes: &[u8]) -> Result<Self, DfcolError> {
        if bytes.len() < HEADER_SIZE {
            return Err(DfcolError::new("DFCOL header is truncated"));
        }
        if &bytes[..8] != b"DFCOL\r\n\x1a" {
            return Err(DfcolError::new("invalid DFCOL magic"));
        }
        let header = Self {
            version: read_u32(bytes, 8),
            header_size: read_u32(bytes, 12),
            endian_tag: read_u32(bytes, 16),
            flags: read_u32(bytes, 20),
            triangle_meshes: read_u32(bytes, 24),
            height_fields: read_u32(bytes, 28),
            boxes: read_u32(bytes, 32),
            convexes: read_u32(bytes, 36),
            actor_count: read_u32(bytes, 40),
            payload_bytes: read_u64(bytes, 48),
            payload_crc32: read_u32(bytes, 56),
            header_crc32: read_u32(bytes, 60),
        };
        if header.version != 1 {
            return Err(DfcolError::new("unsupported DFCOL version"));
        }
        if header.header_size as usize != HEADER_SIZE {
            return Err(DfcolError::new("invalid header size"));
        }
        if header.endian_tag != 0x0102_0304 {
            return Err(DfcolError::new("invalid endian tag"));
        }
        if header.flags != 1 {
            return Err(DfcolError::new("unsupported DFCOL flags"));
        }
        if [
            header.triangle_meshes,
            header.height_fields,
            header.boxes,
            header.convexes,
        ]
        .into_iter()
        .any(|count| count > MAX_GEOMETRY_RECORDS)
        {
            return Err(DfcolError::new(
                "geometry record count exceeds resource limit",
            ));
        }
        if header.actor_count == 0 || header.actor_count > MAX_ACTORS {
            return Err(DfcolError::new("invalid actor count"));
        }
        if read_u32(bytes, 44) != 0 {
            return Err(DfcolError::new("nonzero reserved field"));
        }
        if header.payload_bytes > MAX_FILE_SIZE - HEADER_SIZE as u64
            || header.payload_bytes != bytes.len().saturating_sub(HEADER_SIZE) as u64
            || bytes.len() as u64 > MAX_FILE_SIZE
        {
            return Err(DfcolError::new("DFCOL physical size mismatch"));
        }
        let mut hasher = Hasher::new();
        hasher.update(&bytes[..60]);
        if hasher.finalize() != header.header_crc32 {
            return Err(DfcolError::new("header CRC32 mismatch"));
        }
        let mut payload_hasher = Hasher::new();
        payload_hasher.update(&bytes[HEADER_SIZE..]);
        if payload_hasher.finalize() != header.payload_crc32 {
            return Err(DfcolError::new("payload CRC32 mismatch"));
        }
        let minimum_bytes = u64::from(header.triangle_meshes) * 12
            + u64::from(header.height_fields) * 24
            + u64::from(header.boxes) * 12
            + u64::from(header.convexes) * 12
            + u64::from(header.actor_count) * ACTOR_SIZE;
        if minimum_bytes > header.payload_bytes {
            return Err(DfcolError::new("section counts cannot fit in payload"));
        }
        Ok(header)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
