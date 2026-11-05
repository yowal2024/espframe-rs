#![allow(non_snake_case)]

use crc32fast::Hasher;
use flate2::{Decompress, FlushDecompress, Status};

use super::DfcolError;

const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const VERSION_NEEDED: u16 = 20;
const DEFLATE_METHOD: u16 = 8;
const ENCRYPTED_FLAG: u16 = 1;
const DATA_DESCRIPTOR_FLAG: u16 = 1 << 3;
const ALLOWED_FLAGS: u16 = (1 << 1) | (1 << 2) | (1 << 11);
const LOCAL_HEADER_SIZE: usize = 30;
const CENTRAL_HEADER_SIZE: usize = 46;
const EOCD_SIZE: usize = 22;
pub const MAX_ARCHIVE_SIZE: usize = 128 * 1024 * 1024;
const MAX_ENTRY_SIZE: usize = 256 * 1024 * 1024;
const INFLATE_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfcolZipModel {
    pub map_name: &'static str,
    pub entry_name: &'static str,
}

const MODELS: [DfcolZipModel; 7] = [
    DfcolZipModel {
        map_name: "AZ-5",
        entry_name: "AZ-5.dfcol",
    },
    DfcolZipModel {
        map_name: "Brakkesh",
        entry_name: "Brakkesh.dfcol",
    },
    DfcolZipModel {
        map_name: "Dam_Iris",
        entry_name: "Dam_Iris.dfcol",
    },
    DfcolZipModel {
        map_name: "Forrest",
        entry_name: "Forrest.dfcol",
    },
    DfcolZipModel {
        map_name: "SecretService",
        entry_name: "SecretService.dfcol",
    },
    DfcolZipModel {
        map_name: "SpaceCenter",
        entry_name: "SpaceCenter.dfcol",
    },
    DfcolZipModel {
        map_name: "Tide",
        entry_name: "Tide.dfcol",
    },
];

pub fn DfcolZipModels() -> &'static [DfcolZipModel; 7] {
    &MODELS
}

#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    local_header_offset: u32,
    data_offset: u32,
    compressed_size: u32,
    raw_size: u32,
    crc32: u32,
    flags: u16,
    modified_time: u16,
    modified_date: u16,
}

pub struct DfcolArchive<'a> {
    bytes: &'a [u8],
    entries: [Entry; 7],
    valid: bool,
}

impl<'a> DfcolArchive<'a> {
    pub fn Open(bytes: &'a [u8]) -> Result<Self, DfcolError> {
        if bytes.len() < EOCD_SIZE {
            return Err(DfcolError::new("ZIP is shorter than EOCD"));
        }
        if bytes.len() > MAX_ARCHIVE_SIZE {
            return Err(DfcolError::new("ZIP exceeds the pack size limit"));
        }
        let eocd_offset = bytes.len() - EOCD_SIZE;
        let eocd = &bytes[eocd_offset..];
        if read_u32(eocd, 0)? != EOCD_SIGNATURE {
            return Err(DfcolError::new(
                "ZIP EOCD is missing or trailing data is present",
            ));
        }
        if read_u16(eocd, 4)? != 0 || read_u16(eocd, 6)? != 0 {
            return Err(DfcolError::new("multi-disk ZIP is unsupported"));
        }
        let entries_on_disk = read_u16(eocd, 8)?;
        let entry_count = read_u16(eocd, 10)?;
        if entries_on_disk != 7 || entry_count != 7 || entries_on_disk != entry_count {
            return Err(DfcolError::new("ZIP must contain exactly seven entries"));
        }
        if read_u16(eocd, 20)? != 0 {
            return Err(DfcolError::new("ZIP archive comments are unsupported"));
        }
        let central_size = read_u32(eocd, 12)? as usize;
        let central_offset = read_u32(eocd, 16)? as usize;
        if central_size == u32::MAX as usize || central_offset == u32::MAX as usize {
            return Err(DfcolError::new("ZIP64 is unsupported"));
        }
        if !in_range(central_offset, central_size, eocd_offset)
            || central_offset + central_size != eocd_offset
        {
            return Err(DfcolError::new(
                "central directory range is invalid or has padding",
            ));
        }

        let mut entries = [Entry::default(); 7];
        let mut seen = [false; 7];
        let mut cursor = central_offset;
        for _ in 0..7 {
            if !in_range(cursor, CENTRAL_HEADER_SIZE, eocd_offset) {
                return Err(DfcolError::new("central directory header is truncated"));
            }
            let header = &bytes[cursor..cursor + CENTRAL_HEADER_SIZE];
            if read_u32(header, 0)? != CENTRAL_HEADER_SIGNATURE {
                return Err(DfcolError::new("central directory signature is invalid"));
            }
            let version_needed = read_u16(header, 6)?;
            let flags = read_u16(header, 8)?;
            let method = read_u16(header, 10)?;
            let modified_time = read_u16(header, 12)?;
            let modified_date = read_u16(header, 14)?;
            let crc32 = read_u32(header, 16)?;
            let compressed_size = read_u32(header, 20)?;
            let raw_size = read_u32(header, 24)?;
            let name_length = read_u16(header, 28)? as usize;
            let extra_length = read_u16(header, 30)? as usize;
            let comment_length = read_u16(header, 32)? as usize;
            let disk_start = read_u16(header, 34)?;
            let local_header_offset = read_u32(header, 42)?;
            if version_needed != VERSION_NEEDED {
                return Err(DfcolError::new("entry requires an unsupported ZIP version"));
            }
            if method != DEFLATE_METHOD {
                return Err(DfcolError::new("every entry must use DEFLATE"));
            }
            if flags & ENCRYPTED_FLAG != 0 {
                return Err(DfcolError::new("encrypted ZIP is unsupported"));
            }
            if flags & DATA_DESCRIPTOR_FLAG != 0 {
                return Err(DfcolError::new("ZIP data descriptors are unsupported"));
            }
            if flags & !ALLOWED_FLAGS != 0 {
                return Err(DfcolError::new("unsupported ZIP flags are set"));
            }
            if compressed_size == 0
                || compressed_size == u32::MAX
                || raw_size == u32::MAX
                || local_header_offset == u32::MAX
            {
                return Err(DfcolError::new(
                    "entry uses an invalid or ZIP64 size/offset",
                ));
            }
            if comment_length != 0 {
                return Err(DfcolError::new("ZIP entry comments are unsupported"));
            }
            if disk_start != 0 {
                return Err(DfcolError::new("multi-disk ZIP entry is unsupported"));
            }
            let variable_length = name_length
                .checked_add(extra_length)
                .and_then(|value| value.checked_add(comment_length))
                .ok_or_else(|| DfcolError::new("central directory variable fields overflow"))?;
            if !in_range(cursor + CENTRAL_HEADER_SIZE, variable_length, eocd_offset) {
                return Err(DfcolError::new(
                    "central directory variable fields are truncated",
                ));
            }
            let name_start = cursor + CENTRAL_HEADER_SIZE;
            let name = &bytes[name_start..name_start + name_length];
            validate_extra_fields(
                &bytes[name_start + name_length..name_start + name_length + extra_length],
            )?;
            let model_index = find_model_bytes(name)
                .ok_or_else(|| DfcolError::new("ZIP has an unknown or unsafe entry name"))?;
            if seen[model_index] {
                return Err(DfcolError::new("ZIP has a duplicate entry name"));
            }
            seen[model_index] = true;
            if raw_size == 0 || raw_size as usize > MAX_ENTRY_SIZE {
                return Err(DfcolError::new("entry exceeds the uncompressed size limit"));
            }
            entries[model_index] = Entry {
                local_header_offset,
                data_offset: 0,
                compressed_size,
                raw_size,
                crc32,
                flags,
                modified_time,
                modified_date,
            };
            cursor += CENTRAL_HEADER_SIZE + variable_length;
        }
        if cursor != eocd_offset {
            return Err(DfcolError::new("central directory has unparsed data"));
        }
        if seen.iter().any(|seen| !seen) {
            return Err(DfcolError::new("ZIP is missing a canonical entry"));
        }

        for (index, entry) in entries.iter_mut().enumerate() {
            let local_offset = entry.local_header_offset as usize;
            if !in_range(local_offset, LOCAL_HEADER_SIZE, central_offset) {
                return Err(DfcolError::new("local ZIP header is outside the file area"));
            }
            let local = &bytes[local_offset..local_offset + LOCAL_HEADER_SIZE];
            if read_u32(local, 0)? != LOCAL_HEADER_SIGNATURE {
                return Err(DfcolError::new("local ZIP header signature is invalid"));
            }
            let name_length = read_u16(local, 26)? as usize;
            let extra_length = read_u16(local, 28)? as usize;
            let model = MODELS[index];
            if read_u16(local, 4)? != VERSION_NEEDED
                || read_u16(local, 6)? != entry.flags
                || read_u16(local, 8)? != DEFLATE_METHOD
                || read_u16(local, 10)? != entry.modified_time
                || read_u16(local, 12)? != entry.modified_date
                || read_u32(local, 14)? != entry.crc32
                || read_u32(local, 18)? != entry.compressed_size
                || read_u32(local, 22)? != entry.raw_size
            {
                return Err(DfcolError::new("local and central ZIP metadata differ"));
            }
            if name_length != model.entry_name.len() {
                return Err(DfcolError::new("local ZIP entry name length differs"));
            }
            let extra_offset = local_offset
                .checked_add(LOCAL_HEADER_SIZE)
                .and_then(|value| value.checked_add(name_length))
                .ok_or_else(|| DfcolError::new("local ZIP entry offset overflow"))?;
            let data_offset = extra_offset
                .checked_add(extra_length)
                .ok_or_else(|| DfcolError::new("local ZIP extra field range overflow"))?;
            if !in_range(
                local_offset + LOCAL_HEADER_SIZE,
                name_length,
                central_offset,
            ) || !in_range(extra_offset, extra_length, central_offset)
                || !in_range(data_offset, entry.compressed_size as usize, central_offset)
            {
                return Err(DfcolError::new("local ZIP entry data is truncated"));
            }
            if bytes[local_offset + LOCAL_HEADER_SIZE..extra_offset] != *model.entry_name.as_bytes()
            {
                return Err(DfcolError::new(
                    "local ZIP entry name differs from central directory",
                ));
            }
            validate_extra_fields(&bytes[extra_offset..data_offset])?;
            entry.data_offset = data_offset as u32;
        }

        let mut order: Vec<usize> = (0..7).collect();
        order.sort_by_key(|index| entries[*index].local_header_offset);
        let mut expected_offset = 0usize;
        for index in order {
            let entry = entries[index];
            if entry.local_header_offset as usize != expected_offset {
                return Err(DfcolError::new(
                    "ZIP local entries contain an overlap, gap, or hidden data",
                ));
            }
            expected_offset = entry.data_offset as usize + entry.compressed_size as usize;
        }
        if expected_offset != central_offset {
            return Err(DfcolError::new(
                "junk exists between ZIP file data and central directory",
            ));
        }

        Ok(Self {
            bytes,
            entries,
            valid: true,
        })
    }

    pub fn Valid(&self) -> bool {
        self.valid
    }

    pub fn StoredSize(&self) -> usize {
        self.bytes.len()
    }

    pub fn EntryCount(&self) -> usize {
        MODELS.len()
    }

    pub fn Inflate(&self, entry_name: &str) -> Result<Vec<u8>, DfcolError> {
        if !self.valid {
            return Err(DfcolError::new("ZIP archive view is not valid"));
        }
        let model_index = find_model(entry_name)
            .ok_or_else(|| DfcolError::new("requested ZIP entry is unknown"))?;
        let entry = self.entries[model_index];
        let expected_raw_size = entry.raw_size as usize;
        let start = entry.data_offset as usize;
        let end = start
            .checked_add(entry.compressed_size as usize)
            .ok_or_else(|| DfcolError::new("validated ZIP entry range overflow"))?;
        if end > self.bytes.len() {
            return Err(DfcolError::new(
                "validated ZIP entry range is no longer valid",
            ));
        }

        let mut output = Vec::new();
        output
            .try_reserve_exact(expected_raw_size)
            .map_err(|_| DfcolError::new("unable to allocate ZIP entry"))?;
        output.resize(expected_raw_size, 0);
        let mut overflow = [0u8; 1];
        // false selects a raw DEFLATE stream, matching inflateInit2(-MAX_WBITS).
        let mut decoder = Decompress::new(false);
        let input = &self.bytes[start..end];
        let mut last_in = 0u64;
        let mut last_out = 0u64;
        let status = loop {
            let produced = decoder.total_out() as usize;
            let destination: &mut [u8] = if produced < expected_raw_size {
                let end = produced
                    .saturating_add(INFLATE_CHUNK_SIZE)
                    .min(expected_raw_size);
                &mut output[produced..end]
            } else {
                &mut overflow
            };
            let consumed = decoder.total_in() as usize;
            let input_end = consumed.saturating_add(INFLATE_CHUNK_SIZE).min(input.len());
            let flush = if input_end == input.len() {
                FlushDecompress::Finish
            } else {
                FlushDecompress::None
            };
            let status = decoder
                .decompress(&input[consumed..input_end], destination, flush)
                .map_err(|_| DfcolError::new("DEFLATE stream is invalid"))?;
            if decoder.total_out() as usize > expected_raw_size {
                return Err(DfcolError::new("DEFLATE output exceeds the ZIP entry size"));
            }
            if status == Status::StreamEnd {
                break status;
            }
            if decoder.total_in() == last_in && decoder.total_out() == last_out {
                return Err(DfcolError::new("DEFLATE decoder made no progress"));
            }
            last_in = decoder.total_in();
            last_out = decoder.total_out();
        };
        if status != Status::StreamEnd
            || decoder.total_in() as usize != input.len()
            || decoder.total_out() as usize != expected_raw_size
        {
            return Err(DfcolError::new(
                "DEFLATE stream has a size mismatch or trailing bytes",
            ));
        }
        let mut hasher = Hasher::new();
        hasher.update(&output);
        if hasher.finalize() != entry.crc32 {
            return Err(DfcolError::new("inflated DFCOL CRC-32 mismatch"));
        }
        Ok(output)
    }
}

fn validate_extra_fields(bytes: &[u8]) -> Result<(), DfcolError> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !in_range(cursor, 4, bytes.len()) {
            return Err(DfcolError::new("ZIP extra field header is truncated"));
        }
        let kind = read_u16(bytes, cursor)?;
        let length = read_u16(bytes, cursor + 2)? as usize;
        cursor += 4;
        if !in_range(cursor, length, bytes.len()) {
            return Err(DfcolError::new("ZIP extra field data is truncated"));
        }
        if kind == 0x0001 {
            return Err(DfcolError::new("ZIP64 extra fields are unsupported"));
        }
        // Timestamps and other metadata do not affect ZIP32 names, sizes or data.
        // Never use an extra field to override the validated canonical filename.
        cursor += length;
    }
    Ok(())
}

fn find_model(name: &str) -> Option<usize> {
    MODELS.iter().position(|model| model.entry_name == name)
}

fn find_model_bytes(name: &[u8]) -> Option<usize> {
    MODELS
        .iter()
        .position(|model| model.entry_name.as_bytes() == name)
}

fn in_range(offset: usize, length: usize, total: usize) -> bool {
    offset <= total && length <= total - offset
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DfcolError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| DfcolError::new("ZIP field is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DfcolError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| DfcolError::new("ZIP field is truncated"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
