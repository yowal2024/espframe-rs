use crate::soloader::error::{LoaderError, Result};

pub struct Sleb128Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Sleb128Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub fn decode(&mut self) -> Result<i64> {
        let mut value = 0i64;
        let mut shift = 0usize;
        let mut byte;

        loop {
            byte = *self.bytes.get(self.cursor).ok_or_else(|| {
                LoaderError::Link("failed to decode SLEB128: buffer overrun".into())
            })?;
            self.cursor += 1;
            if shift >= i64::BITS as usize {
                return Err(LoaderError::Link(
                    "failed to decode SLEB128: overlong value".into(),
                ));
            }
            value |= ((byte & 0x7f) as i64) << shift;
            shift += 7;

            if byte & 0x80 == 0 {
                break;
            }
        }

        if shift < i64::BITS as usize && (byte & 0x40) != 0 {
            value |= -1i64 << shift;
        }

        Ok(value)
    }
}
