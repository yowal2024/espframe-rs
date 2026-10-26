//! UE `FTransform` memory layouts and codecs.
//!
//! The bytes in a game process are deliberately kept separate from the
//! canonical [`crate::math::Transform`] type.  A host may provide a codec for
//! packed, obfuscated, or otherwise non-standard transforms; the built-in
//! codec only handles the usual little-endian three-float layout.

use crate::kernel::MemoryAccess;
use crate::math::{Quat, Transform, Vec3};

use super::ReflectionError;

const QUAT_SIZE: usize = 4 * std::mem::size_of::<f32>();
const VECTOR_SIZE: usize = 3 * std::mem::size_of::<f32>();

/// Byte offsets for the three logical values in a UE transform.
///
/// `read_size` is the number of bytes fetched for one transform.  `stride` is
/// the distance to the next transform in an array and must be at least
/// `read_size`.  Padding (for example the fourth float in an `FVector`) is
/// therefore represented by the layout rather than by the canonical math
/// type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformLayout {
    pub rotation_offset: usize,
    pub translation_offset: usize,
    pub scale_offset: usize,
    pub read_size: usize,
    pub stride: usize,
}

impl Default for TransformLayout {
    fn default() -> Self {
        Self::standard()
    }
}

impl TransformLayout {
    pub const fn new(
        rotation_offset: usize,
        translation_offset: usize,
        scale_offset: usize,
        read_size: usize,
        stride: usize,
    ) -> Self {
        Self {
            rotation_offset,
            translation_offset,
            scale_offset,
            read_size,
            stride,
        }
    }

    /// The packed DFM wire layout used by the current main branch: `FQuat`
    /// (16 bytes), followed by two 12-byte `FVector` values.  Arrays may add
    /// eight bytes of tail padding, so the field area is 40 bytes and the
    /// default stride is 48 bytes.
    pub const fn standard() -> Self {
        Self::new(0, 16, 28, 40, 48)
    }

    /// Alias retained for callers that use UE terminology.
    pub const fn ue4() -> Self {
        Self::standard()
    }

    /// A variant used by builds that align each vector to a 16-byte slot.
    /// Hosts must select this only when the authenticated layout describes
    /// that ABI; it is not inferred from target memory.
    pub const fn aligned_ue4() -> Self {
        Self::new(0, 16, 32, 48, 48)
    }

    /// Validate field bounds and array stride before reading process memory.
    pub fn validate(&self) -> Result<(), ReflectionError> {
        if self.read_size == 0 || self.stride < self.read_size {
            return Err(ReflectionError::InvalidTransformLayout);
        }
        let fields = [
            (self.rotation_offset, QUAT_SIZE),
            (self.translation_offset, VECTOR_SIZE),
            (self.scale_offset, VECTOR_SIZE),
        ];
        if fields.iter().any(|(offset, size)| {
            offset
                .checked_add(*size)
                .map_or(true, |end| end > self.read_size)
        }) {
            return Err(ReflectionError::InvalidTransformLayout);
        }
        Ok(())
    }

    pub const fn rotation(&self) -> usize {
        self.rotation_offset
    }

    pub const fn translation(&self) -> usize {
        self.translation_offset
    }

    pub const fn scale3d(&self) -> usize {
        self.scale_offset
    }

    pub const fn scale3d_offset(&self) -> usize {
        self.scale_offset
    }
}

/// Decodes one raw transform record into the canonical math representation.
///
/// Implementations are intentionally host-supplied for encrypted, magic, or
/// otherwise custom `FTransform` encodings.
pub trait TransformCodec {
    fn decode(&self, bytes: &[u8], layout: &TransformLayout) -> Result<Transform, ReflectionError>;
}

/// Standard little-endian codec for UE's float-backed transform fields.
#[derive(Clone, Copy, Debug, Default)]
pub struct LittleEndianTransformCodec;

/// Descriptive alias for the built-in codec.
pub type StandardTransformCodec = LittleEndianTransformCodec;

impl TransformCodec for LittleEndianTransformCodec {
    fn decode(&self, bytes: &[u8], layout: &TransformLayout) -> Result<Transform, ReflectionError> {
        layout.validate()?;
        if bytes.len() < layout.read_size {
            return Err(ReflectionError::TransformDecode);
        }
        let read_f32 = |offset: usize| -> f32 {
            let mut raw = [0_u8; 4];
            raw.copy_from_slice(&bytes[offset..offset + 4]);
            f32::from_le_bytes(raw)
        };
        let q = layout.rotation_offset;
        let t = layout.translation_offset;
        let s = layout.scale_offset;
        Ok(Transform::new(
            Quat::new(
                read_f32(q),
                read_f32(q + 4),
                read_f32(q + 8),
                read_f32(q + 12),
            ),
            Vec3::new(read_f32(t), read_f32(t + 4), read_f32(t + 8)),
            Vec3::new(read_f32(s), read_f32(s + 4), read_f32(s + 8)),
        ))
    }
}

/// Reads transform bytes through the configured [`MemoryAccess`] implementation.
pub struct KernelTransformReader<'a, M: MemoryAccess + ?Sized, C = LittleEndianTransformCodec> {
    driver: &'a M,
    base: u64,
    layout: TransformLayout,
    codec: C,
}

impl<'a, M: MemoryAccess + ?Sized> KernelTransformReader<'a, M, LittleEndianTransformCodec> {
    pub fn new(driver: &'a M, base: u64, layout: TransformLayout) -> Result<Self, ReflectionError> {
        Self::with_codec(driver, base, layout, LittleEndianTransformCodec)
    }

    pub fn New(driver: &'a M, base: u64, layout: TransformLayout) -> Result<Self, ReflectionError> {
        Self::new(driver, base, layout)
    }
}

impl<'a, M: MemoryAccess + ?Sized, C: TransformCodec> KernelTransformReader<'a, M, C> {
    pub fn with_codec(
        driver: &'a M,
        base: u64,
        layout: TransformLayout,
        codec: C,
    ) -> Result<Self, ReflectionError> {
        layout.validate()?;
        if base == 0 {
            return Err(ReflectionError::InvalidAddress);
        }
        Ok(Self {
            driver,
            base,
            layout,
            codec,
        })
    }

    pub fn WithCodec(
        driver: &'a M,
        base: u64,
        layout: TransformLayout,
        codec: C,
    ) -> Result<Self, ReflectionError> {
        Self::with_codec(driver, base, layout, codec)
    }

    pub fn layout(&self) -> TransformLayout {
        self.layout
    }

    pub fn read_at(&self, address: u64) -> Result<Transform, ReflectionError> {
        if address == 0 {
            return Err(ReflectionError::InvalidAddress);
        }
        let expected = isize::try_from(self.layout.read_size)
            .map_err(|_| ReflectionError::InvalidTransformLayout)?;
        let mut bytes = vec![0_u8; self.layout.read_size];
        if self.driver.read(address, &mut bytes, false) != expected {
            return Err(ReflectionError::MemoryRead {
                address,
                size: self.layout.read_size,
            });
        }
        self.codec.decode(&bytes, &self.layout)
    }

    pub fn ReadAt(&self, address: u64) -> Result<Transform, ReflectionError> {
        self.read_at(address)
    }

    pub fn read_transform(&self, address: u64) -> Result<Transform, ReflectionError> {
        self.read_at(address)
    }

    pub fn ReadTransform(&self, address: u64) -> Result<Transform, ReflectionError> {
        self.read_at(address)
    }

    pub fn read(&self, index: usize) -> Result<Transform, ReflectionError> {
        let offset = index
            .checked_mul(self.layout.stride)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        let offset = u64::try_from(offset).map_err(|_| ReflectionError::ArithmeticOverflow)?;
        let address = self
            .base
            .checked_add(offset)
            .ok_or(ReflectionError::ArithmeticOverflow)?;
        self.read_at(address)
    }

    pub fn Read(&self, index: usize) -> Result<Transform, ReflectionError> {
        self.read(index)
    }
}
