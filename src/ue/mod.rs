#![allow(non_snake_case)]

pub mod extensions;
pub mod gnames;
pub mod name_array;
pub mod transform;
pub mod uobject;
pub mod ustruct;

pub use crate::math::{Mat4, Quat, Rotator, Transform, Vec2, Vec3};
pub use crate::projection::{
    in_extended_screen, world_to_screen, world_to_screen_matrix, Camera, Viewport,
};
pub use extensions::{FName, TArrayHeader, UClass};
pub use gnames::GNames;
pub use name_array::{
    LittleEndianNameCodec, NameArray, NameArrayProfile, NameCodec, NameEntryAddress,
};
pub use transform::{
    KernelTransformReader, LittleEndianTransformCodec, StandardTransformCodec, TransformCodec,
    TransformLayout,
};
pub use uobject::UObject;
pub use ustruct::UStruct;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ReflectionError {
    #[error("invalid UE object address")]
    InvalidAddress,
    #[error("UE memory read failed at {address:#x} for {size} bytes")]
    MemoryRead { address: u64, size: usize },
    #[error("UE offset arithmetic overflow")]
    ArithmeticOverflow,
    #[error("UE offset value is invalid")]
    InvalidOffset,
    #[error("invalid UE transform layout")]
    InvalidTransformLayout,
    #[error("UE transform decode failed")]
    TransformDecode,
    #[error("UE FName decode failed")]
    NameDecode,
    #[error("invalid UE FName profile")]
    InvalidNameProfile,
}
