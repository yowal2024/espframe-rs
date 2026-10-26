//! Strict DFCOL pack support.

mod archive;
mod bvh;
pub mod convex;
mod format;
mod registry;
mod sah;
mod scene;
pub mod upload;

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DfcolError(String);

impl DfcolError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for DfcolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for DfcolError {}

impl From<String> for DfcolError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for DfcolError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

pub use archive::{DfcolArchive, DfcolZipModel, DfcolZipModels};
pub use format::DfcolHeader;
pub use registry::{DfcolRegistry, PackBytes, PackStatus, PACK_STORED_BYTES};
pub use scene::{Scene, SceneStats};
pub use upload::{
    DfcolCall, DfcolError as UploadContractError, DfcolUploadError, DfcolUploader,
    KernelMemoryWriter, MemoryWriter, RemoteCalls, TargetResolver,
};
