#![allow(non_snake_case)]

#[cfg(any(all(target_os = "android", feature = "binder"), test))]
mod binder_display_codec;
pub mod display;
pub mod input;
mod input_hook;
pub(crate) mod mirror;
#[cfg(all(target_os = "android", feature = "binder"))]
mod mirror_binder;
#[cfg(feature = "jni")]
mod mirror_jni;
pub mod surface;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowError {
    #[error("surface composer operation is unavailable")]
    Unsupported,
    #[error("android ABI symbol unavailable: {0}")]
    AbiUnavailable(&'static str),
    #[error("invalid window size")]
    InvalidSize,
    #[error("surface composer operation failed: {0}")]
    Backend(String),
    #[error("service is already stopped")]
    Stopped,
}

pub use display::{DisplayInfo, Orientation, Size};
pub use mirror::{DisplayQueryMode, DisplaySnapshot};

/// Query framework displays without a JavaVM (Android 12-16 only).
#[cfg(all(target_os = "android", feature = "binder"))]
pub fn query_displays_native() -> Result<Vec<DisplaySnapshot>, WindowError> {
    mirror_binder::NativeDisplayClient::default().snapshot(mirror_binder::android_sdk()?)
}
#[cfg(target_os = "android")]
pub use input::KernelInputBackend;
pub use input::{InputBackend, InputEvent, InputService};
pub use input_hook::VolumeKeyHook;
pub use input_hook::{android_volume_key_event, VolumeHookError, VolumeHookPlatform};
#[cfg(target_os = "android")]
pub use surface::AndroidSurfaceComposerBackend;
pub use surface::{
    NativeWindow, NativeWindowService, SurfaceComposerBackend, SurfaceConfig, SurfaceHandle,
};
