//! Android-facing facade for EspFrame.
//!
//! Native window ownership lives in [`crate::window`].  This module only
//! exposes the Android-specific aliases needed by a host; it intentionally
//! does not provide a second renderer/backend implementation.

pub use crate::error::AndroidError;
#[cfg(target_os = "android")]
pub use crate::window::input::KernelInputBackend;
#[cfg(target_os = "android")]
pub use crate::window::surface::AndroidSurfaceComposerBackend;
pub use crate::window::{NativeWindow, NativeWindowService, SurfaceConfig, SurfaceHandle};

/// Raw `ANativeWindow` handle consumed by EGL on Android.
pub type NativeWindowHandle = *mut core::ffi::c_void;
