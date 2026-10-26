//! SurfaceFlinger Skia rendering; same frame and texture API as AndroidBackend.
//! ImGui stays on its owner thread. GPU objects and borrowed canvases stay in RE.
#[cfg(target_os = "android")]
mod abi;
#[cfg(any(test, target_os = "android"))]
mod layout;
#[cfg(target_os = "android")]
mod legacy;
mod frame;
#[cfg(any(test, target_os = "android"))]
mod frame_scope;
#[cfg(any(test, target_os = "android"))]
mod geometry;
#[cfg(target_os = "android")]
mod hooks;
#[cfg(any(test, target_os = "android"))]
mod profile;
#[cfg(target_os = "android")]
mod repaint;
#[cfg(target_os = "android")]
mod scene;
#[cfg(all(target_os = "android", feature = "binder"))]
mod window;
#[cfg(all(target_os = "android", feature = "binder"))]
pub use window::SkiaWindowBackend;
#[cfg(any(test, target_os = "android"))]
mod quiescence;
#[cfg(target_os = "android")]
pub use hooks::initialize;

use crate::{render::RenderError, window::Size};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
static LATEST: Mutex<Option<Arc<frame::Frame>>> = Mutex::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static FILTER: AtomicBool = AtomicBool::new(true);

// These distinct callback addresses are command markers consumed by snapshot().
// They are never called on RenderEngine, which has no ImGui context.
#[cfg(any(test, target_os = "android"))]
unsafe extern "C" fn sampler_linear(
    _: *const imgui::sys::ImDrawList,
    _: *const imgui::sys::ImDrawCmd,
) {
    std::hint::black_box(0u8);
}
#[cfg(any(test, target_os = "android"))]
unsafe extern "C" fn sampler_nearest(
    _: *const imgui::sys::ImDrawList,
    _: *const imgui::sys::ImDrawCmd,
) {
    std::hint::black_box(1u8);
}
#[cfg(any(test, target_os = "android"))]
unsafe fn sampler_callbacks(enabled: bool) {
    let platform = imgui::sys::igGetPlatformIO_Nil();
    (*platform).DrawCallback_SetSamplerLinear = if enabled { Some(sampler_linear) } else { None };
    (*platform).DrawCallback_SetSamplerNearest = if enabled { Some(sampler_nearest) } else { None };
}

pub struct SkiaBackend {
    initialized: bool,
    textures: BTreeMap<u32, Arc<frame::Texture>>,
    next_texture: u32,
    pending: Option<Arc<frame::Frame>>,
    #[cfg(target_os = "android")]
    repaint: Option<repaint::Repaint>,
}
impl Default for SkiaBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl SkiaBackend {
    pub fn new() -> Self {
        Self {
            initialized: false,
            textures: BTreeMap::new(),
            next_texture: 1,
            pending: None,
            #[cfg(target_os = "android")]
            repaint: None,
        }
    }
    /// # Safety
    /// window is the opaque token from SkiaWindowBackend, never an ANativeWindow.
    /// The current ImGui context must outlive this backend.
    pub unsafe fn initialize(
        &mut self,
        window: crate::android::NativeWindowHandle,
        size: Size,
    ) -> Result<(), RenderError> {
        self.shutdown();
        if window.is_null() || !size.IsValid() {
            return Err(RenderError::InvalidSurface);
        }
        #[cfg(target_os = "android")]
        {
            if !hooks::installed() {
                return Err(RenderError::Device(
                    "Skia hooks were not installed by the injector".into(),
                ));
            }
            let io = imgui::sys::igGetIO_Nil();
            if io.is_null() {
                return Err(RenderError::NotInitialized);
            }
            let repaint = repaint::Repaint::open().map_err(RenderError::Device)?;
            if ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(RenderError::Device("Skia backend already active".into()));
            }
            self.repaint = Some(repaint);
            (*io).BackendFlags |= imgui::sys::ImGuiBackendFlags_RendererHasVtxOffset as i32;
            (*io).BackendFlags &= !(imgui::sys::ImGuiBackendFlags_RendererHasTextures as i32);
            sampler_callbacks(true);
            self.initialized = true;
            Ok(())
        }
        #[cfg(not(target_os = "android"))]
        {
            Err(RenderError::Device(
                "Skia requires SurfaceFlinger on Android".into(),
            ))
        }
    }
    pub fn begin_frame(&mut self) -> Result<(), RenderError> {
        if !self.initialized {
            return Err(RenderError::NotInitialized);
        }
        self.pending = None;
        Ok(())
    }
    pub fn render(&mut self, data: &imgui::DrawData) -> Result<(), RenderError> {
        if !self.initialized {
            return Err(RenderError::NotInitialized);
        }
        self.pending = Some(Arc::new(frame::snapshot(data, &self.textures)?));
        Ok(())
    }
    pub fn present(&mut self) -> Result<(), RenderError> {
        if !self.initialized {
            return Err(RenderError::NotInitialized);
        }
        *LATEST
            .lock()
            .map_err(|_| RenderError::Device("Skia frame lock".into()))? = self.pending.take();
        #[cfg(target_os = "android")]
        self.repaint
            .as_mut()
            .ok_or(RenderError::NotInitialized)?
            .tick()
            .map_err(RenderError::Device)?;
        Ok(())
    }
    pub fn upload_texture(
        &mut self,
        width: u32,
        height: u32,
        pixels: &[u8],
    ) -> Result<u32, RenderError> {
        if !self.initialized {
            return Err(RenderError::NotInitialized);
        }
        if width == 0
            || height == 0
            || width > 16384
            || height > 16384
            || Some(pixels.len())
                != (width as usize)
                    .checked_mul(height as usize)
                    .and_then(|n| n.checked_mul(4))
        {
            return Err(RenderError::InvalidTexture);
        }
        let id = self.next_texture;
        self.next_texture = id.checked_add(1).ok_or(RenderError::InvalidTexture)?;
        self.textures.insert(
            id,
            Arc::new(frame::Texture {
                width,
                height,
                pixels: pixels.to_vec(),
            }),
        );
        Ok(id)
    }
    pub fn delete_texture(&mut self, id: u32) -> Result<bool, RenderError> {
        Ok(self.textures.remove(&id).is_some())
    }
    pub fn shutdown(&mut self) {
        if self.initialized {
            if let Ok(mut frame) = LATEST.lock() {
                *frame = None;
            }
            ACTIVE.store(false, Ordering::Release);
            #[cfg(target_os = "android")]
            {
                unsafe {
                    sampler_callbacks(false);
                }
                if let Some(mut repaint) = self.repaint.take() {
                    let _ = repaint.tick();
                }
            }
        }
        self.initialized = false;
        self.pending = None;
        self.textures.clear();
    }
}
impl Drop for SkiaBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}
