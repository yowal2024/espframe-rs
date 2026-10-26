//! GLES3/ImGui integration boundary.
//!
//! EspFrame delegates ImGui rendering to the official dear-imgui-rs backend
//! shims.  Host code owns menus and draw data; this module only describes the
//! small platform contract and does not issue extra GL state changes.

pub use crate::error::RenderError;

/// SurfaceFlinger Skia backend using the same frame/texture contract.
pub mod skia;

use crate::window::{NativeWindow, NativeWindowService, Size, SurfaceComposerBackend, WindowError};
#[cfg(target_os = "android")]
use std::collections::HashSet;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Default cadence used while the host is idle (60 Hz).
pub const DEFAULT_IDLE_FPS: u32 = 60;

/// The EGL configuration used by the Android GLES3 boundary.  The requested
/// config intentionally matches the established host contract; the context
/// itself is created with `EGL_CONTEXT_CLIENT_VERSION = 3` below.
#[cfg(any(test, target_os = "android"))]
pub const LEGACY_EGL_CONFIG_ATTRIBUTES: [i32; 17] = [
    0x3033, 0x0004, 0x3040, 0x0004, 0x3022, 5, 0x3023, 6, 0x3024, 5, 0x3020, 32, 0x3025, 16,
    0x3026, 8, 0x3038,
];

/// Owns only the Android EGL surface/context and the official ImGui backend
/// shims.  UI construction, menus, gameplay primitives, and draw scheduling
/// remain with the caller (`EspFrameManager`); this boundary accepts finished
/// ImGui draw data and submits it unchanged.
#[cfg(target_os = "android")]
pub struct AndroidBackend {
    display: *mut std::ffi::c_void,
    surface: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
    platform_ready: bool,
    renderer_ready: bool,
    textures: HashSet<u32>,
}

#[cfg(target_os = "android")]
impl AndroidBackend {
    pub fn new() -> Self {
        Self {
            display: std::ptr::null_mut(),
            surface: std::ptr::null_mut(),
            context: std::ptr::null_mut(),
            platform_ready: false,
            renderer_ready: false,
            textures: HashSet::new(),
        }
    }

    /// # Safety
    /// `window` must be a live ANativeWindow until shutdown. The current ImGui
    /// context must outlive this backend and be current for its operations.
    pub unsafe fn initialize(
        &mut self,
        window: crate::android::NativeWindowHandle,
        size: Size,
    ) -> Result<(), RenderError> {
        if window.is_null() || !size.IsValid() {
            return Err(RenderError::InvalidSurface);
        }
        if unsafe { dear_imgui_sys::igGetCurrentContext().is_null() } {
            return Err(RenderError::NotInitialized);
        }
        let (width, height) = (
            i32::try_from(size.width).map_err(|_| RenderError::InvalidSurface)?,
            i32::try_from(size.height).map_err(|_| RenderError::InvalidSurface)?,
        );
        self.shutdown();
        // Raw GL names only identify textures within their original context.
        self.textures.clear();
        let display = unsafe { eglGetDisplay(std::ptr::null_mut()) };
        if display.is_null() {
            return Err(Self::egl_error("eglGetDisplay"));
        }
        self.display = display;
        let (mut major, mut minor) = (0, 0);
        if unsafe { eglInitialize(display, &mut major, &mut minor) } == 0 {
            return self.fail_initialize("eglInitialize");
        }
        let mut config = std::ptr::null_mut();
        let mut count = 0;
        if unsafe {
            eglChooseConfig(
                display,
                LEGACY_EGL_CONFIG_ATTRIBUTES.as_ptr(),
                &mut config,
                1,
                &mut count,
            )
        } == 0
            || count == 0
        {
            return self.fail_initialize("eglChooseConfig");
        }
        let mut visual = 0;
        if unsafe { eglGetConfigAttrib(display, config, 0x302e, &mut visual) } == 0 {
            return self.fail_initialize("eglGetConfigAttrib(EGL_NATIVE_VISUAL_ID)");
        }
        if unsafe { ANativeWindow_setBuffersGeometry(window, width, height, visual) } != 0 {
            self.shutdown();
            return Err(RenderError::Device(
                "ANativeWindow_setBuffersGeometry".to_owned(),
            ));
        }
        let context = unsafe {
            eglCreateContext(
                display,
                config,
                std::ptr::null_mut(),
                [0x3098, 3, 0x3038].as_ptr(),
            )
        };
        if context.is_null() {
            return self.fail_initialize("eglCreateContext");
        }
        self.context = context;
        let surface = unsafe { eglCreateWindowSurface(display, config, window, [0x3038].as_ptr()) };
        if surface.is_null() {
            return self.fail_initialize("eglCreateWindowSurface");
        }
        self.surface = surface;
        if unsafe { eglMakeCurrent(display, surface, surface, context) } == 0 {
            return self.fail_initialize("eglMakeCurrent");
        }
        unsafe {
            glViewport(0, 0, width, height);
        }
        if unsafe {
            !dear_imgui_sys::backend_shim::android::dear_imgui_backend_android_init(window)
        } {
            self.shutdown();
            return Err(RenderError::Device(
                "ImGui Android backend init failed".to_owned(),
            ));
        }
        self.platform_ready = true;
        if unsafe {
            !dear_imgui_sys::backend_shim::opengl3::dear_imgui_backend_opengl3_init(
                c"#version 300 es".as_ptr(),
            )
        } {
            self.shutdown();
            return Err(RenderError::Device(
                "ImGui OpenGL3 backend init failed".to_owned(),
            ));
        }
        self.renderer_ready = true;
        // The host owns raw GL texture IDs; keep the official renderer in
        // legacy mode so it does not manage texture objects itself.
        unsafe {
            let io = dear_imgui_sys::igGetIO_Nil();
            if !io.is_null() {
                (*io).BackendFlags &= !(dear_imgui_sys::ImGuiBackendFlags_RendererHasTextures
                    as dear_imgui_sys::ImGuiBackendFlags);
            }
        }
        Ok(())
    }

    fn egl_error(stage: &str) -> RenderError {
        match unsafe { eglGetError() } {
            0x300e => RenderError::ContextLost,
            0x300d => RenderError::SurfaceLost,
            code => RenderError::Device(format!("{stage} (EGL 0x{code:04x})")),
        }
    }

    fn fail_initialize(&mut self, stage: &str) -> Result<(), RenderError> {
        let error = Self::egl_error(stage);
        self.shutdown();
        Err(error)
    }

    pub fn begin_frame(&mut self) -> Result<(), RenderError> {
        if self.display.is_null() {
            return Err(RenderError::NotInitialized);
        }
        unsafe {
            if self.renderer_ready {
                dear_imgui_sys::backend_shim::opengl3::dear_imgui_backend_opengl3_new_frame();
            }
            if self.platform_ready {
                dear_imgui_sys::backend_shim::android::dear_imgui_backend_android_new_frame();
            }
        }
        Ok(())
    }

    pub fn render(&mut self, draw_data: &imgui::DrawData) -> Result<(), RenderError> {
        if self.display.is_null() {
            return Err(RenderError::NotInitialized);
        }
        unsafe {
            glClearColor(0.0, 0.0, 0.0, 0.0);
            glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
            dear_imgui_sys::backend_shim::opengl3::dear_imgui_backend_opengl3_render_draw_data(
                draw_data as *const _ as *mut dear_imgui_sys::ImDrawData,
            );
        }
        Ok(())
    }

    /// Upload an application-owned RGBA8 texture into the current GLES context.
    /// The returned GL name is suitable for use as an ImGui texture ID.
    pub fn upload_texture(
        &mut self,
        width: u32,
        height: u32,
        pixels: &[u8],
    ) -> Result<u32, RenderError> {
        if self.display.is_null() {
            return Err(RenderError::NotInitialized);
        }
        if width == 0 || height == 0 {
            return Err(RenderError::InvalidTexture);
        }
        let gl_width = i32::try_from(width).map_err(|_| RenderError::InvalidTexture)?;
        let gl_height = i32::try_from(height).map_err(|_| RenderError::InvalidTexture)?;
        let expected = usize::try_from(width)
            .ok()
            .and_then(|w| usize::try_from(height).ok().and_then(|h| w.checked_mul(h)))
            .and_then(|count| count.checked_mul(4))
            .ok_or(RenderError::InvalidTexture)?;
        if pixels.len() != expected {
            return Err(RenderError::InvalidTexture);
        }
        let mut texture = 0u32;
        unsafe {
            glGenTextures(1, &mut texture);
            if texture == 0 {
                return Err(RenderError::Device("glGenTextures".to_owned()));
            }
            glBindTexture(GL_TEXTURE_2D, texture);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
            glTexImage2D(
                GL_TEXTURE_2D,
                0,
                GL_RGBA as i32,
                gl_width,
                gl_height,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                pixels.as_ptr().cast(),
            );
        }
        self.textures.insert(texture);
        Ok(texture)
    }

    /// Delete an application-owned texture. Unknown/zero names are a no-op.
    pub fn delete_texture(&mut self, texture: u32) -> Result<bool, RenderError> {
        if texture == 0 || !self.textures.remove(&texture) {
            return Ok(false);
        }
        if !self.display.is_null() {
            unsafe {
                glDeleteTextures(1, &texture);
            }
        }
        Ok(true)
    }

    pub fn present(&mut self) -> Result<(), RenderError> {
        if self.display.is_null() {
            return Err(RenderError::NotInitialized);
        }
        if unsafe { eglSwapBuffers(self.display, self.surface) } == 0 {
            return Err(Self::egl_error("eglSwapBuffers"));
        }
        Ok(())
    }

    pub fn shutdown(&mut self) {
        unsafe {
            if self.renderer_ready {
                // Font atlas textures are application-owned (the host uploads
                // them through `upload_texture`), so detach the atlas before
                // the official renderer tears down its resources.
                Self::detach_font_atlas_texture();
                dear_imgui_sys::backend_shim::opengl3::dear_imgui_backend_opengl3_shutdown();
            }
            if self.platform_ready {
                dear_imgui_sys::backend_shim::android::dear_imgui_backend_android_shutdown();
            }
            if !self.display.is_null() {
                let _ = eglMakeCurrent(
                    self.display,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if !self.surface.is_null() {
                    let _ = eglDestroySurface(self.display, self.surface);
                }
                if !self.context.is_null() {
                    let _ = eglDestroyContext(self.display, self.context);
                }
                let _ = eglTerminate(self.display);
            }
        }
        self.display = std::ptr::null_mut();
        self.surface = std::ptr::null_mut();
        self.context = std::ptr::null_mut();
        self.platform_ready = false;
        self.renderer_ready = false;
        // Retain names until callers retire their font/menu references. With
        // no EGL context, delete_texture only releases this ownership record.
    }

    unsafe fn detach_font_atlas_texture() {
        if dear_imgui_sys::igGetCurrentContext().is_null() {
            return;
        }
        let io = dear_imgui_sys::igGetIO_Nil();
        if io.is_null() || (*io).Fonts.is_null() {
            return;
        }
        let atlas = (*io).Fonts;
        if !(*atlas).TexData.is_null() {
            dear_imgui_sys::ImTextureData_SetTexID(
                (*atlas).TexData,
                0 as dear_imgui_sys::ImTextureID,
            );
        }
        (*atlas).TexRef = dear_imgui_sys::ImTextureRef_c::default();
    }
}

#[cfg(target_os = "android")]
impl Drop for AndroidBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(target_os = "android")]
impl Default for AndroidBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "android"))]
pub struct AndroidBackend;

#[cfg(not(target_os = "android"))]
impl AndroidBackend {
    pub const fn new() -> Self {
        Self
    }
    /// # Safety
    /// Matches the Android entry point; this target cannot create a backend.
    pub unsafe fn initialize(
        &mut self,
        _: crate::android::NativeWindowHandle,
        _: Size,
    ) -> Result<(), RenderError> {
        Err(RenderError::Device(
            "Android backend requires Android".to_owned(),
        ))
    }
    pub fn begin_frame(&mut self) -> Result<(), RenderError> {
        Err(RenderError::NotInitialized)
    }
    pub fn render(&mut self, _: &imgui::DrawData) -> Result<(), RenderError> {
        Err(RenderError::NotInitialized)
    }
    pub fn upload_texture(&mut self, _: u32, _: u32, _: &[u8]) -> Result<u32, RenderError> {
        Err(RenderError::NotInitialized)
    }
    pub fn delete_texture(&mut self, _: u32) -> Result<bool, RenderError> {
        Err(RenderError::NotInitialized)
    }
    pub fn present(&mut self) -> Result<(), RenderError> {
        Err(RenderError::NotInitialized)
    }
    pub fn shutdown(&mut self) {}
}

#[cfg(not(target_os = "android"))]
impl Default for AndroidBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "android")]
#[link(name = "EGL")]
unsafe extern "C" {
    fn eglGetDisplay(id: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn eglInitialize(display: *mut std::ffi::c_void, major: *mut i32, minor: *mut i32) -> i32;
    fn eglChooseConfig(
        display: *mut std::ffi::c_void,
        attrs: *const i32,
        configs: *mut *mut std::ffi::c_void,
        size: i32,
        count: *mut i32,
    ) -> i32;
    fn eglGetConfigAttrib(
        display: *mut std::ffi::c_void,
        config: *mut std::ffi::c_void,
        attribute: i32,
        value: *mut i32,
    ) -> i32;
    fn eglCreateContext(
        display: *mut std::ffi::c_void,
        config: *mut std::ffi::c_void,
        share: *mut std::ffi::c_void,
        attrs: *const i32,
    ) -> *mut std::ffi::c_void;
    fn eglCreateWindowSurface(
        display: *mut std::ffi::c_void,
        config: *mut std::ffi::c_void,
        window: *mut std::ffi::c_void,
        attrs: *const i32,
    ) -> *mut std::ffi::c_void;
    fn eglMakeCurrent(
        display: *mut std::ffi::c_void,
        draw: *mut std::ffi::c_void,
        read: *mut std::ffi::c_void,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn eglSwapBuffers(display: *mut std::ffi::c_void, surface: *mut std::ffi::c_void) -> i32;
    fn eglDestroySurface(display: *mut std::ffi::c_void, surface: *mut std::ffi::c_void) -> i32;
    fn eglDestroyContext(display: *mut std::ffi::c_void, context: *mut std::ffi::c_void) -> i32;
    fn eglTerminate(display: *mut std::ffi::c_void) -> i32;
    fn eglGetError() -> i32;
}

#[cfg(target_os = "android")]
#[link(name = "android")]
unsafe extern "C" {
    fn ANativeWindow_setBuffersGeometry(
        window: *mut std::ffi::c_void,
        width: i32,
        height: i32,
        format: i32,
    ) -> i32;
}

#[cfg(target_os = "android")]
#[link(name = "GLESv3")]
unsafe extern "C" {
    fn glViewport(x: i32, y: i32, width: i32, height: i32);
    fn glClearColor(r: f32, g: f32, b: f32, a: f32);
    fn glClear(mask: u32);
    fn glGenTextures(count: i32, textures: *mut u32);
    fn glBindTexture(target: u32, texture: u32);
    fn glTexParameteri(target: u32, pname: u32, value: i32);
    fn glPixelStorei(pname: u32, value: i32);
    fn glTexImage2D(
        target: u32,
        level: i32,
        internal_format: i32,
        width: i32,
        height: i32,
        border: i32,
        format: u32,
        kind: u32,
        pixels: *const std::ffi::c_void,
    );
    fn glDeleteTextures(count: i32, textures: *const u32);
}

#[cfg(target_os = "android")]
const GL_TEXTURE_2D: u32 = 0x0DE1;
#[cfg(target_os = "android")]
const GL_COLOR_BUFFER_BIT: u32 = 0x0000_4000;
#[cfg(target_os = "android")]
const GL_DEPTH_BUFFER_BIT: u32 = 0x0000_0100;
#[cfg(target_os = "android")]
const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
#[cfg(target_os = "android")]
const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
#[cfg(target_os = "android")]
const GL_TEXTURE_WRAP_S: u32 = 0x2802;
#[cfg(target_os = "android")]
const GL_TEXTURE_WRAP_T: u32 = 0x2803;
#[cfg(target_os = "android")]
const GL_LINEAR: i32 = 0x2601;
#[cfg(target_os = "android")]
const GL_CLAMP_TO_EDGE: i32 = 0x812F;
#[cfg(target_os = "android")]
const GL_RGBA: u32 = 0x1908;
#[cfg(target_os = "android")]
const GL_UNSIGNED_BYTE: u32 = 0x1401;
#[cfg(target_os = "android")]
const GL_UNPACK_ROW_LENGTH: u32 = 0x0CF2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderMode {
    Active,
    Idle,
}

#[derive(Clone, Copy, Debug)]
pub struct FrameInfo {
    pub now: Instant,
    pub delta: Duration,
    pub window_size: Option<Size>,
    pub mode: RenderMode,
}

/// Thread-safe control plane for a render manager owned by another thread.
/// The control plane only changes scheduling state; ImGui and window objects
/// remain thread-affine to the manager's render thread.
#[derive(Clone)]
pub struct EspFrameControl {
    shared: Arc<(Mutex<ControlState>, Condvar)>,
}

#[derive(Clone, Copy)]
struct ControlState {
    idle: bool,
    idle_fps: u32,
    stopped: bool,
}

impl EspFrameControl {
    pub fn set_idle(&self, idle: bool) {
        let mut state = self
            .shared
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.idle != idle {
            state.idle = idle;
            self.shared.1.notify_all();
        }
    }

    pub fn is_idle(&self) -> bool {
        self.snapshot().idle
    }

    pub fn set_idle_fps(&self, fps: u32) {
        let mut state = self
            .shared
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.idle_fps = fps.max(1);
        self.shared.1.notify_all();
    }

    pub fn idle_fps(&self) -> u32 {
        self.snapshot().idle_fps
    }

    pub fn stop(&self) {
        let mut state = self
            .shared
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.stopped = true;
        self.shared.1.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        self.snapshot().stopped
    }

    fn snapshot(&self) -> ControlState {
        *self
            .shared
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

type DrawCallback = Box<dyn FnMut(&FrameInfo, &imgui::Ui) -> Result<(), RenderError>>;

/// Owns one NativeWindow, ImGui context and GLES3 backend on the render thread.
/// Only the control handle may cross threads; callbacks build UI/draw lists.
pub struct EspFrameManager<B: SurfaceComposerBackend> {
    backend: AndroidBackend,
    backend_ready: bool,
    font_texture: Option<u32>,
    context: imgui::Context,
    service: NativeWindowService<B>,
    window: Option<NativeWindow<B>>,
    control: EspFrameControl,
    last_frame: Option<Instant>,
    last_idle_frame: Option<Instant>,
    on_draw: Option<DrawCallback>,
    on_idle_draw: Option<DrawCallback>,
}

impl<B: SurfaceComposerBackend> EspFrameManager<B> {
    pub fn new(service: NativeWindowService<B>) -> Self {
        Self::with_context(service, imgui::Context::create())
    }

    pub fn with_context(service: NativeWindowService<B>, context: imgui::Context) -> Self {
        Self {
            backend: AndroidBackend::new(),
            backend_ready: false,
            font_texture: None,
            service,
            window: None,
            context,
            control: EspFrameControl {
                shared: Arc::new((
                    Mutex::new(ControlState {
                        idle: false,
                        idle_fps: DEFAULT_IDLE_FPS,
                        stopped: false,
                    }),
                    Condvar::new(),
                )),
            },
            last_frame: None,
            last_idle_frame: None,
            on_draw: None,
            on_idle_draw: None,
        }
    }

    pub fn service(&self) -> &NativeWindowService<B> {
        &self.service
    }
    pub fn service_mut(&mut self) -> &mut NativeWindowService<B> {
        &mut self.service
    }
    pub fn window(&self) -> Option<&NativeWindow<B>> {
        self.window.as_ref()
    }
    pub fn context(&self) -> &imgui::Context {
        &self.context
    }
    pub fn context_mut(&mut self) -> &mut imgui::Context {
        &mut self.context
    }
    pub fn control(&self) -> EspFrameControl {
        self.control.clone()
    }
    pub fn is_idle(&self) -> bool {
        self.control.is_idle()
    }
    pub fn idle_fps(&self) -> u32 {
        self.control.idle_fps()
    }

    /// Set the active/idle mode.  The next [`draw`](Self::draw) dispatches to
    /// the corresponding callback.
    pub fn set_idle(&self, idle: bool) {
        self.control.set_idle(idle);
    }

    /// Configure idle cadence.  Zero is clamped to one FPS so callers cannot
    /// accidentally create a divide-by-zero interval.
    pub fn set_idle_fps(&self, fps: u32) {
        self.control.set_idle_fps(fps);
    }

    pub fn on_draw<F>(&mut self, callback: F)
    where
        F: FnMut(&FrameInfo, &imgui::Ui) -> Result<(), RenderError> + 'static,
    {
        self.on_draw = Some(Box::new(callback));
    }

    pub fn on_idle_draw<F>(&mut self, callback: F)
    where
        F: FnMut(&FrameInfo, &imgui::Ui) -> Result<(), RenderError> + 'static,
    {
        self.on_idle_draw = Some(Box::new(callback));
    }

    /// Dispatch one UI frame to the callback for the current mode.
    /// Returns `true` when a callback was installed and invoked.
    pub fn draw(&mut self, ui: &imgui::Ui, info: FrameInfo) -> Result<bool, RenderError> {
        let idle = self.is_idle();
        let info = FrameInfo {
            mode: if idle {
                RenderMode::Idle
            } else {
                RenderMode::Active
            },
            window_size: self.window.as_ref().map(|window| window.Size()),
            ..info
        };
        let callback = if idle {
            self.on_idle_draw.as_mut()
        } else {
            self.on_draw.as_mut()
        };
        let result = match callback {
            Some(callback) => callback(&info, ui).map(|_| true),
            None => Ok(false),
        };
        self.last_frame = Some(info.now);
        if idle {
            self.last_idle_frame = Some(info.now);
        }
        result
    }

    /// Initialize graphics and the context's configured font atlas. Hosts can
    /// install their fonts and style through context_mut before this call.
    pub fn initialize(&mut self) -> Result<(), RenderError> {
        let binding = self.context.binding();
        binding
            .try_with_bound_context(|| self.initialize_bound())
            .map_err(|error| RenderError::Ui(error.to_string()))?
    }

    fn initialize_bound(&mut self) -> Result<(), RenderError> {
        if self.backend_ready {
            return Ok(());
        }
        let window = self.window.as_ref().ok_or(RenderError::InvalidSurface)?;
        // Both the window and ImGui context are owned by this manager and
        // released only after backend shutdown.
        unsafe {
            self.backend.initialize(window.AsRaw(), window.Size())?;
        }
        let result = (|| {
            let atlas = self
                .context
                .font_atlas()
                .try_claim_legacy_renderer()
                .map_err(|error| RenderError::Ui(error.to_string()))?;
            atlas.build();
            let data = atlas.tex_data().ok_or(RenderError::InvalidTexture)?;
            let pixels = data.pixels().ok_or(RenderError::InvalidTexture)?;
            let rgba;
            let pixels = match data.format() {
                imgui::TextureFormat::RGBA32 => pixels,
                imgui::TextureFormat::Alpha8 => {
                    rgba = pixels
                        .iter()
                        .flat_map(|alpha| [255, 255, 255, *alpha])
                        .collect::<Vec<_>>();
                    &rgba
                }
            };
            let texture = self
                .backend
                .upload_texture(data.width(), data.height(), pixels)?;
            drop(data);
            unsafe { atlas.set_texture_id(imgui::TextureId::new(u64::from(texture))) };
            self.font_texture = Some(texture);
            Ok(())
        })();
        if result.is_err() {
            self.release_graphics();
        } else {
            self.backend_ready = true;
        }
        result
    }

    pub fn upload_texture(
        &mut self,
        width: u32,
        height: u32,
        pixels: &[u8],
    ) -> Result<u32, RenderError> {
        self.initialize()?;
        self.context
            .binding()
            .try_with_bound_context(|| self.backend.upload_texture(width, height, pixels))
            .map_err(|error| RenderError::Ui(error.to_string()))?
    }

    pub fn delete_texture(&mut self, texture: u32) -> Result<bool, RenderError> {
        self.context
            .binding()
            .try_with_bound_context(|| self.backend.delete_texture(texture))
            .map_err(|error| RenderError::Ui(error.to_string()))?
    }

    fn prepare_frame(&mut self, now: Instant) -> Result<FrameInfo, RenderError> {
        self.initialize()?;
        self.backend.begin_frame()?;
        let size = self
            .window
            .as_ref()
            .ok_or(RenderError::InvalidSurface)?
            .Size();
        let mode = if self.is_idle() {
            RenderMode::Idle
        } else {
            RenderMode::Active
        };
        let delta = self
            .last_frame
            .map(|last| now.saturating_duration_since(last))
            .filter(|delta| !delta.is_zero())
            .unwrap_or(Duration::from_micros(16_666));
        let io = self.context.io_mut();
        io.set_display_size([size.width as f32, size.height as f32]);
        io.set_display_framebuffer_scale([1.0, 1.0]);
        io.set_delta_time(delta.as_secs_f32());
        self.last_frame = Some(now);
        if mode == RenderMode::Idle {
            self.last_idle_frame = Some(now);
        }
        Ok(FrameInfo {
            now,
            delta,
            window_size: Some(size),
            mode,
        })
    }

    fn build_frame<'a>(
        context: &'a mut imgui::Context,
        on_draw: &mut Option<DrawCallback>,
        on_idle_draw: &mut Option<DrawCallback>,
        info: FrameInfo,
    ) -> Result<imgui::render::ReconciledFrame<'a>, RenderError> {
        let callback = if info.mode == RenderMode::Idle {
            on_idle_draw
        } else {
            on_draw
        };
        let frame = context
            .try_begin_frame()
            .map_err(|error| RenderError::Ui(error.to_string()))?;
        if let Some(callback) = callback.as_mut() {
            callback(&info, frame.ui())?;
        }
        Ok(frame.render_legacy())
    }

    /// Build and present a complete frame using the manager-owned backend.
    pub fn frame(&mut self, now: Instant) -> Result<(), RenderError> {
        self.draw_frame(now)
    }

    /// Begin, invoke exactly one host callback, submit and present one frame.
    pub fn draw_frame(&mut self, now: Instant) -> Result<(), RenderError> {
        let binding = self.context.binding();
        binding
            .try_with_bound_context(|| self.draw_frame_bound(now))
            .map_err(|error| RenderError::Ui(error.to_string()))?
    }

    fn draw_frame_bound(&mut self, now: Instant) -> Result<(), RenderError> {
        if self.mirror_enabled() {
            self.process_mirror_display()
                .map_err(|error| RenderError::Device(error.to_string()))?;
        }
        let info = self.prepare_frame(now)?;
        {
            let frame = Self::build_frame(
                &mut self.context,
                &mut self.on_draw,
                &mut self.on_idle_draw,
                info,
            )?;
            self.backend.render(frame.draw_data())?;
        }
        let result = self.backend.present();
        if matches!(
            result,
            Err(RenderError::ContextLost | RenderError::SurfaceLost)
        ) {
            self.release_graphics();
        }
        result
    }

    /// Run on the render thread until the host calls control.stop(). Active
    /// callback pacing is host-owned; callbacks must return to observe stop.
    pub fn run(&mut self) -> Result<(), RenderError> {
        let result = (|| {
            while self.wait_until_frame(None) {
                // Report resource loss so the host recreates all its texture
                // IDs before restarting; only the font atlas is manager-owned.
                self.draw_frame(Instant::now())?;
            }
            Ok(())
        })();
        self.shutdown();
        result
    }

    pub fn next_idle_deadline(&self, now: Instant) -> Instant {
        let interval = Duration::from_nanos((1_000_000_000 / self.idle_fps() as u64).max(1));
        self.last_idle_frame
            .map(|last| last + interval)
            .unwrap_or(now)
    }

    pub fn wait_for_idle_frame(&self, stop: &AtomicBool) -> bool {
        self.wait_until_frame(Some(stop))
    }

    fn wait_until_frame(&self, stop: Option<&AtomicBool>) -> bool {
        let mut state = self
            .control
            .shared
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            if state.stopped || stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
                return false;
            }
            if !state.idle {
                return true;
            }
            let period = Duration::from_nanos((1_000_000_000 / u64::from(state.idle_fps)).max(1));
            let deadline = self
                .last_idle_frame
                .map(|last| last + period)
                .unwrap_or_else(Instant::now);
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return true;
            }
            let wait = if stop.is_some() {
                remaining.min(Duration::from_millis(20))
            } else {
                remaining
            };
            state = self
                .control
                .shared
                .1
                .wait_timeout(state, wait)
                .unwrap_or_else(|error| error.into_inner())
                .0;
        }
    }

    /// Create and retain the manager's sole NativeWindow.
    pub fn create_window(
        &mut self,
        name: &CStr,
        size: Size,
        skip_screenshot: bool,
    ) -> Result<(), WindowError> {
        self.create_window_with_buffer_size(name, size, size, skip_screenshot)?;
        Ok(())
    }

    pub fn create_window_with_buffer_size(
        &mut self,
        name: &CStr,
        native_size: Size,
        buffer_size: Size,
        skip_screenshot: bool,
    ) -> Result<(), WindowError> {
        if !native_size.IsValid() || !buffer_size.IsValid() {
            return Err(WindowError::InvalidSize);
        }
        self.clear_window();
        self.window = Some(self.service.CreateWithBufferSize(
            name,
            native_size,
            buffer_size,
            skip_screenshot,
        )?);
        Ok(())
    }

    pub fn process_mirror_display(&mut self) -> Result<(), WindowError> {
        self.service.ProcessMirrorDisplay()
    }

    pub fn mirror_enabled(&self) -> bool {
        self.service.MirrorEnabled()
    }

    pub fn set_window(&mut self, window: NativeWindow<B>) {
        self.clear_window();
        self.window = Some(window);
    }
    pub fn clear_window(&mut self) {
        self.release_graphics();
        self.window = None;
    }

    fn release_graphics(&mut self) {
        self.context.binding().with_bound_context(|| {
            if let Some(texture) = self.font_texture.take() {
                if let Ok(atlas) = self.context.font_atlas().try_claim_legacy_renderer() {
                    unsafe { atlas.set_texture_id(imgui::TextureId::null()) };
                }
                let _ = self.backend.delete_texture(texture);
            }
            self.backend.shutdown();
        });
        self.backend_ready = false;
        self.last_frame = None;
        self.last_idle_frame = None;
    }

    pub fn shutdown(&mut self) {
        self.control.stop();
        self.clear_window();
    }

    // Compatibility spellings used by the existing Android-facing API.
    #[allow(non_snake_case)]
    pub fn SetIdle(&self, idle: bool) {
        self.set_idle(idle);
    }
    #[allow(non_snake_case)]
    pub fn IsIdle(&self) -> bool {
        self.is_idle()
    }
    #[allow(non_snake_case)]
    pub fn SetIdleFps(&self, fps: u32) {
        self.set_idle_fps(fps);
    }
    #[allow(non_snake_case)]
    pub fn IdleFps(&self) -> u32 {
        self.idle_fps()
    }
    #[allow(non_snake_case)]
    pub fn onDraw<F>(&mut self, callback: F)
    where
        F: FnMut(&FrameInfo, &imgui::Ui) -> Result<(), RenderError> + 'static,
    {
        self.on_draw(callback);
    }
    #[allow(non_snake_case)]
    pub fn onIdleDraw<F>(&mut self, callback: F)
    where
        F: FnMut(&FrameInfo, &imgui::Ui) -> Result<(), RenderError> + 'static,
    {
        self.on_idle_draw(callback);
    }
}

impl<B: SurfaceComposerBackend> Drop for EspFrameManager<B> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Official dear-imgui-sys Android/OpenGL3 shim entry points.
///
/// Keeping these as re-exports prevents EspFrame from growing a competing
/// backend while allowing a host to initialize the shims next to its EGL
/// lifecycle.
#[cfg(target_os = "android")]
pub mod backend_shim {
    pub use dear_imgui_sys::backend_shim::{android, opengl3};
}
