//! Shared ImGui rendering primitives with Android-version API adapters.
//! No second Skia library is linked. ROM factories are preferred, with checked
//! compact-layout adapters for functions eliminated by inlining.
use super::abi::{self as skia, Paint, Rect};
use super::frame::{Frame, Texture};
use super::profile::Rom;
use crate::xdl;
use core::ffi::c_void;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, OnceLock,
};

type Ptr = *mut c_void;
static API: OnceLock<Api> = OnceLock::new();
// ARM64 nontrivial return storage uses x8. Up to eight integer/pointer parameters.
core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".global espframe_skia_factory",
    ".hidden espframe_skia_factory",
    ".type espframe_skia_factory, %function",
    "espframe_skia_factory:",
    "bti c",
    "mov x16, x0",
    "mov x8, x1",
    "mov x17, x2",
    "ldp x0, x1, [x17]",
    "ldp x2, x3, [x17, #16]",
    "ldp x4, x5, [x17, #32]",
    "ldp x6, x7, [x17, #48]",
    "br x16",
    ".size espframe_skia_factory, .-espframe_skia_factory",
);
extern "C" {
    fn espframe_skia_factory(function: usize, out: *mut c_void, args: *const usize);
}
unsafe fn factory(function: usize, out: *mut c_void, args: &[usize]) {
    let mut regs = [0usize; 8];
    regs[..args.len()].copy_from_slice(args);
    espframe_skia_factory(function, out, regs.as_ptr());
}
#[repr(C, align(16))]
struct Info {
    bytes: [u8; 32],
    canary: [u8; 16],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Point {
    x: f32,
    y: f32,
}
#[repr(C)]
struct Sampling {
    max_aniso: i32,
    use_cubic: u32,
    b: f32,
    c: f32,
    filter: i32,
    mipmap: i32,
}

struct Api {
    info: usize,
    legacy_shader: bool,
    old_sampling: bool,
    colored_paint: Option<unsafe extern "C" fn(*mut Paint, *const [f32; 4], Ptr)>,
    vertices: usize,
    data: usize,
    image: usize,
    shader: usize,
    destroy_info: unsafe extern "C" fn(*mut Info),
    destroy_data: DataRelease,
    delete_vertices: unsafe extern "C" fn(Ptr),
    construct_paint: Option<unsafe extern "C" fn(*mut Paint)>,
    destroy_paint: unsafe extern "C" fn(*mut Paint),
    set_color: unsafe extern "C" fn(*mut Paint, *const [f32; 4], Ptr),
    set_shader: Option<unsafe extern "C" fn(*mut Paint, *mut Ptr)>,
    draw_vertices: unsafe extern "C" fn(Ptr, Ptr, i32, *const Paint),
    state: skia::CanvasState,
    clip: unsafe extern "C" fn(Ptr, *const Rect, i32, bool),
}
enum DataRelease {
    Slot(unsafe extern "C" fn(*mut Ptr)),
    Unref(unsafe extern "C" fn(Ptr)),
}
impl DataRelease {
    unsafe fn release(&self, slot: &mut Ptr) {
        match self {
            Self::Slot(f) => f(slot),
            Self::Unref(f) => {
                if !slot.is_null() {
                    f(*slot);
                    *slot = core::ptr::null_mut();
                }
            }
        }
    }
}

pub unsafe fn prepare() -> Result<(), String> {
    if API.get().is_some() {
        return Ok(());
    }
    let (module, rom) = skia::open_module()?;
    let result = (|| {
        macro_rules! addr {
            ($s:expr) => {
                skia::symbol(&module, $s)?
            };
        }
        macro_rules! sym {
            ($s:expr) => {
                core::mem::transmute(addr!($s))
            };
        }
        let (info, compact_info) = if rom.legacy() {
            super::legacy::check_info(&module)?;
            (0, true)
        } else {
            let (info, info_code) =
                skia::function_words(&module, c"_ZN11SkImageInfo13MakeN32PremulEii", 512)?;
            let compact_info = super::layout::n32_layout(&info_code).map_err(str::to_owned)?;
            (info, compact_info)
        };
        let construct_paint = skia::optional_symbol(&module, c"_ZN7SkPaintC1Ev")?;
        let set_shader =
            skia::optional_symbol(&module, c"_ZN7SkPaint9setShaderE5sk_spI8SkShaderE")?;
        if rom.android12() {
            super::legacy::check_paint12(&module)?;
        } else if rom == Rom::Android14 {
            super::legacy::check_paint14(&module)?;
        } else if construct_paint.is_none() || set_shader.is_none() {
            // Compact AOSP paint: six owned pointers, RGBA at 48, width at 64,
            // miter at 68 and flags at 72. Check the complete move constructor
            // before using this layout; vendor 16/17 layouts are different.
            skia::checked_words(
                &module,
                c"_ZN7SkPaintC1EOS_",
                &[
                    0xf9400028, 0xf900003f, 0xf9000008, 0xf9400428, 0xf900043f, 0xf9000408,
                    0xf9400828, 0xf900083f, 0xf9000808, 0xf9400c28, 0xf9000c3f, 0xf9000c08,
                    0xf9401028, 0xf900103f, 0xf9001008, 0xf9401428, 0xf900143f, 0xf9001408,
                    0x3cc3c020, 0x3dc00c21, 0x3c83c000, 0x3d800c01, 0xd65f03c0,
                ],
            )?;
        }
        let destroy_info = match skia::optional_symbol(&module, c"_ZN11SkImageInfoD2Ev")? {
            Some(p) => core::mem::transmute(p),
            None if compact_info => destroy_unmanaged_info as unsafe extern "C" fn(*mut Info),
            None => return Err("extended ImageInfo requires ROM destructor".into()),
        };
        let api = Api {
            info,
            legacy_shader: rom.legacy(),
            old_sampling: rom.android12() || rom == Rom::Android13,
            colored_paint: if rom.android12() {
                Some(sym!(
                    c"_ZN7SkPaintC1ERK8SkRGBA4fIL11SkAlphaType3EEP12SkColorSpace"
                ))
            } else {
                None
            },
            vertices: addr!(c"_ZN10SkVertices8MakeCopyENS_10VertexModeEiPK7SkPointS3_PKjiPKt"),
            data: match skia::optional_symbol(&module, c"_ZN6SkData18PrivateNewWithCopyEPKvm")? {
                Some(p) => p,
                None if rom.legacy() => addr!(c"_ZN6SkData12MakeWithCopyEPKvm"),
                None => return Err("missing SkData factory".into()),
            },
            image: if rom.legacy() {
                addr!(c"_ZN7SkImage14MakeRasterDataERK11SkImageInfo5sk_spI6SkDataEm")
            } else {
                addr!(c"_ZN8SkImages14RasterFromDataERK11SkImageInfo5sk_spI6SkDataEm")
            },
            shader: if rom.legacy() {
                addr!(c"_ZN13SkImageShader4MakeE5sk_spI7SkImageE10SkTileModeS3_RK17SkSamplingOptionsPK8SkMatrixb")
            } else {
                addr!(c"_ZNK7SkImage10makeShaderE10SkTileModeS0_RK17SkSamplingOptionsPK8SkMatrix")
            },
            destroy_info,
            destroy_data: match skia::optional_symbol(&module, c"_ZN5sk_spI6SkDataED2Ev")? {
                Some(p) => DataRelease::Slot(core::mem::transmute(p)),
                None if rom.android12() => {
                    DataRelease::Unref(super::legacy::data_release(&module)?)
                }
                None => DataRelease::Unref(sym!(c"_ZNK10SkNVRefCntI6SkDataE5unrefEv")),
            },
            delete_vertices: if rom.legacy() || rom == Rom::Android15 {
                core::mem::transmute(skia::library_symbol(c"libc++.so", c"_ZdlPv")?)
            } else {
                core::mem::transmute(
                    match skia::optional_symbol(&module, c"_ZN10SkVerticesdlEPv")? {
                        Some(address) => address,
                        None => skia::checked_vertices_delete(&module)?,
                    },
                )
            },
            construct_paint: construct_paint.map(|p| core::mem::transmute(p)),
            destroy_paint: sym!(c"_ZN7SkPaintD1Ev"),
            set_color: sym!(c"_ZN7SkPaint8setColorERK8SkRGBA4fIL11SkAlphaType3EEP12SkColorSpace"),
            set_shader: set_shader.map(|p| core::mem::transmute(p)),
            draw_vertices: sym!(
                c"_ZN8SkCanvas12drawVerticesEPK10SkVertices11SkBlendModeRK7SkPaint"
            ),
            state: skia::CanvasState::resolve(&module)?,
            clip: sym!(c"_ZN8SkCanvas8clipRectERK6SkRect8SkClipOpb"),
        };
        let _ = API.set(api);
        Ok(())
    })();
    drop(xdl::xdl_close(module));
    result
}

// The complete compact N32 factory is checked to initialize null colorspace.
// Extended factories always retain the ROM destructor.
unsafe extern "C" fn destroy_unmanaged_info(info: *mut Info) {
    debug_assert!((&(*info).bytes)[..8].iter().all(|&b| b == 0));
}
fn api() -> &'static Api {
    API.get().expect("prepare before drawing")
}

// Verified in this ROM's MakeCopy / setShader / makeShader disassembly:
// SkVertices has a nonvirtual refcount at +0; image/shader have a vptr and refcount at +8.
// Vtable slot +16 is internal_dispose. Never call a deleting destructor on a shared image.
struct Owned {
    ptr: Ptr,
    vertices: bool,
}
impl Owned {
    fn new(ptr: Ptr, vertices: bool) -> Result<Self, String> {
        if ptr.is_null() {
            return Err("Skia factory returned null".into());
        }
        Ok(Self { ptr, vertices })
    }
    unsafe fn ref_clone(&self) -> Ptr {
        let offset = if self.vertices { 0 } else { 8 };
        (*(self.ptr.cast::<u8>().add(offset).cast::<AtomicU32>())).fetch_add(1, Ordering::Relaxed);
        self.ptr
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            let offset = if self.vertices { 0 } else { 8 };
            if (*(self.ptr.cast::<u8>().add(offset).cast::<AtomicU32>()))
                .fetch_sub(1, Ordering::AcqRel)
                == 1
            {
                if self.vertices {
                    (api().delete_vertices)(self.ptr);
                } else {
                    let vtable = *self.ptr.cast::<*const usize>();
                    let dispose: unsafe extern "C" fn(Ptr) = core::mem::transmute(*vtable.add(2));
                    dispose(self.ptr);
                }
            }
        }
    }
}
struct ScopedPaint(Paint);
impl ScopedPaint {
    unsafe fn new(color: u32, shader: Option<&Owned>) -> Self {
        let mut p = Self(Paint::storage());
        if let Some(f) = api().colored_paint {
            f(&mut p.0, &[0., 0., 0., 1.], core::ptr::null_mut());
        } else {
            match api().construct_paint {
                Some(f) => f(&mut p.0),
                None => p.0.construct_compact(),
            }
        }
        let rgba = [
            ((color >> 16) & 255) as f32 / 255.,
            ((color >> 8) & 255) as f32 / 255.,
            (color & 255) as f32 / 255.,
            (color >> 24) as f32 / 255.,
        ];
        (api().set_color)(&mut p.0, &rgba, core::ptr::null_mut());
        if let Some(shader) = shader {
            let mut slot = shader.ref_clone();
            match api().set_shader {
                Some(f) => f(&mut p.0, &mut slot),
                None => {
                    p.0.attach_compact_shader(slot);
                    slot = core::ptr::null_mut();
                }
            }
            assert!(
                slot.is_null(),
                "ROM setShader must consume its sk_sp argument"
            );
        }
        p
    }
}
impl Drop for ScopedPaint {
    fn drop(&mut self) {
        unsafe {
            (api().destroy_paint)(&mut self.0);
        }
        assert!(self.0.canary_ok());
    }
}
struct Saved {
    canvas: Ptr,
}
impl Saved {
    unsafe fn new(canvas: Ptr) -> Self {
        api().state.save(canvas);
        Self { canvas }
    }
}
impl Drop for Saved {
    fn drop(&mut self) {
        unsafe {
            api().state.restore(self.canvas);
        }
    }
}

unsafe fn info(w: usize, h: usize) -> Info {
    let mut value = Info {
        bytes: [0; 32],
        canary: [0xa5; 16],
    };
    // The selected factory is checked for RGBA_8888=4 and premul=2.
    if api().info == 0 {
        value.bytes[8..12].copy_from_slice(&4i32.to_ne_bytes());
        value.bytes[12..16].copy_from_slice(&2i32.to_ne_bytes());
        value.bytes[16..20].copy_from_slice(&(w as i32).to_ne_bytes());
        value.bytes[20..24].copy_from_slice(&(h as i32).to_ne_bytes());
    } else {
        factory(api().info, (&mut value as *mut Info).cast(), &[w, h]);
    }
    value
}
unsafe fn free_info(value: &mut Info) {
    (api().destroy_info)(value);
    assert_eq!(value.canary, [0xa5; 16]);
}
unsafe fn texture(w: usize, h: usize, pixels: &[u8], linear: bool) -> Result<Owned, String> {
    if pixels.len() != w * h * 4 {
        return Err("texture length".into());
    }
    let mut data: Ptr = core::ptr::null_mut();
    let mut image: Ptr = core::ptr::null_mut();
    let mut shader: Ptr = core::ptr::null_mut();
    // All texture sources are straight RGBA. Convert once when creating the
    // cached Skia texture; never premultiply again on each draw submission.
    let premultiplied = pixels
        .chunks_exact(4)
        .flat_map(|p| {
            let a = p[3] as u16;
            [
                ((p[0] as u16 * a + 127) / 255) as u8,
                ((p[1] as u16 * a + 127) / 255) as u8,
                ((p[2] as u16 * a + 127) / 255) as u8,
                p[3],
            ]
        })
        .collect::<Vec<_>>();
    let pixels = premultiplied.as_slice();
    factory(
        api().data,
        (&mut data as *mut Ptr).cast(),
        &[pixels.as_ptr() as usize, pixels.len()],
    );
    if data.is_null() {
        return Err("data null".into());
    }
    let mut meta = info(w, h);
    factory(
        api().image,
        (&mut image as *mut Ptr).cast(),
        &[
            (&meta as *const Info) as usize,
            (&mut data as *mut Ptr) as usize,
            w * 4,
        ],
    );
    api().destroy_data.release(&mut data);
    free_info(&mut meta);
    let image = Owned::new(image, false)?;
    let sampling = Sampling {
        max_aniso: 0,
        use_cubic: 0,
        b: 0.,
        c: 0.,
        filter: if linear { 1 } else { 0 },
        mipmap: 0,
    };
    // API 31?33 have no maxAniso member; their struct starts at useCubic.
    let sampling_ptr = (&sampling as *const Sampling)
        .cast::<u8>()
        .add(if api().old_sampling { 4 } else { 0 });
    let mut image_slot = if api().legacy_shader {
        image.ref_clone()
    } else {
        core::ptr::null_mut()
    };
    factory(
        api().shader,
        (&mut shader as *mut Ptr).cast(),
        &[
            if api().legacy_shader {
                (&mut image_slot as *mut Ptr) as usize
            } else {
                image.ptr as usize
            },
            0,
            0,
            sampling_ptr as usize,
            0,
            0,
        ],
    );
    // Skia 12 borrows the by-value argument until its caller destructs it;
    // later factories move it out. Release only a remaining owned slot.
    if !image_slot.is_null() {
        drop(Owned::new(image_slot, false)?);
    }
    // Image owner is released here; shader must retain its own reference.
    Owned::new(shader, false)
}
unsafe fn mesh(
    positions: &[Point],
    uv: &[Point],
    colors: &[u32],
    indices: &[u16],
) -> Result<Owned, String> {
    if positions.is_empty()
        || positions.len() != colors.len()
        || (!uv.is_empty() && uv.len() != positions.len())
        || indices.len() % 3 != 0
        || indices.iter().any(|&i| i as usize >= positions.len())
    {
        return Err("invalid mesh".into());
    }
    let mut ptr: Ptr = core::ptr::null_mut();
    factory(
        api().vertices,
        (&mut ptr as *mut Ptr).cast(),
        &[
            0,
            positions.len(),
            positions.as_ptr() as usize,
            if uv.is_empty() {
                0
            } else {
                uv.as_ptr() as usize
            },
            colors.as_ptr() as usize,
            indices.len(),
            indices.as_ptr() as usize,
        ],
    );
    Owned::new(ptr, true)
}
unsafe fn draw(canvas: Ptr, vertices: &Owned, shader: Option<&Owned>) {
    let paint = ScopedPaint::new(0xffffffff, shader);
    (api().draw_vertices)(canvas, vertices.ptr, 13, &paint.0); // kModulate: texture * vertex color.
}

struct Command {
    vertices: Owned,
    shader: usize,
    clip: Rect,
}
struct Shader {
    source: Arc<Texture>,
    linear: bool,
    object: Owned,
}
pub(super) struct Scene {
    commands: Vec<Command>,
    shaders: Vec<Shader>,
}
impl Scene {
    pub(super) unsafe fn new(frame: &Frame, previous: Option<&Self>) -> Result<Self, String> {
        let mut result = Self {
            commands: Vec::new(),
            shaders: Vec::new(),
        };
        for c in &frame.commands {
            let shader = if let Some(i) = result
                .shaders
                .iter()
                .position(|s| Arc::ptr_eq(&s.source, &c.texture) && s.linear == c.linear)
            {
                i
            } else {
                let old = previous.and_then(|p| {
                    p.shaders
                        .iter()
                        .find(|s| Arc::ptr_eq(&s.source, &c.texture) && s.linear == c.linear)
                });
                let object = if let Some(old) = old {
                    Owned::new(old.object.ref_clone(), false)?
                } else {
                    texture(
                        c.texture.width as usize,
                        c.texture.height as usize,
                        &c.texture.pixels,
                        c.linear,
                    )?
                };
                result.shaders.push(Shader {
                    source: c.texture.clone(),
                    linear: c.linear,
                    object,
                });
                result.shaders.len() - 1
            };
            let positions = c
                .vertices
                .iter()
                .map(|v| Point {
                    x: v.pos[0],
                    y: v.pos[1],
                })
                .collect::<Vec<_>>();
            let uv = c
                .vertices
                .iter()
                .map(|v| Point {
                    x: v.uv[0] * c.texture.width as f32,
                    y: v.uv[1] * c.texture.height as f32,
                })
                .collect::<Vec<_>>();
            let colors = c
                .vertices
                .iter()
                .map(|v| {
                    (v.color & 0xff00ff00) | ((v.color & 0xff) << 16) | ((v.color >> 16) & 0xff)
                })
                .collect::<Vec<_>>();
            let vertices = mesh(&positions, &uv, &colors, &c.indices)?;
            result.commands.push(Command {
                vertices,
                shader,
                clip: Rect {
                    left: c.clip[0],
                    top: c.clip[1],
                    right: c.clip[2],
                    bottom: c.clip[3],
                },
            });
        }
        Ok(result)
    }
    pub(super) unsafe fn draw(&self, canvas: Ptr) {
        for c in &self.commands {
            let _clip = Saved::new(canvas);
            (api().clip)(canvas, &c.clip, 1, false);
            draw(canvas, &c.vertices, Some(&self.shaders[c.shader].object));
        }
    }
}
