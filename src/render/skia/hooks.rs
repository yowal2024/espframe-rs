//! Payload-owned setup. Executable patches are installed by a payload worker
//! while SF/main and RenderEngine are parked at their idle syscall boundaries.
use super::{
    abi,
    frame::Frame,
    frame_scope::FrameScope,
    geometry::Geometry,
    profile::Rom,
    scene::{self, Scene},
};
use crate::xdl;
use core::{cell::RefCell, ffi::c_void};
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, Ordering},
    Arc, OnceLock,
};

type Ptr = *mut c_void;
static READY: AtomicBool = AtomicBool::new(false);
static ORIGINALS: [AtomicPtr<c_void>; 9] = [const { AtomicPtr::new(core::ptr::null_mut()) }; 9];
static API: OnceLock<Api> = OnceLock::new();
thread_local! {
    static SCOPE: RefCell<FrameScope> = const { RefCell::new(FrameScope::new()) };
    static DRAW: RefCell<Option<(Arc<Frame>, Scene)>> = const { RefCell::new(None) };
    static LATENCY: RefCell<ComposeLatency> = RefCell::new(ComposeLatency::default());
}

struct ComposeLatency {
    since: std::time::Instant,
    count: u64,
    sum: [f64; 4],
    max: [f64; 4],
}
impl Default for ComposeLatency {
    fn default() -> Self {
        Self {
            since: std::time::Instant::now(),
            count: 0,
            sum: [0.0; 4],
            max: [0.0; 4],
        }
    }
}
impl ComposeLatency {
    fn record(&mut self, values: [f64; 4]) {
        self.count += 1;
        for (i, value) in values.into_iter().enumerate() {
            self.sum[i] += value;
            self.max[i] = self.max[i].max(value);
        }
        let elapsed = self.since.elapsed();
        if elapsed < std::time::Duration::from_secs(2) {
            return;
        }
        crate::espframe_log!("skia.latency.compose",
            "samples={} hz={:.1} fields=frame_age_ms,scene_draw_ms,reused,lock_miss avg={:.2?} max={:.2?}",
            self.count, self.count as f64 / elapsed.as_secs_f64(),
            self.sum.map(|sum| sum / self.count as f64), self.max);
        *self = Self::default();
    }
}
struct Api {
    rom: Rom,
    legacy_flush_site: usize,
    region_set: Option<unsafe extern "C" fn(Ptr, Ptr)>,
    dirty_layout: Option<super::layout::DirtyLayout>,
    orientation_offset: usize,
    set_matrix: unsafe extern "C" fn(Ptr, *const f32),
    targets: [usize; 9],
    dirty: unsafe extern "C" fn(Ptr),
    canvas: unsafe extern "C" fn(Ptr) -> Ptr,
    size: unsafe extern "C" fn(Ptr) -> u64,
    state: abi::CanvasState,
    reset_cache: unsafe extern "C" fn(Ptr, u32),
    cache_offset: usize,
}
pub(super) fn installed() -> bool {
    READY.load(Ordering::Acquire)
}
pub(super) unsafe fn prepare() -> Result<(), String> {
    if API.get().is_some() {
        return Ok(());
    }
    let (module, rom) = abi::open_module()?;
    let result = (|| {
        macro_rules! addr {
            ($s:expr) => {
                abi::symbol(&module, $s)?
            };
        }
        macro_rules! sym {
            ($s:expr) => {
                core::mem::transmute(addr!($s))
            };
        }
        let dirty = abi::optional_symbol(
            &module,
            c"_ZN7android17compositionengine4impl6Output17dirtyEntireOutputEv",
        )?;
        // Some ROMs compute a second, buffer-age-based damage region that does
        // not include Output::dirtyRegion or our non-Layer overlay. Resolve by
        // capability, without a device name, Build ID or private field offset.
        let buffer_damage = abi::optional_symbol(
            &module,
            c"_ZN7android12BufferDamage17computeDispDamageEiiRNS_6RegionE",
        )?;
        let dirty_layout = if dirty.is_none() && !rom.android12() {
            let (_, filter) = abi::function_words(
                &module,
                c"_ZN7android17compositionengine4impl6Output14setLayerFilterENS_2ui11LayerFilterE",
                1024,
            )?;
            let (_, size) = abi::function_words(
                &module,
                c"_ZN7android17compositionengine4impl6Output14setDisplaySizeERKNS_2ui4SizeE",
                1024,
            )?;
            let (_, begin) = abi::function_words(
                &module,
                c"_ZN7android17compositionengine4impl6Output10beginFrameEv",
                1024,
            )?;
            let (_, region) = abi::function_words(
                &module,
                c"_ZNK7android17compositionengine4impl6Output14getDirtyRegionEv",
                256,
            )?;
            Some(
                super::layout::dirty_layout(&filter, &size, &begin, &region)
                    .map_err(str::to_owned)?,
            )
        } else {
            None
        };
        let (reset, config) = abi::function_words(
            &module,
            c"_ZN7android17compositionengine4impl6Output30cacheClientCompositionRequestsEj",
            512,
        )?;
        let (compose_target, compose) =
            abi::function_words(&module, super::legacy::compose_symbol(rom), 65536)?;
        let cache_offset = super::layout::cache_offset(&config, &compose).map_err(str::to_owned)?;
        let orientation_offset = if rom.android12() {
            208
        } else if rom == Rom::Android13 {
            112
        } else if rom == Rom::Android14 {
            136
        } else {
            let (_, canvas) = abi::function_words(
                &module,
                c"_ZN7android12renderengine4skia16SkiaRenderEngine10initCanvasEP8SkCanvasRKNS0_15DisplaySettingsE",
                16384,
            )?;
            super::layout::display_orientation_offset(&canvas).map_err(str::to_owned)?
        };
        let legacy_draw = if rom.legacy() {
            let (address, code) =
                abi::function_words(&module, super::legacy::draw_symbol(rom), 131072)?;
            let site = super::layout::legacy_flush_site(&code).map_err(str::to_owned)?;
            Some((address, address + site))
        } else {
            None
        };
        let api = Api {
            rom,
            legacy_flush_site: legacy_draw.map_or(0, |(_, site)| site),
            dirty_layout,
            orientation_offset,
            region_set: if dirty_layout.is_some() || buffer_damage.is_some() {
                Some(core::mem::transmute(abi::library_symbol(
                    c"libui.so",
                    c"_ZN7android6Region3setERKNS_4RectE",
                )?))
            } else {
                None
            },
            set_matrix: sym!(c"_ZN8SkCanvas9setMatrixERK8SkMatrix"),
            targets: [
                if let Some((address, _)) = legacy_draw {
                    address
                } else {
                    addr!(c"_ZN7android12renderengine4skia16SkiaRenderEngine18drawLayersInternalEOKNSt3__110shared_ptrINS3_7promiseINS_4base8expectedINS_2spINS_5FenceEEEiEEEEEERKNS0_15DisplaySettingsERKNS3_6vectorINS0_13LayerSettingsENS3_9allocatorISK_EEEERKNS4_INS0_15ExternalTextureEEEONS6_14unique_fd_implINS6_13DefaultCloserEEE")
                },
                if rom.legacy() {
                    0
                } else {
                    abi::optional_symbol(&module, c"_ZN7android12renderengine4skia16SkiaRenderEngine22drawLayersFadeInternalEOKNSt3__110shared_ptrINS3_7promiseINS_4base8expectedINS_2spINS_5FenceEEEiEEEEEERKNS0_15DisplaySettingsERKNS3_6vectorINS0_13LayerSettingsENS3_9allocatorISK_EEEE")?.unwrap_or(0)
                },
                if rom.android12() {
                    0
                } else {
                    addr!(c"_ZN7android17compositionengine4impl6Output10beginFrameEv")
                },
                compose_target,
                if rom.legacy() {
                    addr!(super::legacy::flush_symbol(rom))
                } else {
                    addr!(c"_ZN7android12renderengine4skia18SkiaGLRenderEngine14flushAndSubmitEPNS1_14SkiaGpuContextE5sk_spI9SkSurfaceE")
                },
                if rom.android12() {
                    addr!(c"_ZNK7android17compositionengine4impl6Output14getDirtyRegionEb")
                } else if rom.legacy() {
                    0
                } else {
                    addr!(c"_ZN7android12renderengine4skia20GaneshVkRenderEngine14flushAndSubmitEPNS1_14SkiaGpuContextE5sk_spI9SkSurfaceE")
                },
                if rom == Rom::Android17 {
                    addr!(c"_ZN7android12renderengine4skia22GraphiteVkRenderEngine14flushAndSubmitEPNS1_14SkiaGpuContextE5sk_spI9SkSurfaceE")
                } else {
                    0
                },
                if rom.legacy() {
                    0
                } else {
                    abi::optional_symbol(
                        &module,
                        c"_ZN7android12renderengine4skia11SkiaCapture10tryCaptureEP9SkSurface",
                    )?
                    .unwrap_or(0)
                },
                buffer_damage.unwrap_or(0),
            ],
            dirty: dirty
                .map(|address| core::mem::transmute(address))
                .unwrap_or(dirty_inline),
            canvas: core::mem::transmute(
                match abi::optional_symbol(&module, c"_ZN9SkSurface9getCanvasEv")? {
                    Some(p) => p,
                    None => match abi::optional_symbol(
                        &module,
                        c"_ZN14SkSurface_Base15getCachedCanvasEv",
                    )? {
                        Some(p) => p,
                        None if rom.android12() => super::legacy::canvas(&module)? as usize,
                        None => return Err("missing surface canvas accessor".into()),
                    },
                },
            ),
            size: sym!(c"_ZNK8SkCanvas16getBaseLayerSizeEv"),
            state: abi::CanvasState::resolve(&module)?,
            reset_cache: core::mem::transmute(reset),
            cache_offset,
        };
        scene::prepare()?;
        let _ = API.set(api);
        Ok(())
    })();
    drop(xdl::xdl_close(module));
    result
}

// Match the ROM's inlined dirtyEntireOutput: use display bounds, not viewport.
// All offsets are extracted and cross-checked before hooks are installed.
unsafe extern "C" fn dirty_inline(output: Ptr) {
    let api = API.get().unwrap();
    let layout = api.dirty_layout.unwrap();
    let vtable = *output.cast::<*const u8>();
    let offset = core::ptr::read_unaligned(vtable.sub(layout.virtual_base).cast::<isize>());
    let base = output.cast::<u8>().offset(offset);
    let base_vtable = *base.cast::<*const u8>();
    let edit: unsafe extern "C" fn(Ptr) -> *mut u8 = core::mem::transmute(
        core::ptr::read_unaligned(base_vtable.add(layout.edit_slot).cast::<usize>()),
    );
    let state = edit(base.cast());
    let bounds = core::ptr::read_unaligned(state.add(layout.bounds).cast::<[i32; 2]>());
    let rect = [0i32, 0, bounds[0], bounds[1]];
    (api.region_set.unwrap())(state.add(layout.region).cast(), rect.as_ptr() as Ptr);
}

/// Initialize on the payload supervisor before starting UI/input workers.
pub fn initialize() -> Result<(), String> {
    static SETUP: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _setup = SETUP.lock().map_err(|_| "Skia setup lock poisoned")?;
    if installed() {
        return Ok(());
    }
    unsafe {
        prepare()?;
    }
    let result = super::quiescence::with_idle_threads(|| unsafe { install() })?;
    if result == 1 {
        Ok(())
    } else {
        Err("Skia hook installation failed".into())
    }
}

unsafe fn install() -> usize {
    if installed() {
        return 1;
    }
    let Some(api) = API.get() else {
        return 0;
    };
    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let p = libc::mmap(
        core::ptr::null_mut(),
        page,
        7,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        return 0;
    }
    libc::munmap(p, page);
    let replacements = [
        if api.rom.android12() {
            draw_layers12 as *const ()
        } else if api.rom.legacy() {
            draw_layers13 as *const ()
        } else {
            draw_layers as *const ()
        },
        draw_fade as *const (),
        begin_frame as *const (),
        compose_surfaces as *const (),
        if api.rom.legacy() {
            legacy_flush as *const ()
        } else {
            flush_gl as *const ()
        },
        if api.rom.android12() {
            dirty_region12 as *const ()
        } else {
            flush_vk as *const ()
        },
        flush_graphite as *const (),
        capture_begin as *const (),
        compute_buffer_damage as *const (),
    ];
    for (i, replacement) in replacements.iter().enumerate() {
        if api.targets[i] == 0 {
            continue;
        }
        // A failed rollback may retain a trampoline. Never install twice.
        if !ORIGINALS[i].load(Ordering::Acquire).is_null() {
            continue;
        }
        match dobby_rs::hook(api.targets[i] as Ptr, *replacement as Ptr) {
            Ok(original) => ORIGINALS[i].store(original, Ordering::Release),
            Err(_) => {
                for j in (0..i).rev() {
                    if !ORIGINALS[j].load(Ordering::Acquire).is_null()
                        && dobby_rs::unhook(api.targets[j] as Ptr).is_ok()
                    {
                        ORIGINALS[j].store(core::ptr::null_mut(), Ordering::Release);
                    }
                }
                return 0;
            }
        }
    }
    READY.store(true, Ordering::Release);
    1
}
unsafe extern "C" fn capture_begin(capture: Ptr, surface: Ptr) -> Ptr {
    let original: unsafe extern "C" fn(Ptr, Ptr) -> Ptr =
        core::mem::transmute(ORIGINALS[7].load(Ordering::Acquire));
    let canvas = original(capture, surface);
    SCOPE.with(|s| s.borrow_mut().capture(surface as usize));
    canvas
}

// API 31/32 return status_t and pass an output fence pointer. API 33/34
// fulfill a promise and still carry useFramebufferCache before the input fd.
unsafe extern "C" fn draw_layers12(
    engine: Ptr,
    display: Ptr,
    layers: Ptr,
    buffer: Ptr,
    internal: bool,
    fence: Ptr,
    out: Ptr,
) -> i32 {
    let _scope = enter_composition(engine, display.cast(), Some(internal));
    let original: unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr, bool, Ptr, Ptr) -> i32 =
        core::mem::transmute(ORIGINALS[0].load(Ordering::Acquire));
    original(engine, display, layers, buffer, internal, fence, out)
}
unsafe extern "C" fn draw_layers13(
    engine: Ptr,
    promise: Ptr,
    display: Ptr,
    layers: Ptr,
    buffer: Ptr,
    internal: bool,
    fence: Ptr,
) {
    let _scope = enter_composition(engine, display.cast(), Some(internal));
    let original: unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr, Ptr, bool, Ptr) =
        core::mem::transmute(ORIGINALS[0].load(Ordering::Acquire));
    original(engine, promise, display, layers, buffer, internal, fence)
}

core::arch::global_asm!(
    ".text", ".p2align 4", ".global espframe_skia_legacy_flush", ".hidden espframe_skia_legacy_flush",
    ".type espframe_skia_legacy_flush, %function",
    "espframe_skia_legacy_flush:", "bti c",
    "stp x29, x30, [sp, #-64]!", "mov x29, sp",
    "stp x0, x1, [sp, #16]", "stp x2, x3, [sp, #32]", "str x8, [sp, #48]",
    "mov x1, x30", "bl {before}", "mov x16, x0",
    "ldr x8, [sp, #48]", "ldp x2, x3, [sp, #32]", "ldp x0, x1, [sp, #16]",
    "ldp x29, x30, [sp], #64", "br x16",
    ".global espframe_skia_dirty_region12", ".hidden espframe_skia_dirty_region12",
    ".type espframe_skia_dirty_region12, %function",
    "espframe_skia_dirty_region12:", "bti c",
    "stp x29, x30, [sp, #-48]!", "mov x29, sp",
    "stp x0, x8, [sp, #16]", "str x1, [sp, #32]",
    "bl {dirty}", "mov x16, x0", "mov x17, x1",
    "ldp x0, x8, [sp, #16]", "ldr x1, [sp, #32]", "orr w1, w1, w17",
    "ldp x29, x30, [sp], #48", "br x16",
    before = sym before_legacy_flush, dirty = sym dirty_region12_original,
);
extern "C" {
    #[link_name = "espframe_skia_legacy_flush"]
    fn legacy_flush();
    #[link_name = "espframe_skia_dirty_region12"]
    fn dirty_region12();
}
#[repr(C)]
struct DirtyCall {
    original: Ptr,
    active: usize,
}
unsafe extern "C" fn dirty_region12_original() -> DirtyCall {
    DirtyCall {
        original: ORIGINALS[5].load(Ordering::Acquire),
        active: super::ACTIVE.load(Ordering::Acquire) as usize,
    }
}
unsafe extern "C" fn before_legacy_flush(surface: Ptr, caller: usize) -> Ptr {
    if caller == API.get().unwrap().legacy_flush_site {
        let engine = SCOPE.with(|s| s.borrow().current_engine());
        // The recognized ROM block verifies destination equality immediately
        // before this call. Nested/intermediate flushes have different callers.
        before_flush(engine as Ptr, core::ptr::null_mut(), &surface, 4);
    }
    ORIGINALS[4].load(Ordering::Acquire)
}
// All three backends have (this, SkiaGpuContext*, sk_sp<SkSurface>) parameters.
// Their nontrivial fence return uses x8; tail-call the trampoline with the
// caller's original x8 and LR, leaving return ownership entirely with the ROM.
core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".global espframe_skia_flush_gl",
    ".hidden espframe_skia_flush_gl",
    ".type espframe_skia_flush_gl, %function",
    "espframe_skia_flush_gl:",
    "bti c",
    "mov w3, #4",
    "b 2f",
    ".global espframe_skia_flush_vk",
    ".hidden espframe_skia_flush_vk",
    ".type espframe_skia_flush_vk, %function",
    "espframe_skia_flush_vk:",
    "bti c",
    "mov w3, #5",
    "b 2f",
    ".global espframe_skia_flush_graphite",
    ".hidden espframe_skia_flush_graphite",
    ".type espframe_skia_flush_graphite, %function",
    "espframe_skia_flush_graphite:",
    "bti c",
    "mov w3, #6",
    "2:",
    "stp x29, x30, [sp, #-48]!",
    "mov x29, sp",
    "stp x0, x1, [sp, #16]",
    "stp x2, x8, [sp, #32]",
    "bl {before_flush}",
    "mov x16, x0",
    "ldp x2, x8, [sp, #32]",
    "ldp x0, x1, [sp, #16]",
    "ldp x29, x30, [sp], #48",
    "br x16",
    before_flush = sym before_flush,
);
extern "C" {
    #[link_name = "espframe_skia_flush_gl"]
    fn flush_gl();
    #[link_name = "espframe_skia_flush_vk"]
    fn flush_vk();
    #[link_name = "espframe_skia_flush_graphite"]
    fn flush_graphite();
}
unsafe extern "C" fn before_flush(
    engine: Ptr,
    _context: Ptr,
    surface_slot: *const Ptr,
    index: usize,
) -> Ptr {
    let surface = if surface_slot.is_null() {
        core::ptr::null_mut()
    } else {
        *surface_slot
    };
    let frame = SCOPE.with(|s| s.borrow_mut().submit(engine as usize, surface as usize));
    // Skia objects are released on their owning RenderEngine thread.
    if !super::ACTIVE.load(Ordering::Acquire) {
        DRAW.with(|d| {
            d.borrow_mut().take();
        });
    } else if let Some((physical, geometry)) = frame {
        if physical || !super::FILTER.load(Ordering::Acquire) {
            if let Some(g) = geometry {
                // endCapture may already have destroyed its recording canvas.
                // Always obtain the live canvas from the surface being submitted.
                draw_canvas((API.get().unwrap().canvas)(surface), g);
            }
        }
    }
    ORIGINALS[index].load(Ordering::Acquire)
}
unsafe fn output_name<'a>(display: *const u8) -> Option<&'a [u8]> {
    if display.is_null() {
        return None;
    }
    let tag = *display;
    let (data, len) = if tag & 1 == 0 {
        (display.add(1), (tag >> 1) as usize)
    } else {
        (
            core::ptr::read_unaligned(display.add(16).cast::<*const u8>()),
            core::ptr::read_unaligned(display.add(8).cast::<usize>()),
        )
    };
    if data.is_null() || len > 256 || (tag & 1 == 0 && len > 22) {
        return None;
    }
    Some(core::slice::from_raw_parts(data, len))
}
fn enter_composition(engine: Ptr, display: *const u8, internal: Option<bool>) -> Composition {
    unsafe {
        let rom = API.get().unwrap().rom;
        let old = rom.android12() || rom == Rom::Android13;
        let name = if old {
            b"".as_slice()
        } else {
            output_name(display).unwrap_or(b"")
        };
        let (physical_offset, clip_offset) = if old { (0, 16) } else { (24, 40) };
        let geometry = if display.is_null() || name == b"RegionSampling" {
            None
        } else {
            let g = Geometry {
                physical: core::ptr::read_unaligned(display.add(physical_offset).cast()),
                clip: core::ptr::read_unaligned(display.add(clip_offset).cast()),
                orientation: core::ptr::read_unaligned(
                    display.add(API.get().unwrap().orientation_offset).cast(),
                ),
            };
            g.dimensions().map(|_| g)
        };
        let physical = if old {
            internal.unwrap_or(false)
        } else {
            rom.physical_output(name)
        };
        SCOPE.with(|s| s.borrow_mut().enter(engine as usize, physical, geometry));
        Composition
    }
}
struct Composition;
impl Drop for Composition {
    fn drop(&mut self) {
        SCOPE.with(|s| s.borrow_mut().leave());
    }
}
// These references/unique_ptr wrappers are borrowed exactly as passed by RE.
// Both original methods return void; the promise is fulfilled by ROM code.
unsafe extern "C" fn draw_layers(
    engine: Ptr,
    promise: Ptr,
    display: Ptr,
    layers: Ptr,
    buffer: Ptr,
    fence: Ptr,
) {
    let _scope = enter_composition(engine, display.cast(), None);
    let original: unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr, Ptr, Ptr) =
        core::mem::transmute(ORIGINALS[0].load(Ordering::Acquire));
    original(engine, promise, display, layers, buffer, fence);
}
unsafe extern "C" fn draw_fade(engine: Ptr, promise: Ptr, display: Ptr, layers: Ptr) {
    let _scope = enter_composition(engine, display.cast(), None);
    let original: unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr) =
        core::mem::transmute(ORIGINALS[1].load(Ordering::Acquire));
    original(engine, promise, display, layers);
}
unsafe extern "C" fn begin_frame(output: Ptr) {
    if super::ACTIVE.load(Ordering::Acquire) {
        (API.get().unwrap().dirty)(output);
    }
    let original: unsafe extern "C" fn(Ptr) =
        core::mem::transmute(ORIGINALS[2].load(Ordering::Acquire));
    original(output);
}

unsafe extern "C" fn compute_buffer_damage(damage: Ptr, width: i32, height: i32, region: Ptr) {
    if super::ACTIVE.load(Ordering::Acquire) && !region.is_null() && width > 0 && height > 0 {
        let rect = [0i32, 0, width, height];
        // Supply full damage BEFORE the ROM updates its buffer-age history and
        // partial-composition metadata. Expanding only the final Skia clip would
        // leave old menu pixels in buffers reused outside the ROM's damage.
        (API.get().unwrap().region_set.unwrap())(region, rect.as_ptr() as Ptr);
    }
    let original: unsafe extern "C" fn(Ptr, i32, i32, Ptr) =
        core::mem::transmute(ORIGINALS[8].load(Ordering::Acquire));
    original(damage, width, height, region);
}

// composeSurfaces returns optional<unique_fd> through x8. The wrapper preserves
// that storage and all five possible input registers. The cache token is scoped to this
// synchronous call, on the output's composition thread, never a worker map.
core::arch::global_asm!(
    ".text", ".p2align 4",
    ".global espframe_skia_compose_surfaces", ".hidden espframe_skia_compose_surfaces",
    ".type espframe_skia_compose_surfaces, %function",
    "espframe_skia_compose_surfaces:", "bti c",
    "stp x29, x30, [sp, #-112]!", "mov x29, sp",
    "str x4, [sp, #80]",
    "stp x0, x1, [sp, #16]", "stp x2, x3, [sp, #32]", "str x8, [sp, #48]",
    "bl {suspend}", "str x0, [sp, #56]",
    "bl {original}", "mov x16, x0",
    "ldp x0, x1, [sp, #16]", "ldp x2, x3, [sp, #32]", "ldr x8, [sp, #48]",
    "ldr x4, [sp, #80]", "blr x16", "stp x0, x1, [sp, #64]",
    "ldr x0, [sp, #16]", "ldr x1, [sp, #56]", "bl {resume}",
    "ldp x0, x1, [sp, #64]", "ldp x29, x30, [sp], #112", "ret",
    ".size espframe_skia_compose_surfaces, .-espframe_skia_compose_surfaces",
    suspend = sym suspend_cache, resume = sym resume_cache, original = sym compose_original,
);
extern "C" {
    #[link_name = "espframe_skia_compose_surfaces"]
    fn compose_surfaces();
}
unsafe extern "C" fn compose_original() -> Ptr {
    ORIGINALS[3].load(Ordering::Acquire)
}
unsafe extern "C" fn suspend_cache(output: Ptr) -> Ptr {
    if !super::ACTIVE.load(Ordering::Acquire) {
        return core::ptr::null_mut();
    }
    let slot = output
        .cast::<u8>()
        .add(API.get().unwrap().cache_offset)
        .cast::<Ptr>();
    if (*slot).is_null() {
        return core::ptr::null_mut();
    }
    let capacity = *(*slot).cast::<u32>();
    // Drop stale entries, including buffers that could contain our overlay.
    // The same capacity is restored, with no overlay frames added to the cache.
    (API.get().unwrap().reset_cache)(output, capacity);
    core::ptr::replace(slot, core::ptr::null_mut())
}
unsafe extern "C" fn resume_cache(output: Ptr, cache: Ptr) {
    if !cache.is_null() {
        let slot = output
            .cast::<u8>()
            .add(API.get().unwrap().cache_offset)
            .cast::<Ptr>();
        // Inspected composeSurfaces only reads this unique_ptr; it never resets it.
        assert!((*slot).is_null());
        *slot = cache;
    }
}
unsafe fn draw_canvas(canvas: Ptr, g: Geometry) {
    let Some(api) = API.get() else {
        return;
    };
    if canvas.is_null() {
        return;
    }
    let size = (api.size)(canvas);
    if !g.fits_canvas(size as u32, (size >> 32) as u32) {
        return;
    }
    // RenderEngine never waits for the UI producer or retains its ImGui pointers.
    let started = crate::debug_log::enabled().then(std::time::Instant::now);
    let (frame, lock_miss) = match super::LATEST.try_lock() {
        Ok(s) => (s.clone(), false),
        Err(_) => (None, true),
    };
    DRAW.with(|slot| {
        let mut slot = slot.borrow_mut();
        let mut reused = true;
        if let Some(frame) = frame {
            if slot
                .as_ref()
                .is_none_or(|(old, _)| !Arc::ptr_eq(old, &frame))
            {
                reused = false;
                match Scene::new(&frame, slot.as_ref().map(|(_, s)| s)) {
                    Ok(scene) => *slot = Some((frame, scene)),
                    Err(_) => {
                        slot.take();
                        return;
                    }
                }
            }
        }
        let Some((frame, scene)) = slot.as_ref() else {
            return;
        };
        if frame.produced.elapsed() > std::time::Duration::from_millis(500) {
            slot.take();
            return;
        }
        let Some((sx, sy, rw, rh)) = g.projection() else {
            return;
        };
        let Some(screen) = g.screen_size() else {
            return;
        };
        api.state.save(canvas);
        // T(physical) * S(output) * T(center) * R * T(-viewport/2) * S(frame).
        // Exact right-angle coefficients avoid a missing SkCanvas::rotate on 14.
        let (cos, sin) = match g.orientation {
            4 => (0., 1.),
            3 => (-1., 0.),
            7 => (0., -1.),
            _ => (1., 0.),
        };
        let w = screen.width as f32;
        let h = screen.height as f32;
        #[repr(C)]
        struct Matrix {
            values: [f32; 9],
            mask: u32,
        }
        let matrix = Matrix {
            values: [
                sx * cos * w / frame.width,
                -sx * sin * h / frame.height,
                g.physical[0] as f32 + sx * (rw / 2. - cos * w / 2. + sin * h / 2.),
                sy * sin * w / frame.width,
                sy * cos * h / frame.height,
                g.physical[1] as f32 + sy * (rh / 2. - sin * w / 2. - cos * h / 2.),
                0.,
                0.,
                1.,
            ],
            mask: 0x80,
        };
        (api.set_matrix)(canvas, matrix.values.as_ptr());
        scene.draw(canvas);
        api.state.restore(canvas);
        if let Some(started) = started {
            LATENCY.with(|stats| {
                stats.borrow_mut().record([
                    frame.produced.elapsed().as_secs_f64() * 1000.0,
                    started.elapsed().as_secs_f64() * 1000.0,
                    f64::from(reused),
                    f64::from(lock_miss),
                ])
            });
        }
    });
}
