//! API 31–34 adapters. Never depend on SkiaCapture helpers or retain a canvas.
use super::{abi, profile::Rom};
use crate::xdl::XdlHandle;
use core::{
    ffi::{c_void, CStr},
    sync::atomic::{AtomicU32, Ordering},
};
use std::sync::OnceLock;
type Ptr = *mut c_void;

pub fn draw_symbol(rom: Rom) -> &'static CStr {
    if rom.android12() {
        c"_ZN7android12renderengine4skia18SkiaGLRenderEngine10drawLayersERKNS0_15DisplaySettingsERKNSt3__16vectorIPKNS0_13LayerSettingsENS6_9allocatorISA_EEEERKNS6_10shared_ptrINS0_15ExternalTextureEEEbONS_4base14unique_fd_implINSL_13DefaultCloserEEEPSO_"
    } else if rom == Rom::Android13 {
        c"_ZN7android12renderengine4skia18SkiaGLRenderEngine18drawLayersInternalEOKNSt3__110shared_ptrINS3_7promiseINS0_18RenderEngineResultEEEEERKNS0_15DisplaySettingsERKNS3_6vectorINS0_13LayerSettingsENS3_9allocatorISF_EEEERKNS4_INS0_15ExternalTextureEEEbONS_4base14unique_fd_implINSP_13DefaultCloserEEE"
    } else {
        c"_ZN7android12renderengine4skia16SkiaRenderEngine18drawLayersInternalEOKNSt3__110shared_ptrINS3_7promiseINS_4base8expectedINS_2spINS_5FenceEEEiEEEEEERKNS0_15DisplaySettingsERKNS3_6vectorINS0_13LayerSettingsENS3_9allocatorISK_EEEERKNS4_INS0_15ExternalTextureEEEbONS6_14unique_fd_implINS6_13DefaultCloserEEE"
    }
}
pub fn compose_symbol(rom: Rom) -> &'static CStr {
    if rom.android12() {
        c"_ZN7android17compositionengine4impl6Output15composeSurfacesERKNS_6RegionERKNS0_22CompositionRefreshArgsE"
    } else if rom == Rom::Android13 {
        c"_ZN7android17compositionengine4impl6Output15composeSurfacesERKNS_6RegionERKNS0_22CompositionRefreshArgsENSt3__110shared_ptrINS_12renderengine15ExternalTextureEEERNS_4base14unique_fd_implINSE_13DefaultCloserEEE"
    } else {
        c"_ZN7android17compositionengine4impl6Output15composeSurfacesERKNS_6RegionENSt3__110shared_ptrINS_12renderengine15ExternalTextureEEERNS_4base14unique_fd_implINSB_13DefaultCloserEEE"
    }
}
pub fn flush_symbol(rom: Rom) -> &'static CStr {
    if rom == Rom::Android14 {
        c"_ZN13SkSurface_Gpu7onFlushEN9SkSurface20BackendSurfaceAccessERK11GrFlushInfoPKN5skgpu19MutableTextureStateE"
    } else {
        c"_ZN13SkSurface_Gpu7onFlushEN9SkSurface20BackendSurfaceAccessERK11GrFlushInfoPK28GrBackendSurfaceMutableState"
    }
}

fn require(code: &[u32], sequence: &[u32], label: &str) -> Result<(), String> {
    if code
        .windows(sequence.len())
        .filter(|s| *s == sequence)
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(format!("unrecognized legacy {label} layout"))
    }
}

// At final flush the ROM has already created and used this cached canvas.
// A missing cache skips drawing; calling onNewCanvas would leak a second canvas.
pub unsafe fn canvas(module: &XdlHandle) -> Result<unsafe extern "C" fn(Ptr) -> Ptr, String> {
    let (_, dtor) = abi::function_words(module, c"_ZN14SkSurface_BaseD2Ev", 1024)?;
    require(
        &dtor,
        &[
            0xf9401260, 0xf900127f, 0xb40000c0, 0xf9400008, 0xf9400bf3, 0xf9400501,
        ],
        "cached canvas",
    )?;
    Ok(cached_canvas)
}
unsafe extern "C" fn cached_canvas(surface: Ptr) -> Ptr {
    *surface.cast::<u8>().add(0x20).cast::<Ptr>()
}

pub struct Restore12 {
    internal: unsafe extern "C" fn(Ptr),
}
impl Restore12 {
    pub unsafe fn resolve(module: &XdlHandle) -> Result<Self, String> {
        let (_, save) = abi::function_words(
            module,
            c"_ZN8SkCanvas28only_axis_aligned_saveBehindEPK6SkRect",
            2048,
        )?;
        require(
            &save,
            &[
                0xb94c6268, 0xf9402269, 0x11000508, 0xb90c6268, 0xb9405928, 0x11000508, 0xb9005928,
            ],
            "deferred save",
        )?;
        let (address, dtor) = abi::function_words(module, c"_ZN8SkCanvasD1Ev", 2048)?;
        let block = [
            0xf9402268, 0xb9405909, 0x7100053f, 0x54fffeaa, 0xb9403a68, 0x7100051f, 0x54ffff0d,
            0xf9400268, 0xaa1303e0, 0xf9403d08, 0xd63f0100, 0xb94c6268, 0xaa1303e0, 0x51000508,
            0xb90c6268,
        ];
        require(&dtor, &block, "restore stack")?;
        let at = dtor.windows(block.len()).position(|s| s == block).unwrap() + block.len();
        let internal = abi::symbol(module, c"_ZN8SkCanvas15internalRestoreEv")?;
        let branch = dtor[at];
        let displacement = ((branch << 6) as i32 >> 6) as isize * 4;
        if branch & 0xfc000000 != 0x94000000
            || (address + at * 4).wrapping_add_signed(displacement) != internal
            || dtor.get(at + 1..at + 5) != Some(&[0xf9400268, 0xaa1303e0, 0xf9404108, 0xd63f0100])
        {
            return Err("legacy restore dispatch not recognized".into());
        }
        Ok(Self {
            internal: core::mem::transmute(internal),
        })
    }
    pub unsafe fn restore(&self, canvas: Ptr) {
        let p = canvas.cast::<u8>();
        let rec = *p.add(0x40).cast::<*mut u8>();
        let deferred = rec.add(0x58).cast::<i32>();
        let count = p.add(0xc60).cast::<i32>();
        if *deferred > 0 {
            *deferred -= 1;
            *count -= 1;
        } else if *p.add(0x38).cast::<i32>() > 1 {
            let will: unsafe extern "C" fn(Ptr) =
                core::mem::transmute(*(*p.cast::<*const usize>()).add(15));
            will(canvas);
            *count -= 1;
            (self.internal)(canvas);
            let did: unsafe extern "C" fn(Ptr) =
                core::mem::transmute(*(*p.cast::<*const usize>()).add(16));
            did(canvas);
        }
    }
}

pub unsafe fn check_info(module: &XdlHandle) -> Result<(), String> {
    // Independent byte-size consumer verifies colorType and dimensions; the
    // bitmap consumer verifies colorspace and alpha at the corresponding fields.
    let (_, code) = abi::function_words(module, c"_ZNK11SkImageInfo15computeByteSizeEm", 1024)?;
    for offset in [8, 16, 20] {
        if !code.iter().any(|&w| {
            let base = (w >> 5) & 31;
            (base == 0 || (base == 19 && code.contains(&0xaa0003f3)))
                && matches!(w & 0xffc00000, 0xb9800000 | 0xb9400000)
                && ((w >> 10) & 0xfff) * 4 == offset
        }) {
            return Err("legacy ImageInfo fields not recognized".into());
        }
    }
    let (_, bitmap) = abi::function_words(module, c"_ZN8SkBitmap7setInfoERK11SkImageInfom", 2048)?;
    if !bitmap.contains(&0xaa0103f5)
        || !bitmap.contains(&0xf94002b6)
        || !(bitmap.contains(&0x29415c28)
            || bitmap.windows(2).any(|s| s == [0xb9400c21, 0xb9400aa0]))
    {
        return Err("legacy ImageInfo color/alpha ownership not recognized".into());
    }
    Ok(())
}

pub unsafe fn check_paint14(module: &XdlHandle) -> Result<(), String> {
    let (_, code) = abi::function_words(module, c"_ZN7SkPaintC1ERKS_", 1024)?;
    require(
        &code,
        &[0x3cc3c260, 0x3dc00e61, 0x3c83c280, 0x3d800e81],
        "paint values",
    )?;
    for i in 0..6 {
        let load = if i == 0 {
            0xf9400035
        } else {
            0xf9400275 | i << 10
        };
        let store = 0xf9000295 | i << 10;
        if !code.contains(&load) || !code.contains(&store) {
            return Err("legacy paint ownership not recognized".into());
        }
    }
    Ok(())
}
pub unsafe fn check_paint12(module: &XdlHandle) -> Result<(), String> {
    let (_, code) = abi::function_words(module, c"_ZN7SkPaintaSEOS_", 2048)?;
    // Shader is the second transferred owned pointer in the move assignment.
    if !code
        .windows(4)
        .any(|s| s == [0xf9400688, 0xf900069f, 0xf9400660, 0xf9000668])
    {
        return Err("legacy paint shader slot not recognized".into());
    }
    Ok(())
}

static DELETE_DATA: OnceLock<unsafe extern "C" fn(Ptr)> = OnceLock::new();
pub unsafe fn data_release(module: &XdlHandle) -> Result<unsafe extern "C" fn(Ptr), String> {
    let (_, code) = abi::function_words(module, c"_ZN6SkData18PrivateNewWithCopyEPKvm", 1024)?;
    require(
        &code,
        &[
            0xaa0003f6, 0x52800028, 0x9100a000, 0xa900fedf, 0xb90002c8, 0xa901d2c0,
        ],
        "owned data allocation",
    )?;
    let delete = core::mem::transmute(abi::library_symbol(c"libc++.so", c"_ZdlPv")?);
    let _ = DELETE_DATA.set(delete);
    Ok(unref_data)
}
unsafe extern "C" fn unref_data(data: Ptr) {
    // Only nonempty PrivateNewWithCopy allocations reach this adapter. The
    // checked factory initializes null release proc/context and refcount at 0.
    if !data.is_null() && (*data.cast::<AtomicU32>()).fetch_sub(1, Ordering::AcqRel) == 1 {
        (DELETE_DATA.get().unwrap())(data);
    }
}
