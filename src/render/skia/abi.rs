//! Android-version adapters with runtime symbol resolution.
use super::profile::{for_sdk, Rom};
use crate::xdl;
use core::ffi::{c_void, CStr};

pub unsafe fn open_module() -> Result<(xdl::XdlHandle, Rom), String> {
    let sdk = crate::xdl::lzma::android_api_level();
    let rom = for_sdk(sdk).ok_or_else(|| format!("unsupported Skia Android API level: {sdk}"))?;
    let mut errors = Vec::new();
    for name in [c"libsurfaceflinger.so", c"/system/bin/surfaceflinger"] {
        match xdl::xdl_open(name, xdl::XDL_DEFAULT) {
            Ok(module) => return Ok((module, rom)),
            Err(error) => errors.push(format!("{}: {error}", name.to_string_lossy())),
        }
    }
    Err(errors.join("; "))
}

pub unsafe fn library_symbol(library: &CStr, name: &CStr) -> Result<usize, String> {
    let module = xdl::xdl_open(library, xdl::XDL_DEFAULT).map_err(|e| e.to_string())?;
    let result = symbol(&module, name);
    drop(xdl::xdl_close(module));
    result
}

pub unsafe fn function_words(
    module: &xdl::XdlHandle,
    name: &CStr,
    max_bytes: usize,
) -> Result<(usize, Vec<u32>), String> {
    let found = match xdl::xdl_sym(module, name) {
        Err(xdl::XdlError::SymbolNotFound) => xdl::xdl_dsym(module, name),
        result => result,
    }
    .map_err(|e| format!("{}: {e}", name.to_string_lossy()))?;
    if found.address % 4 != 0 || found.size == 0 || found.size % 4 != 0 || found.size > max_bytes {
        return Err(format!(
            "invalid probe boundary: {}",
            name.to_string_lossy()
        ));
    }
    Ok((
        found.address,
        core::slice::from_raw_parts(found.address as *const u32, found.size / 4).to_vec(),
    ))
}

/// Missing class delete is accepted only when both inspected SkVertices release
/// paths actually call the system's ordinary operator delete. A PLT name alone
/// is insufficient: validate its resolved GOT pointer in this loaded module.
pub unsafe fn checked_vertices_delete(module: &xdl::XdlHandle) -> Result<usize, String> {
    let expected = library_symbol(c"libc++.so", c"_ZdlPv")?;
    let (make_address, make) = function_words(
        module,
        c"_ZN10SkVertices8MakeCopyENS_10VertexModeEiPK7SkPointS3_PKjiPKt",
        8192,
    )?;
    let (builder_address, builder) =
        function_words(module, c"_ZN10SkVertices7Builder4initERKNS_4DescE", 8192)?;
    let (make_site, builder_site) =
        super::layout::vertices_delete_sites(&make, &builder).map_err(str::to_owned)?;
    let info = xdl::xdl_info(module, xdl::XDL_DI_DLINFO).map_err(|e| e.to_string())?;
    let contains = |address: usize, length: usize, flags: u32| {
        info.program_headers().iter().any(|header| {
            if header.p_type != 1 || header.p_flags & flags != flags {
                return false;
            }
            let Some(start) = info.base().checked_add(header.p_vaddr as usize) else {
                return false;
            };
            let Some(end) = start.checked_add(header.p_memsz as usize) else {
                return false;
            };
            address >= start && address.checked_add(length).is_some_and(|last| last <= end)
        })
    };
    let mut unref = None;
    for (address, code, site) in [
        (make_address, &make, make_site),
        (builder_address, &builder, builder_site),
    ] {
        let helper = super::layout::branch_address(address + site - 16, code[site / 4 - 4])
            .ok_or("invalid vertices unref call")?;
        if unref.replace(helper).is_some_and(|other| other != helper) {
            return Err("vertices release helpers disagree".into());
        }
        let mut target = super::layout::branch_address(address + site, code[site / 4])
            .ok_or("invalid vertices delete call")?;
        if target == expected {
            continue;
        }
        if target % 4 != 0 || !contains(target, 20, 5) {
            return Err("vertices delete target outside executable module".into());
        }
        if core::ptr::read(target as *const u32) == 0xd503245f {
            target += 4;
        }
        let stub = core::slice::from_raw_parts(target as *const u32, 4);
        let slot =
            super::layout::plt_slot(target, stub).ok_or("unsupported vertices delete import")?;
        if slot % 8 != 0
            || !contains(slot, 8, 4)
            || core::ptr::read(slot as *const usize) != expected
        {
            return Err("vertices release is not system operator delete".into());
        }
    }
    Ok(expected)
}

pub unsafe fn symbol(module: &xdl::XdlHandle, name: &CStr) -> Result<usize, String> {
    let found = match xdl::xdl_sym(module, name) {
        Err(xdl::XdlError::SymbolNotFound) => xdl::xdl_dsym(module, name),
        result => result,
    };
    found
        .map(|s| s.address)
        .map_err(|e| format!("{}: {e}", name.to_string_lossy()))
}

// Only absence enables an alternative; malformed ELF / read failures remain errors.
pub unsafe fn optional_symbol(
    module: &xdl::XdlHandle,
    name: &CStr,
) -> Result<Option<usize>, String> {
    let found = match xdl::xdl_sym(module, name) {
        Err(xdl::XdlError::SymbolNotFound) => xdl::xdl_dsym(module, name),
        result => result,
    };
    match found {
        Ok(value) => Ok(Some(value.address)),
        Err(xdl::XdlError::SymbolNotFound) => Ok(None),
        Err(error) => Err(format!("{}: {error}", name.to_string_lossy())),
    }
}

/// A bounded instruction check for the few inline ABI fallbacks. This checks
/// layout evidence, not a device/build identifier; unknown code fails closed.
pub unsafe fn checked_words(
    module: &xdl::XdlHandle,
    name: &CStr,
    words: &[u32],
) -> Result<usize, String> {
    checked_instructions(module, name, words, false)
}
pub unsafe fn checked_instructions(
    module: &xdl::XdlHandle,
    name: &CStr,
    words: &[u32],
    relocate_calls: bool,
) -> Result<usize, String> {
    let found = match xdl::xdl_sym(module, name) {
        Err(xdl::XdlError::SymbolNotFound) => xdl::xdl_dsym(module, name),
        result => result,
    }
    .map_err(|e| format!("{}: {e}", name.to_string_lossy()))?;
    if found.size < words.len() * 4
        || !core::slice::from_raw_parts(found.address as *const u32, words.len())
            .iter()
            .zip(words)
            .all(|(actual, expected)| {
                let mask = if relocate_calls && expected & 0xfc000000 == 0x94000000 {
                    0xfc000000
                } else {
                    u32::MAX
                };
                actual & mask == expected & mask
            })
    {
        return Err(format!(
            "unrecognized inline ABI: {}",
            name.to_string_lossy()
        ));
    }
    Ok(found.address)
}

type Ptr = *mut c_void;
pub struct CanvasState {
    save: unsafe extern "C" fn(Ptr, *const Rect) -> i32,
    restore: Option<unsafe extern "C" fn(Ptr)>,
    legacy_restore: Option<super::legacy::Restore12>,
}
impl CanvasState {
    pub unsafe fn resolve(module: &xdl::XdlHandle) -> Result<Self, String> {
        Ok(Self {
            save: core::mem::transmute(symbol(
                module,
                c"_ZN8SkCanvas28only_axis_aligned_saveBehindEPK6SkRect",
            )?),
            restore: optional_symbol(module, c"_ZN8SkCanvas7restoreEv")?
                .map(|p| core::mem::transmute(p)),
            legacy_restore: if optional_symbol(module, c"_ZN8SkCanvas7restoreEv")?.is_none() {
                if !for_sdk(crate::xdl::lzma::android_api_level()).is_some_and(Rom::android12) {
                    return Err("missing SkCanvas::restore".into());
                }
                Some(super::legacy::Restore12::resolve(module)?)
            } else {
                None
            },
        })
    }
    pub unsafe fn save(&self, canvas: Ptr) {
        // Shared by all six inspected API 35–37 samples. Empty bounds cannot
        // intersect any local clip: ordinary deferred save, no copy/layer/clear.
        (self.save)(
            canvas,
            &Rect {
                left: 0.,
                top: 0.,
                right: 0.,
                bottom: 0.,
            },
        );
    }
    pub unsafe fn restore(&self, canvas: Ptr) {
        // Our scopes always add exactly one save and balance inner scopes.
        match self.restore {
            Some(f) => f(canvas),
            None => self.legacy_restore.as_ref().unwrap().restore(canvas),
        }
    }
}

// Reserve the largest inspected paint, followed by a canary. ROM constructors
// are preferred; the compact fallback requires a checked move-constructor ABI.
#[repr(C, align(16))]
pub struct Paint {
    bytes: [u8; 96],
    canary: [u8; 16],
}
impl Paint {
    pub const fn storage() -> Self {
        Self {
            bytes: [0; 96],
            canary: [0xa5; 16],
        }
    }
    pub fn canary_ok(&self) -> bool {
        self.canary == [0xa5; 16]
    }
    pub unsafe fn construct_compact(&mut self) {
        self.bytes.fill(0);
        self.bytes[60..64].copy_from_slice(&1f32.to_ne_bytes());
        self.bytes[68..72].copy_from_slice(&4f32.to_ne_bytes());
    }
    pub unsafe fn attach_compact_shader(&mut self, shader: Ptr) {
        // Only called once on a newly constructed paint. The transferred ref
        // is subsequently released by the ROM destructor.
        let slot = self.bytes.as_mut_ptr().add(8).cast::<Ptr>();
        assert!((*slot).is_null());
        *slot = shader;
    }
}
#[repr(C)]
pub struct Rect {
    pub left: f32,
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
}
