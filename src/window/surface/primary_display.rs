//! Minimal Skia viewport query. libgui owns Binder/Parcelable decoding.
use super::{DisplayInfo, Orientation, UiDisplayState, WindowError};

fn primary_geometry(state: UiDisplayState) -> Result<DisplayInfo, WindowError> {
    if state.layer_stack != 0 {
        return Err(WindowError::Backend(
            "display no longer carries the primary layer stack".into(),
        ));
    }
    let orientation = match state.orientation {
        0 => Orientation::Portrait,
        1 => Orientation::Landscape,
        2 => Orientation::ReversePortrait,
        3 => Orientation::ReverseLandscape,
        _ => return Err(WindowError::Backend("invalid display orientation".into())),
    };
    let size = state.layer_stack_space_rect;
    if size.width <= 0 || size.height <= 0 {
        return Err(WindowError::InvalidSize);
    }
    // DisplayState is already oriented. Preserve the natural dimensions,
    // including devices whose natural orientation is landscape.
    let (width, height) = if orientation.IsRotated() {
        (size.height, size.width)
    } else {
        (size.width, size.height)
    };
    // Skia needs only geometry; retain its existing density/fps defaults.
    Ok(DisplayInfo::new(
        width as u32,
        height as u32,
        orientation,
        1.,
        60.,
        0,
    ))
}

#[cfg(target_os = "android")]
mod android {
    use super::super::{
        display_cache, function, open_library, status_result, symbol_label,
        CppPhysicalDisplayIdVector, CppStrongPointerRef, CppStrongPointerReturn,
        OwnedStrongPointer, RefBaseFn, RefBaseLayout, XdlLibrary, CPP_OPERATOR_DELETE,
        GET_DISPLAY_STATE, GET_PHYSICAL_DISPLAY_IDS, GET_PHYSICAL_DISPLAY_TOKEN,
        REFBASE_DEC_STRONG, REFBASE_INC_STRONG,
    };
    use super::{primary_geometry, DisplayInfo, UiDisplayState, WindowError};
    use crate::xdl::xdl_sym;
    use std::ffi::{c_void, CStr};

    #[derive(Clone, Copy)]
    struct Api {
        ids: unsafe extern "C" fn() -> CppPhysicalDisplayIdVector,
        token: unsafe extern "C" fn(u64) -> CppStrongPointerReturn,
        state: unsafe extern "C" fn(*const CppStrongPointerRef, *mut UiDisplayState) -> i32,
        retain: RefBaseFn,
        release: RefBaseFn,
        delete: unsafe extern "C" fn(*mut c_void),
    }

    /// Query on the viewport owner thread, never in an SF/RenderEngine callback.
    /// Only the 16-byte ui::DisplayState ABI crosses this boundary.
    pub struct PrimaryDisplayQuery {
        // Rust drops fields in declaration order: release the token first.
        token: Option<OwnedStrongPointer>,
        api: Api,
        _libraries: [XdlLibrary; 3],
    }

    // The backend moves to its owner thread; queries require exclusive access.
    // IBinder's RefBase retains/releases are thread-safe.
    unsafe impl Send for PrimaryDisplayQuery {}

    impl PrimaryDisplayQuery {
        pub fn resolve() -> Result<Self, WindowError> {
            let gui = open_library(b"libgui.so\0")?;
            let utils = open_library(b"libutils.so\0")?;
            let cpp = open_library(b"libc++.so\0")?;
            let symbol = |library: &XdlLibrary, name: &'static [u8]| {
                let name_c = CStr::from_bytes_with_nul(name).expect("static symbol");
                unsafe { xdl_sym(library.0.as_ref().expect("open library"), name_c) }
                    .map(|value| value.address as *mut c_void)
                    .map_err(|_| WindowError::AbiUnavailable(symbol_label(name)))
            };
            let api = unsafe {
                Api {
                    ids: function(symbol(&gui, GET_PHYSICAL_DISPLAY_IDS)?),
                    token: function(symbol(&gui, GET_PHYSICAL_DISPLAY_TOKEN)?),
                    state: function(symbol(&gui, GET_DISPLAY_STATE)?),
                    retain: function(symbol(&utils, REFBASE_INC_STRONG)?),
                    release: function(symbol(&utils, REFBASE_DEC_STRONG)?),
                    delete: function(symbol(&cpp, CPP_OPERATOR_DELETE)?),
                }
            };
            Ok(Self {
                token: None,
                api,
                _libraries: [cpp, utils, gui],
            })
        }

        pub fn query(&mut self) -> Result<DisplayInfo, WindowError> {
            let api = self.api;
            display_cache::query_cached(
                &mut self.token,
                || api.primary_token(),
                |token| primary_geometry(api.state(token)?),
            )
        }
    }

    impl Api {
        fn state(&self, token: &OwnedStrongPointer) -> Result<UiDisplayState, WindowError> {
            let mut state = UiDisplayState::default();
            let status = unsafe { (self.state)(&token.raw(), &mut state) };
            status_result(status, "getDisplayState")?;
            Ok(state)
        }

        fn physical_ids(&self) -> Result<Vec<u64>, WindowError> {
            let ids = unsafe { (self.ids)() };
            let begin = ids.begin as usize;
            let end = ids.end as usize;
            let capacity = ids.capacity_end as usize;
            let valid = begin != 0
                && begin % 8 == 0
                && end >= begin
                && capacity >= end
                && (end - begin) % 8 == 0
                && (capacity - begin) % 8 == 0
                && (end - begin) / 8 <= 64;
            let result = if valid {
                Ok(unsafe { std::slice::from_raw_parts(ids.begin, (end - begin) / 8) }.to_vec())
            } else {
                Err(WindowError::Backend("invalid physical display list".into()))
            };
            if !ids.begin.is_null() {
                // The vector storage belongs to the system libc++, not Rust.
                unsafe { (self.delete)(ids.begin.cast()) };
            }
            result
        }

        fn primary_token(&self) -> Result<OwnedStrongPointer, WindowError> {
            for id in self.physical_ids()? {
                let mut returned = unsafe { (self.token)(id) };
                let token = unsafe {
                    OwnedStrongPointer::adopt_returned_as(
                        &mut returned,
                        RefBaseLayout::BinderVirtual,
                        self.retain,
                        self.release,
                    )
                };
                let Some(token) = token else { continue };
                // Physical enumeration order is not logical display order.
                // Ignore inactive/secondary displays and transient hotplug errors.
                if self.state(&token).and_then(primary_geometry).is_ok() {
                    return Ok(token);
                }
            }
            Err(WindowError::Backend(
                "no physical display carries the primary layer stack".into(),
            ))
        }
    }
}

#[cfg(target_os = "android")]
pub use android::PrimaryDisplayQuery;

#[cfg(test)]
mod tests {
    use super::super::UiSize;
    use super::*;

    #[test]
    fn preserves_geometry_for_all_rotations_and_natural_landscape() {
        for (width, height) in [(1220, 2656), (2560, 1600)] {
            for rotation in 0..4 {
                let (w, h) = if rotation % 2 != 0 {
                    (height, width)
                } else {
                    (width, height)
                };
                let info = primary_geometry(UiDisplayState {
                    layer_stack: 0,
                    orientation: rotation,
                    layer_stack_space_rect: UiSize {
                        width: w,
                        height: h,
                    },
                })
                .unwrap();
                assert_eq!(
                    (info.physical_width, info.physical_height),
                    (width as u32, height as u32)
                );
                assert_eq!(
                    (info.oriented_size().width, info.oriented_size().height),
                    (w as u32, h as u32)
                );
            }
        }
    }

    #[test]
    fn rejects_secondary_inactive_and_invalid_display_states() {
        let main = UiDisplayState {
            layer_stack: 0,
            orientation: 0,
            layer_stack_space_rect: UiSize {
                width: 1220,
                height: 2656,
            },
        };
        for stack in [1, u32::MAX] {
            assert!(primary_geometry(UiDisplayState {
                layer_stack: stack,
                ..main
            })
            .is_err());
        }
        for rotation in [-1, 4, 256] {
            assert!(primary_geometry(UiDisplayState {
                orientation: rotation,
                ..main
            })
            .is_err());
        }
        for (width, height) in [(0, 2656), (1220, 0), (-1, 2656), (1220, -1)] {
            assert!(primary_geometry(UiDisplayState {
                layer_stack_space_rect: UiSize { width, height },
                ..main
            })
            .is_err());
        }
    }
}
