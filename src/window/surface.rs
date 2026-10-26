#![allow(non_snake_case)]
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use super::{DisplayInfo, Orientation, Size, WindowError};
use std::ffi::{c_void, CStr};
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

#[path = "surface/display_cache.rs"]
mod display_cache;
#[cfg(any(target_os = "android", test))]
#[path = "surface/primary_display.rs"]
mod primary_display;
#[cfg(target_os = "android")]
pub use primary_display::PrimaryDisplayQuery;
#[cfg(any(target_os = "android", test))]
#[path = "surface/mirror_abi.rs"]
mod mirror_abi;
#[cfg(target_os = "android")]
#[path = "surface/mirror_android.rs"]
mod mirror_android;
#[cfg(test)]
#[path = "surface/refbase_tests.rs"]
mod refbase_tests;

#[cfg(target_os = "android")]
use crate::xdl::{
    xdl_close, xdl_dsym, xdl_open, xdl_sym, XdlError, XdlHandle, XDL_ALWAYS_FORCE_LOAD,
};
#[cfg(target_os = "android")]
use std::collections::HashMap;

#[repr(C)]
pub struct ANativeWindow {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceHandle(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceConfig {
    pub layer: i32,
    pub trusted_overlay: bool,
    pub skip_screenshot: bool,
    pub buffer_size: Size,
}

type RefBaseFn = unsafe extern "C" fn(*const c_void, *const c_void);

#[repr(C, align(16))]
struct CppStrongPointerReturn {
    pointer: MaybeUninit<*mut c_void>,
    opaque: MaybeUninit<[usize; 3]>,
}

impl CppStrongPointerReturn {
    #[cfg(test)]
    const fn uninitialized() -> Self {
        Self {
            pointer: MaybeUninit::uninit(),
            opaque: MaybeUninit::uninit(),
        }
    }

    fn identity(&mut self) -> *const c_void {
        (self as *mut Self).cast()
    }

    unsafe fn pointer(&self) -> *mut c_void {
        unsafe { self.pointer.assume_init() }
    }

    #[cfg(test)]
    unsafe fn write_pointer_for_foreign_return(&mut self, pointer: *mut c_void) {
        self.pointer.write(pointer);
    }
}

#[cfg(target_os = "android")]
macro_rules! adopt_cpp_strong_return {
    ($backend:expr, $call:expr) => {{
        let mut returned: CppStrongPointerReturn = $call;
        $backend.adopt_returned(&mut returned)
    }};
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CppStrongPointerRef {
    pointer: *mut c_void,
}

impl CppStrongPointerRef {
    const fn new(pointer: *mut c_void) -> Self {
        Self { pointer }
    }
}

#[derive(Clone, Copy)]
enum RefBaseLayout {
    Direct,
    BinderVirtual,
}

impl RefBaseLayout {
    /// 参数必须是对应类型的有效 C++ 对象，虚表遵循 Android ARM64 Itanium ABI。
    unsafe fn pointer(self, object: NonNull<c_void>) -> NonNull<c_void> {
        match self {
            Self::Direct => object,
            Self::BinderVirtual => unsafe {
                // IBinder : public virtual RefBase；对象首地址不是 RefBase 子对象地址。
                // ARM64 编译器从 IBinder 虚表 address point 前第三项读取有符号虚基偏移。
                // BpBinder/BBinder 的具体布局可以不同，不能固定增加某个对象内偏移。
                let vtable = object.as_ptr().cast::<*const isize>().read();
                let offset = vtable.sub(3).read();
                NonNull::new_unchecked(object.as_ptr().cast::<u8>().offset(offset).cast())
            },
        }
    }
}

struct OwnedStrongPointer {
    pointer: NonNull<c_void>,
    refbase: NonNull<c_void>,
    release: RefBaseFn,
    identity: Box<u8>,
}

impl OwnedStrongPointer {
    unsafe fn adopt_returned(
        returned: &mut CppStrongPointerReturn,
        retain: RefBaseFn,
        release: RefBaseFn,
    ) -> Option<Self> {
        unsafe { Self::adopt_returned_as(returned, RefBaseLayout::Direct, retain, release) }
    }

    unsafe fn adopt_returned_as(
        returned: &mut CppStrongPointerReturn,
        layout: RefBaseLayout,
        retain: RefBaseFn,
        release: RefBaseFn,
    ) -> Option<Self> {
        let pointer = NonNull::new(unsafe { returned.pointer() })?;
        let refbase = unsafe { layout.pointer(pointer) };
        let identity = Box::new(0);
        unsafe {
            retain(
                refbase.as_ptr().cast_const(),
                (&*identity as *const u8).cast(),
            );
            // AOSP DEBUG_REFS=0 时 ID 仅用于调试记账，decStrong 仍递减实际计数。
            // 获取自有引用、释放返回值引用必须使用同一个 RefBase 子对象地址。
            release(refbase.as_ptr().cast_const(), returned.identity());
        }
        Some(Self {
            pointer,
            refbase,
            release,
            identity,
        })
    }

    #[cfg(test)]
    unsafe fn retain(&self, retain: RefBaseFn) -> Self {
        let identity = Box::new(0);
        retain(
            self.refbase.as_ptr().cast_const(),
            (&*identity as *const u8).cast(),
        );
        Self {
            pointer: self.pointer,
            refbase: self.refbase,
            release: self.release,
            identity,
        }
    }

    fn raw(&self) -> CppStrongPointerRef {
        CppStrongPointerRef::new(self.pointer.as_ptr())
    }

    fn pointer(&self) -> *mut c_void {
        self.pointer.as_ptr()
    }
}

impl Drop for OwnedStrongPointer {
    fn drop(&mut self) {
        unsafe {
            (self.release)(
                self.refbase.as_ptr().cast_const(),
                (&*self.identity as *const u8).cast(),
            );
        }
    }
}

trait PlacementStorage {
    fn pointer(&mut self) -> *mut c_void;
}

macro_rules! placement_storage {
    ($name:ident, $size:expr) => {
        #[repr(C, align(8))]
        struct $name {
            bytes: [MaybeUninit<u8>; $size],
        }

        impl $name {
            const fn new() -> Self {
                Self {
                    bytes: [MaybeUninit::uninit(); $size],
                }
            }
        }

        impl PlacementStorage for $name {
            fn pointer(&mut self) -> *mut c_void {
                self.bytes.as_mut_ptr().cast()
            }
        }
    };
}

placement_storage!(String8Storage, 8);
placement_storage!(LayerMetadataStorage, 64);
placement_storage!(SurfaceComposerClientStorage, 256);
placement_storage!(TransactionStorage, 2048);

const _: () = assert!(std::mem::size_of::<String8Storage>() >= 8);
const _: () = assert!(std::mem::align_of::<String8Storage>() >= 8);
const _: () = assert!(std::mem::size_of::<LayerMetadataStorage>() >= 64);
const _: () = assert!(std::mem::align_of::<LayerMetadataStorage>() >= 8);
const _: () = assert!(std::mem::size_of::<SurfaceComposerClientStorage>() >= 256);
const _: () = assert!(std::mem::align_of::<SurfaceComposerClientStorage>() >= 8);
const _: () = assert!(std::mem::size_of::<TransactionStorage>() >= 2048);
const _: () = assert!(std::mem::align_of::<TransactionStorage>() >= 8);

struct RetainedPlacementObject<S: PlacementStorage> {
    storage: NonNull<S>,
    release: RefBaseFn,
    identity: Box<u8>,
}

impl<S: PlacementStorage> RetainedPlacementObject<S> {
    unsafe fn new(storage: NonNull<S>, release: RefBaseFn, identity: Box<u8>) -> Self {
        Self {
            storage,
            release,
            identity,
        }
    }

    fn pointer(&mut self) -> *mut c_void {
        unsafe { self.storage.as_mut().pointer() }
    }
}

impl<S: PlacementStorage> Drop for RetainedPlacementObject<S> {
    fn drop(&mut self) {
        unsafe {
            (self.release)(
                self.storage.as_ptr().cast_const().cast(),
                (&*self.identity as *const u8).cast(),
            );
        }
    }
}

type PlacementDtor = unsafe extern "C" fn(*mut c_void);

struct DestroyedPlacementObject<S: PlacementStorage> {
    storage: Box<S>,
    destroy: PlacementDtor,
}

impl<S: PlacementStorage> DestroyedPlacementObject<S> {
    unsafe fn new(storage: Box<S>, destroy: PlacementDtor) -> Self {
        Self { storage, destroy }
    }

    fn pointer(&mut self) -> *mut c_void {
        self.storage.pointer()
    }
}

impl<S: PlacementStorage> Drop for DestroyedPlacementObject<S> {
    fn drop(&mut self) {
        unsafe { (self.destroy)(self.storage.pointer()) }
    }
}

struct VirtualDestroyedPlacementObject<S: PlacementStorage> {
    storage: Box<S>,
}

impl<S: PlacementStorage> VirtualDestroyedPlacementObject<S> {
    unsafe fn new(storage: Box<S>) -> Self {
        Self { storage }
    }

    fn pointer(&mut self) -> *mut c_void {
        self.storage.pointer()
    }
}

impl<S: PlacementStorage> Drop for VirtualDestroyedPlacementObject<S> {
    fn drop(&mut self) {
        unsafe {
            let object = self.storage.pointer();
            let vtable = object.cast::<*const *const c_void>().read();
            let complete_destructor = vtable.read();
            debug_assert!(!complete_destructor.is_null());
            let destroy: PlacementDtor = std::mem::transmute(complete_destructor);
            destroy(object);
        }
    }
}

enum TransactionPlacement {
    Direct(DestroyedPlacementObject<TransactionStorage>),
    Virtual(VirtualDestroyedPlacementObject<TransactionStorage>),
}

impl TransactionPlacement {
    fn pointer(&mut self) -> *mut c_void {
        match self {
            Self::Direct(transaction) => transaction.pointer(),
            Self::Virtual(transaction) => transaction.pointer(),
        }
    }
}

fn drop_placement_owners(
    transaction: &mut Option<TransactionPlacement>,
    client: &mut Option<RetainedPlacementObject<SurfaceComposerClientStorage>>,
) {
    transaction.take();
    client.take();
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UiSize {
    width: i32,
    height: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UiDisplayState {
    layer_stack: u32,
    orientation: i32,
    layer_stack_space_rect: UiSize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LegacyDisplayInfo {
    width: u32,
    height: u32,
    xdpi: f32,
    ydpi: f32,
    fps: f32,
    density: f32,
    orientation: u8,
    secure: bool,
    _padding: [u8; 6],
    app_vsync_offset: i64,
    presentation_deadline: i64,
    viewport_width: u32,
    viewport_height: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CppPhysicalDisplayIdVector {
    begin: *mut u64,
    end: *mut u64,
    capacity_end: *mut u64,
}

const CREATE_SURFACE_5_TO_7: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8Ejjij\0";
const CREATE_SURFACE_8: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijPNS_14SurfaceControlEjj\0";
const CREATE_SURFACE_9: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijPNS_14SurfaceControlEii\0";
const CREATE_SURFACE_10: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijPNS_14SurfaceControlENS_13LayerMetadataE\0";
const CREATE_SURFACE_11: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijPNS_14SurfaceControlENS_13LayerMetadataEPj\0";
const CREATE_SURFACE_12_TO_13: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijRKNS_2spINS_7IBinderEEENS_13LayerMetadataEPj\0";
const CREATE_SURFACE_14: &[u8] =
    b"_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjiiRKNS_2spINS_7IBinderEEENS_3gui13LayerMetadataEPj\0";
const GET_SURFACE_CONST: &[u8] = b"_ZNK7android14SurfaceControl10getSurfaceEv\0";
const GET_SURFACE_MUT: &[u8] = b"_ZN7android14SurfaceControl10getSurfaceEv\0";
const SET_LAYER_I32: &[u8] = b"_ZN7android14SurfaceControl8setLayerEi\0";
const SET_LAYER_U32: &[u8] = b"_ZN7android14SurfaceControl8setLayerEj\0";
const REFBASE_INC_STRONG: &[u8] = b"_ZNK7android7RefBase9incStrongEPKv\0";
const REFBASE_DEC_STRONG: &[u8] = b"_ZNK7android7RefBase9decStrongEPKv\0";
const STRING8_CTOR: &[u8] = b"_ZN7android7String8C2EPKc\0";
const STRING8_DTOR: &[u8] = b"_ZN7android7String8D2Ev\0";
const LAYER_METADATA_CTOR: &[u8] = b"_ZN7android13LayerMetadataC2Ev\0";
const LAYER_METADATA_VTABLE: &[u8] = b"_ZTVN7android13LayerMetadataE\0";
const GUI_LAYER_METADATA_CTOR: &[u8] = b"_ZN7android3gui13LayerMetadataC2Ev\0";
const GUI_LAYER_METADATA_VTABLE: &[u8] = b"_ZTVN7android3gui13LayerMetadataE\0";
const LAYER_METADATA_SET_I32: &[u8] = b"_ZN7android13LayerMetadata8setInt32Eji\0";
const CLIENT_CTOR: &[u8] = b"_ZN7android21SurfaceComposerClientC2Ev\0";
const GET_BUILT_IN_DISPLAY: &[u8] = b"_ZN7android21SurfaceComposerClient17getBuiltInDisplayEi\0";
const GET_INTERNAL_DISPLAY_TOKEN: &[u8] =
    b"_ZN7android21SurfaceComposerClient23getInternalDisplayTokenEv\0";
const GET_PHYSICAL_DISPLAY_IDS: &[u8] =
    b"_ZN7android21SurfaceComposerClient21getPhysicalDisplayIdsEv\0";
const GET_PHYSICAL_DISPLAY_TOKEN: &[u8] =
    b"_ZN7android21SurfaceComposerClient23getPhysicalDisplayTokenENS_17PhysicalDisplayIdE\0";
const GET_DISPLAY_INFO: &[u8] = b"_ZN7android21SurfaceComposerClient14getDisplayInfoERKNS_2spINS_7IBinderEEEPNS_11DisplayInfoE\0";
const GET_DISPLAY_STATE: &[u8] = b"_ZN7android21SurfaceComposerClient15getDisplayStateERKNS_2spINS_7IBinderEEEPNS_2ui12DisplayStateE\0";
const OPEN_GLOBAL_TRANSACTION: &[u8] =
    b"_ZN7android21SurfaceComposerClient21openGlobalTransactionEv\0";
const CLOSE_GLOBAL_TRANSACTION: &[u8] =
    b"_ZN7android21SurfaceComposerClient22closeGlobalTransactionEb\0";
const TRANSACTION_CTOR: &[u8] = b"_ZN7android21SurfaceComposerClient11TransactionC2Ev\0";
const TRANSACTION_DTOR: &[u8] = b"_ZN7android21SurfaceComposerClient11TransactionD2Ev\0";
const TRANSACTION_VTABLE: &[u8] = b"_ZTVN7android21SurfaceComposerClient11TransactionE\0";
const TRANSACTION_SET_LAYER: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction8setLayerERKNS_2spINS_14SurfaceControlEEEi\0";
const TRANSACTION_SET_TRUSTED_OVERLAY: &[u8] = b"_ZN7android21SurfaceComposerClient11Transaction17setTrustedOverlayERKNS_2spINS_14SurfaceControlEEEb\0";
const TRANSACTION_SHOW: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction4showERKNS_2spINS_14SurfaceControlEEE\0";
const MIRROR_SURFACE: &[u8] =
    b"_ZN7android21SurfaceComposerClient13mirrorSurfaceEPNS_14SurfaceControlE\0";
const MIRROR_SURFACE_WITH_STOP_AT: &[u8] =
    b"_ZN7android21SurfaceComposerClient13mirrorSurfaceEPNS_14SurfaceControlES2_\0";
const TRANSACTION_HIDE: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction4hideERKNS_2spINS_14SurfaceControlEEE\0";
const TRANSACTION_SET_LAYER_STACK: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction13setLayerStackERKNS_2spINS_14SurfaceControlEEENS_2ui10LayerStackE\0";
const TRANSACTION_SET_LAYER_STACK_U32: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction13setLayerStackERKNS_2spINS_14SurfaceControlEEEj\0";
const TRANSACTION_REPARENT: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction8reparentERKNS_2spINS_14SurfaceControlEEES6_\0";
const TRANSACTION_SET_MATRIX: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction9setMatrixERKNS_2spINS_14SurfaceControlEEEffff\0";
const TRANSACTION_SET_POSITION: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction11setPositionERKNS_2spINS_14SurfaceControlEEEff\0";
const MIRROR_TRANSACTION_SYMBOLS: [&[u8]; 4] = [
    TRANSACTION_HIDE,
    TRANSACTION_REPARENT,
    TRANSACTION_SET_MATRIX,
    TRANSACTION_SET_POSITION,
];
const TRANSACTION_APPLY_ONE_BOOL: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction5applyEb\0";
const TRANSACTION_APPLY_TWO_BOOLS: &[u8] =
    b"_ZN7android21SurfaceComposerClient11Transaction5applyEbb\0";
const SURFACE_CONTROL_DISCONNECT: &[u8] = b"_ZN7android14SurfaceControl10disconnectEv\0";
const SURFACE_DISCONNECT: &[u8] = b"_ZN7android7Surface10disconnectEi\0";
const ANATIVE_WINDOW_SET_BUFFERS_GEOMETRY: &[u8] = b"ANativeWindow_setBuffersGeometry\0";
const CPP_OPERATOR_DELETE: &[u8] = b"_ZdlPv\0";

fn layer_metadata_constructor_symbol(release: u32) -> &'static [u8] {
    if release >= 14 {
        GUI_LAYER_METADATA_CTOR
    } else {
        LAYER_METADATA_CTOR
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DisplayTokenAbi {
    BuiltIn,
    Internal,
    Physical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DisplayInfoAbi {
    Legacy,
    State,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionApplyAbi {
    OneBool,
    TwoBools,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MirrorLayerStackAbi {
    U32,
    UiLayerStack,
}

impl MirrorLayerStackAbi {
    fn for_release(release: u32) -> Option<Self> {
        match release {
            12 => Some(Self::U32),
            13..=16 => Some(Self::UiLayerStack),
            _ => None,
        }
    }

    fn symbol(self) -> &'static [u8] {
        match self {
            Self::U32 => TRANSACTION_SET_LAYER_STACK_U32,
            Self::UiLayerStack => TRANSACTION_SET_LAYER_STACK,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionDestroyAbi {
    Direct,
    Virtual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SkipScreenshotAbi {
    Unsupported,
    WindowType,
    LayerMetadata { key: u32, value: i32 },
    Flag(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MirrorDisplayAbi {
    Unavailable,
    Legacy,
    WithStopAt,
}

impl MirrorDisplayAbi {
    fn select(release: u32, legacy: bool, stop_at: bool, transactions: bool) -> Self {
        if !(12..=16).contains(&release) || !transactions {
            Self::Unavailable
        } else if legacy {
            Self::Legacy
        } else if stop_at {
            Self::WithStopAt
        } else {
            Self::Unavailable
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefBaseIdsDebugOnly {
    AospAndroid5To14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CppPlacementLayout {
    size: usize,
    align: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AndroidPlacementLayouts {
    string8: CppPlacementLayout,
    metadata: Option<CppPlacementLayout>,
    client: CppPlacementLayout,
    transaction: Option<CppPlacementLayout>,
}

const STRING8_LAYOUT_ANDROID_5_TO_14: CppPlacementLayout = CppPlacementLayout { size: 8, align: 8 };
const LAYER_METADATA_LAYOUT_ANDROID_10_TO_14: CppPlacementLayout =
    CppPlacementLayout { size: 64, align: 8 };
const SURFACE_COMPOSER_CLIENT_LAYOUT_ANDROID_5_TO_14: CppPlacementLayout = CppPlacementLayout {
    size: 256,
    align: 8,
};
const TRANSACTION_LAYOUT_ANDROID_9_TO_14: CppPlacementLayout = CppPlacementLayout {
    size: 2048,
    align: 8,
};

impl AndroidPlacementLayouts {
    fn for_release(release: u32) -> Option<Self> {
        match release {
            5..=8 => Some(Self {
                string8: STRING8_LAYOUT_ANDROID_5_TO_14,
                metadata: None,
                client: SURFACE_COMPOSER_CLIENT_LAYOUT_ANDROID_5_TO_14,
                transaction: None,
            }),
            9 => Some(Self {
                string8: STRING8_LAYOUT_ANDROID_5_TO_14,
                metadata: None,
                client: SURFACE_COMPOSER_CLIENT_LAYOUT_ANDROID_5_TO_14,
                transaction: Some(TRANSACTION_LAYOUT_ANDROID_9_TO_14),
            }),
            10..=16 => Some(Self {
                string8: STRING8_LAYOUT_ANDROID_5_TO_14,
                metadata: Some(LAYER_METADATA_LAYOUT_ANDROID_10_TO_14),
                client: SURFACE_COMPOSER_CLIENT_LAYOUT_ANDROID_5_TO_14,
                transaction: Some(TRANSACTION_LAYOUT_ANDROID_9_TO_14),
            }),
            _ => None,
        }
    }

    fn validate(self) -> Result<(), WindowError> {
        validate_placement_layout::<String8Storage>(self.string8, "String8 placement ABI")?;
        if let Some(metadata) = self.metadata {
            validate_placement_layout::<LayerMetadataStorage>(
                metadata,
                "LayerMetadata placement ABI",
            )?;
        }
        validate_placement_layout::<SurfaceComposerClientStorage>(
            self.client,
            "SurfaceComposerClient placement ABI",
        )?;
        if let Some(transaction) = self.transaction {
            validate_placement_layout::<TransactionStorage>(
                transaction,
                "Transaction placement ABI",
            )?;
        }
        Ok(())
    }
}

fn validate_placement_layout<S>(
    required: CppPlacementLayout,
    label: &'static str,
) -> Result<(), WindowError> {
    let actual_size = std::mem::size_of::<S>();
    let actual_align = std::mem::align_of::<S>();
    if actual_size < required.size
        || actual_align < required.align
        || !actual_size.is_multiple_of(required.align)
    {
        Err(WindowError::AbiUnavailable(label))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AndroidAbiPlan {
    release: u32,
    refbase_id_contract: Option<RefBaseIdsDebugOnly>,
    create_surface: &'static [u8],
    display_token: DisplayTokenAbi,
    display_info: DisplayInfoAbi,
    get_surface: &'static [u8],
    legacy_set_layer: Option<&'static [u8]>,
    apply: Option<TransactionApplyAbi>,
    transaction_destroy: Option<TransactionDestroyAbi>,
    trusted_overlay: bool,
    skip_screenshot: SkipScreenshotAbi,
    mirror_display: MirrorDisplayAbi,
    placements: AndroidPlacementLayouts,
}

impl AndroidAbiPlan {
    fn for_release(release: u32) -> Option<Self> {
        let placements = AndroidPlacementLayouts::for_release(release)?;
        let create_surface = match release {
            5..=7 => CREATE_SURFACE_5_TO_7,
            8 => CREATE_SURFACE_8,
            9 => CREATE_SURFACE_9,
            10 => CREATE_SURFACE_10,
            11 => CREATE_SURFACE_11,
            12..=13 => CREATE_SURFACE_12_TO_13,
            14..=16 => CREATE_SURFACE_14,
            _ => return None,
        };
        let display_token = match release {
            5..=9 => DisplayTokenAbi::BuiltIn,
            10..=13 => DisplayTokenAbi::Internal,
            14..=16 => DisplayTokenAbi::Physical,
            _ => return None,
        };
        let display_info = match release {
            5..=10 => DisplayInfoAbi::Legacy,
            11..=16 => DisplayInfoAbi::State,
            _ => return None,
        };
        let legacy_set_layer = match release {
            5 | 8 => Some(SET_LAYER_I32),
            6..=7 => Some(SET_LAYER_U32),
            _ => None,
        };
        let apply = match release {
            5..=8 => None,
            9..=12 => Some(TransactionApplyAbi::OneBool),
            13..=16 => Some(TransactionApplyAbi::TwoBools),
            _ => return None,
        };
        let transaction_destroy = match release {
            5..=8 => None,
            9..=14 => Some(TransactionDestroyAbi::Direct),
            15..=16 => Some(TransactionDestroyAbi::Virtual),
            _ => return None,
        };
        let skip_screenshot = match release {
            5..=7 => SkipScreenshotAbi::Unsupported,
            8..=9 => SkipScreenshotAbi::WindowType,
            10..=11 => SkipScreenshotAbi::LayerMetadata {
                key: 2,
                value: 441_731,
            },
            12..=16 => SkipScreenshotAbi::Flag(0x40),
            _ => return None,
        };
        Some(Self {
            release,
            refbase_id_contract: Some(RefBaseIdsDebugOnly::AospAndroid5To14),
            create_surface,
            display_token,
            display_info,
            get_surface: if release <= 11 {
                GET_SURFACE_CONST
            } else {
                GET_SURFACE_MUT
            },
            legacy_set_layer,
            apply,
            transaction_destroy,
            trusted_overlay: (12..=16).contains(&release),
            skip_screenshot,
            mirror_display: MirrorDisplayAbi::Unavailable,
            placements,
        })
    }

    fn validate_storage(self) -> Result<(), WindowError> {
        self.placements.validate()
    }

    fn validate_refbase_contract(self) -> Result<(), WindowError> {
        if self.refbase_id_contract == Some(RefBaseIdsDebugOnly::AospAndroid5To14) {
            Ok(())
        } else {
            Err(WindowError::AbiUnavailable("RefBase ID contract"))
        }
    }

    fn required_symbols(self, skip_screenshot: bool) -> Result<Vec<&'static [u8]>, WindowError> {
        if skip_screenshot && self.skip_screenshot == SkipScreenshotAbi::Unsupported {
            return Err(WindowError::AbiUnavailable("skip screenshot ABI"));
        }
        let mut symbols = vec![
            REFBASE_INC_STRONG,
            REFBASE_DEC_STRONG,
            STRING8_CTOR,
            STRING8_DTOR,
            CLIENT_CTOR,
            self.create_surface,
            self.get_surface,
            ANATIVE_WINDOW_SET_BUFFERS_GEOMETRY,
        ];
        match self.display_token {
            DisplayTokenAbi::BuiltIn => symbols.push(GET_BUILT_IN_DISPLAY),
            DisplayTokenAbi::Internal => symbols.push(GET_INTERNAL_DISPLAY_TOKEN),
            DisplayTokenAbi::Physical => {
                symbols.extend([
                    GET_PHYSICAL_DISPLAY_IDS,
                    GET_PHYSICAL_DISPLAY_TOKEN,
                    CPP_OPERATOR_DELETE,
                ]);
            }
        }
        symbols.push(match self.display_info {
            DisplayInfoAbi::Legacy => GET_DISPLAY_INFO,
            DisplayInfoAbi::State => GET_DISPLAY_STATE,
        });
        if self.release >= 10 {
            symbols.extend(if self.release >= 14 {
                [GUI_LAYER_METADATA_CTOR, GUI_LAYER_METADATA_VTABLE]
            } else {
                [LAYER_METADATA_CTOR, LAYER_METADATA_VTABLE]
            });
        }
        if skip_screenshot
            && matches!(
                self.skip_screenshot,
                SkipScreenshotAbi::LayerMetadata { .. }
            )
        {
            symbols.push(LAYER_METADATA_SET_I32);
        }
        if let Some(set_layer) = self.legacy_set_layer {
            symbols.extend([OPEN_GLOBAL_TRANSACTION, CLOSE_GLOBAL_TRANSACTION, set_layer]);
        } else {
            symbols.extend([TRANSACTION_CTOR, TRANSACTION_SET_LAYER, TRANSACTION_SHOW]);
            symbols.push(match self.transaction_destroy {
                Some(TransactionDestroyAbi::Direct) => TRANSACTION_DTOR,
                Some(TransactionDestroyAbi::Virtual) => TRANSACTION_VTABLE,
                None => return Err(WindowError::AbiUnavailable("transaction object ABI")),
            });
            symbols.push(match self.apply.unwrap() {
                TransactionApplyAbi::OneBool => TRANSACTION_APPLY_ONE_BOOL,
                TransactionApplyAbi::TwoBools => TRANSACTION_APPLY_TWO_BOOLS,
            });
            if self.trusted_overlay {
                symbols.push(TRANSACTION_SET_TRUSTED_OVERLAY);
            }
        }
        if self.release >= 7 {
            symbols.push(SURFACE_CONTROL_DISCONNECT);
        } else {
            symbols.push(SURFACE_DISCONNECT);
        }
        Ok(symbols)
    }
}

const NATIVE_WINDOW_SUBOBJECT_OFFSET: usize = 16;

fn DisconnectLegacySurfaceBeforeNativeRelease(
    release: u32,
    native_surface: Option<*mut c_void>,
    disconnect: impl FnOnce(*mut c_void, i32),
) {
    if release <= 6 {
        if let Some(native_surface) = native_surface {
            disconnect(native_surface, 1);
        }
    }
}

fn surface_to_native_window(surface: *mut c_void) -> Option<NonNull<ANativeWindow>> {
    NonNull::new(surface).and_then(|surface| {
        NonNull::new(
            surface
                .as_ptr()
                .cast::<u8>()
                .wrapping_add(NATIVE_WINDOW_SUBOBJECT_OFFSET)
                .cast(),
        )
    })
}

fn native_window_to_surface(window: NonNull<ANativeWindow>) -> *mut c_void {
    window
        .as_ptr()
        .cast::<u8>()
        .wrapping_sub(NATIVE_WINDOW_SUBOBJECT_OFFSET)
        .cast()
}

/// Operations that must have a proven Rust-callable ABI before production
/// surface creation is attempted. The default is deliberately empty: host
/// test doubles opt into the trait without claiming Android capabilities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SurfaceCapabilities {
    pub get_display_info: bool,
    pub create_surface: bool,
    pub set_layer: bool,
    pub set_trusted_overlay: bool,
    pub set_skip_screenshot: bool,
    pub set_buffer_size: bool,
    pub acquire_native_window: bool,
    pub release_native_window: bool,
    pub destroy_surface: bool,
    pub mirror_display: bool,
}

/// Distinguishes symbol discovery from an ABI that Rust can safely call.
/// A private C++ symbol may resolve while its object and return ABI remains
/// unknown, so it must not appear in `callable_abi`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SurfaceCapabilityReport {
    pub resolved_symbols: SurfaceCapabilities,
    pub callable_abi: SurfaceCapabilities,
}

impl SurfaceCapabilities {
    pub fn Require(self, skip_screenshot: bool) -> Result<(), WindowError> {
        let required = [
            (self.get_display_info, "get_display_info"),
            (self.create_surface, "create_surface"),
            (self.set_layer, "set_layer"),
            (self.set_trusted_overlay, "set_trusted_overlay"),
            (
                !skip_screenshot || self.set_skip_screenshot,
                "set_skip_screenshot",
            ),
            (self.set_buffer_size, "set_buffer_size"),
            (self.acquire_native_window, "acquire_window"),
            (self.release_native_window, "release_window"),
            (self.destroy_surface, "destroy_surface"),
        ];
        required
            .into_iter()
            .find(|(available, _)| !available)
            .map(|(_, name)| Err(WindowError::AbiUnavailable(name)))
            .unwrap_or(Ok(()))
    }
}

pub trait SurfaceComposerBackend: Send + 'static {
    fn Preflight(&mut self, skip_screenshot: bool) -> Result<(), WindowError> {
        let _ = skip_screenshot;
        Ok(())
    }
    fn GetDisplayInfo(&mut self) -> Result<DisplayInfo, WindowError>;
    fn CreateSurface(&mut self, name: &CStr, size: Size) -> Result<SurfaceHandle, WindowError>;
    fn SetLayer(&mut self, surface: &SurfaceHandle, layer: i32) -> Result<(), WindowError>;
    fn SetTrustedOverlay(
        &mut self,
        surface: &SurfaceHandle,
        enabled: bool,
    ) -> Result<(), WindowError>;
    fn SetSkipScreenshot(
        &mut self,
        surface: &SurfaceHandle,
        enabled: bool,
    ) -> Result<(), WindowError>;
    fn SetBufferSize(&mut self, surface: &SurfaceHandle, size: Size) -> Result<(), WindowError>;
    /// Apply the surface policy as one owned operation.
    ///
    /// Backends that need a single SurfaceComposer transaction can override
    /// this hook. The default keeps the host-testable setter contract while
    /// preserving the legacy ordering of policy calls.
    fn Configure(
        &mut self,
        surface: &SurfaceHandle,
        config: SurfaceConfig,
    ) -> Result<(), WindowError> {
        self.SetLayer(surface, config.layer)?;
        self.SetTrustedOverlay(surface, config.trusted_overlay)?;
        self.SetSkipScreenshot(surface, config.skip_screenshot)
    }
    fn AcquireNativeWindow(
        &mut self,
        surface: &SurfaceHandle,
    ) -> Result<NonNull<ANativeWindow>, WindowError>;
    fn ReleaseNativeWindow(&mut self, _window: NonNull<ANativeWindow>) {}
    fn ProcessMirrorDisplay(&mut self) -> Result<(), WindowError>;
    /// Whether this backend has a callable mirror-display implementation.
    ///
    /// Mirroring is an optional compatibility path. A backend that cannot
    /// safely resolve its private mirror ABI must leave this disabled so the
    /// primary overlay surface can still be created and rendered.
    fn MirrorEnabled(&self) -> bool {
        false
    }
    fn DestroySurface(&mut self, surface: SurfaceHandle);
}

pub struct NativeWindow<B: SurfaceComposerBackend> {
    backend: Arc<Mutex<B>>,
    surface: Option<SurfaceHandle>,
    native: NonNull<ANativeWindow>,
    size: Size,
}

// `ANativeWindow` is a reference-counted producer/consumer handle and the
// NDK exposes its acquire/release and buffer-geometry operations as
// thread-safe. SurfaceComposer creation can therefore happen on the
// supervisor thread while EGL initialization stays on the render worker. The
// actual EGL objects are still created and destroyed by the render worker;
// this hand-off only moves the native-window reference and its locked backend.
unsafe impl<B: SurfaceComposerBackend + Send> Send for NativeWindow<B> {}

impl<B: SurfaceComposerBackend> NativeWindow<B> {
    pub fn Size(&self) -> Size {
        self.size
    }
    pub fn AsRaw(&self) -> *mut c_void {
        self.native.as_ptr().cast()
    }
}

impl<B: SurfaceComposerBackend> Drop for NativeWindow<B> {
    fn drop(&mut self) {
        if let Some(surface) = self.surface.take() {
            crate::espframe_log!(
                "surface.native_window.drop",
                "native={:#x} surface={:#x} size={}x{}",
                self.native.as_ptr() as usize,
                surface.0,
                self.size.width,
                self.size.height
            );
            let mut backend = match self.backend.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            backend.ReleaseNativeWindow(self.native);
            backend.DestroySurface(surface);
        }
    }
}

pub struct NativeWindowService<B: SurfaceComposerBackend> {
    backend: Arc<Mutex<B>>,
    display: Option<DisplayInfo>,
}

impl<B: SurfaceComposerBackend> Clone for NativeWindowService<B> {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            display: self.display,
        }
    }
}

impl<B: SurfaceComposerBackend> NativeWindowService<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
            display: None,
        }
    }

    pub fn DisplayInfo(&mut self) -> Result<DisplayInfo, WindowError> {
        let info = self
            .backend
            .lock()
            .map_err(|_| WindowError::Backend("backend lock poisoned".into()))?
            .GetDisplayInfo()?;
        Ok(self.TrackDisplay(info))
    }

    fn TrackDisplay(&mut self, mut info: DisplayInfo) -> DisplayInfo {
        if let Some(previous) = self.display {
            if previous.orientation != info.orientation
                || previous.physical_width != info.physical_width
                || previous.physical_height != info.physical_height
            {
                info.generation = previous.generation.saturating_add(1);
            } else {
                info.generation = previous.generation;
            }
        }
        self.display = Some(info);
        info
    }

    pub fn Create(
        &mut self,
        name: &CStr,
        size: Size,
        skip_screenshot: bool,
    ) -> Result<NativeWindow<B>, WindowError> {
        self.CreateWithBufferSize(name, size, size, skip_screenshot)
    }

    /// Create a native window at the display's physical size while selecting
    /// an independent buffer size for rendering.
    ///
    /// Android's `createSurface` dimensions describe the native window layer;
    /// `ANativeWindow_setBuffersGeometry` controls the renderer's buffer.  A
    /// scaled render resolution therefore must not be passed to
    /// `createSurface`, otherwise the overlay is no longer aligned with the
    /// display layer.  The returned [`NativeWindow`] reports `buffer_size`,
    /// which is the size consumed by the renderer.
    pub fn CreateWithBufferSize(
        &mut self,
        name: &CStr,
        native_size: Size,
        buffer_size: Size,
        skip_screenshot: bool,
    ) -> Result<NativeWindow<B>, WindowError> {
        if !native_size.IsValid() || !buffer_size.IsValid() {
            return Err(WindowError::InvalidSize);
        }
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| WindowError::Backend("backend lock poisoned".into()))?;
        backend.Preflight(skip_screenshot)?;
        drop(backend);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| WindowError::Backend("backend lock poisoned".into()))?;
        let info = backend.GetDisplayInfo()?;
        drop(backend);
        let _info = self.TrackDisplay(info);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| WindowError::Backend("backend lock poisoned".into()))?;
        crate::espframe_log!(
            "surface.create.begin",
            "name={} native={}x{} buffer={}x{} skip_screenshot={}",
            name.to_string_lossy(),
            native_size.width,
            native_size.height,
            buffer_size.width,
            buffer_size.height,
            skip_screenshot
        );
        let surface = backend.CreateSurface(name, native_size)?;
        crate::espframe_log!("surface.create.ok", "surface={:#x}", surface.0);
        let config = SurfaceConfig {
            layer: i32::MAX,
            trusted_overlay: true,
            skip_screenshot,
            buffer_size,
        };
        if let Err(error) = backend.Configure(&surface, config) {
            backend.DestroySurface(surface);
            return Err(error);
        }
        let native = match backend.AcquireNativeWindow(&surface) {
            Ok(native) => native,
            Err(error) => {
                backend.DestroySurface(surface);
                return Err(error);
            }
        };
        crate::espframe_log!(
            "surface.native_window.acquire.ok",
            "surface={:#x} native={:#x}",
            surface.0,
            native.as_ptr() as usize
        );
        if let Err(error) = backend.SetBufferSize(&surface, buffer_size) {
            backend.ReleaseNativeWindow(native);
            backend.DestroySurface(surface);
            return Err(error);
        }
        drop(backend);
        Ok(NativeWindow {
            backend: Arc::clone(&self.backend),
            surface: Some(surface),
            native,
            size: buffer_size,
        })
    }

    pub fn ProcessMirrorDisplay(&mut self) -> Result<(), WindowError> {
        self.backend
            .lock()
            .map_err(|_| WindowError::Backend("backend lock poisoned".into()))?
            .ProcessMirrorDisplay()
    }

    pub fn MirrorEnabled(&self) -> bool {
        self.backend
            .lock()
            .map(|backend| backend.MirrorEnabled())
            .unwrap_or(false)
    }
}

#[cfg(target_os = "android")]
pub struct AndroidSurfaceComposerBackend {
    _libraries: AndroidLibraries,
    plan: AndroidAbiPlan,
    symbols: AndroidSymbols,
    client: Option<RetainedPlacementObject<SurfaceComposerClientStorage>>,
    transaction: Option<TransactionPlacement>,
    display_token: Option<OwnedStrongPointer>,
    source_layer_stack: std::cell::Cell<Option<u32>>,
    surfaces: HashMap<usize, AndroidSurface>,
    pending_skip_screenshot: bool,
    mirror_state: mirror_android::MirrorState,
}

#[cfg(target_os = "android")]
struct AndroidSymbols {
    pointers: HashMap<&'static [u8], *mut c_void>,
}

#[cfg(target_os = "android")]
impl AndroidSymbols {
    fn get(&self, name: &'static [u8]) -> *mut c_void {
        self.pointers
            .get(name)
            .copied()
            .unwrap_or(std::ptr::null_mut())
    }
}

#[cfg(target_os = "android")]
fn android_release() -> Result<u32, WindowError> {
    let mut value = [0 as libc::c_char; 128];
    let length = unsafe {
        libc::__system_property_get(c"ro.build.version.release".as_ptr(), value.as_mut_ptr())
    };
    if length <= 0 {
        return Err(WindowError::AbiUnavailable("Android release property"));
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), length as usize) };
    let digits = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect::<Vec<_>>();
    std::str::from_utf8(&digits)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(WindowError::AbiUnavailable("Android release property"))
}

#[cfg(target_os = "android")]
struct XdlLibrary(Option<XdlHandle>);

#[cfg(target_os = "android")]
impl Drop for XdlLibrary {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            if let Some(linker) = xdl_close(handle) {
                // Backend teardown drops every C++ owner before these libraries.
                unsafe { linker.close() };
            }
        }
    }
}

#[cfg(target_os = "android")]
struct AndroidLibraries {
    // Preserve the reverse-open release order, including on resolution errors.
    cpp: Option<XdlLibrary>,
    android: XdlLibrary,
    utils: XdlLibrary,
    gui: XdlLibrary,
}

#[cfg(target_os = "android")]
fn open_library(name: &'static [u8]) -> Result<XdlLibrary, WindowError> {
    let name_cstr = CStr::from_bytes_with_nul(name)
        .map_err(|_| WindowError::AbiUnavailable(library_label(name)))?;
    xdl_open(name_cstr, XDL_ALWAYS_FORCE_LOAD)
        .map(|handle| XdlLibrary(Some(handle)))
        .map_err(|_| WindowError::AbiUnavailable(library_label(name)))
}

#[cfg(target_os = "android")]
fn library_label(name: &'static [u8]) -> &'static str {
    match name {
        b"libgui.so\0" => "libgui.so",
        b"libutils.so\0" => "libutils.so",
        b"libandroid.so\0" => "libandroid.so",
        b"libc++.so\0" => "libc++.so",
        _ => "Android native library",
    }
}

#[cfg(target_os = "android")]
fn symbol_library<'a>(
    name: &'static [u8],
    libraries: &'a AndroidLibraries,
) -> Option<&'a XdlHandle> {
    let library = if matches!(
        name,
        REFBASE_INC_STRONG | REFBASE_DEC_STRONG | STRING8_CTOR | STRING8_DTOR
    ) {
        &libraries.utils
    } else if name == ANATIVE_WINDOW_SET_BUFFERS_GEOMETRY {
        &libraries.android
    } else if name == CPP_OPERATOR_DELETE {
        libraries.cpp.as_ref()?
    } else {
        &libraries.gui
    };
    library.0.as_ref()
}

#[cfg(target_os = "android")]
fn first_missing_symbol(
    symbols: &AndroidSymbols,
    plan: AndroidAbiPlan,
    skip_screenshot: bool,
) -> Option<&'static str> {
    let required = match plan.required_symbols(skip_screenshot) {
        Ok(required) => required,
        Err(WindowError::AbiUnavailable(name)) => return Some(name),
        Err(_) => return Some("SurfaceComposer ABI"),
    };
    required
        .into_iter()
        .find(|name| symbols.get(name).is_null())
        .map(symbol_label)
}

#[cfg(target_os = "android")]
fn symbol_label(name: &'static [u8]) -> &'static str {
    match name {
        REFBASE_INC_STRONG => "RefBase::incStrong",
        REFBASE_DEC_STRONG => "RefBase::decStrong",
        STRING8_CTOR => "String8::String8",
        STRING8_DTOR => "String8::~String8",
        LAYER_METADATA_CTOR | GUI_LAYER_METADATA_CTOR => "LayerMetadata::LayerMetadata",
        LAYER_METADATA_VTABLE | GUI_LAYER_METADATA_VTABLE => "LayerMetadata virtual destructor",
        LAYER_METADATA_SET_I32 => "LayerMetadata::setInt32",
        CLIENT_CTOR => "SurfaceComposerClient::SurfaceComposerClient",
        GET_BUILT_IN_DISPLAY => "SurfaceComposerClient::getBuiltInDisplay",
        GET_INTERNAL_DISPLAY_TOKEN => "SurfaceComposerClient::getInternalDisplayToken",
        GET_PHYSICAL_DISPLAY_IDS => "SurfaceComposerClient::getPhysicalDisplayIds",
        GET_PHYSICAL_DISPLAY_TOKEN => "SurfaceComposerClient::getPhysicalDisplayToken",
        GET_DISPLAY_INFO => "SurfaceComposerClient::getDisplayInfo",
        GET_DISPLAY_STATE => "SurfaceComposerClient::getDisplayState",
        OPEN_GLOBAL_TRANSACTION => "SurfaceComposerClient::openGlobalTransaction",
        CLOSE_GLOBAL_TRANSACTION => "SurfaceComposerClient::closeGlobalTransaction",
        TRANSACTION_CTOR => "SurfaceComposerClient::Transaction::Transaction",
        TRANSACTION_DTOR => "SurfaceComposerClient::Transaction::~Transaction",
        TRANSACTION_VTABLE => "SurfaceComposerClient::Transaction vtable",
        TRANSACTION_SET_LAYER => "SurfaceComposerClient::Transaction::setLayer",
        TRANSACTION_SET_TRUSTED_OVERLAY => "SurfaceComposerClient::Transaction::setTrustedOverlay",
        TRANSACTION_SHOW => "SurfaceComposerClient::Transaction::show",
        TRANSACTION_APPLY_ONE_BOOL | TRANSACTION_APPLY_TWO_BOOLS => {
            "SurfaceComposerClient::Transaction::apply"
        }
        GET_SURFACE_CONST | GET_SURFACE_MUT => "SurfaceControl::getSurface",
        SET_LAYER_I32 | SET_LAYER_U32 => "SurfaceControl::setLayer",
        SURFACE_CONTROL_DISCONNECT => "SurfaceControl::disconnect",
        SURFACE_DISCONNECT => "Surface::disconnect",
        ANATIVE_WINDOW_SET_BUFFERS_GEOMETRY => "ANativeWindow_setBuffersGeometry",
        CPP_OPERATOR_DELETE => "operator delete",
        CREATE_SURFACE_5_TO_7
        | CREATE_SURFACE_8
        | CREATE_SURFACE_9
        | CREATE_SURFACE_10
        | CREATE_SURFACE_11
        | CREATE_SURFACE_12_TO_13
        | CREATE_SURFACE_14 => "SurfaceComposerClient::createSurface",
        _ => "SurfaceComposer symbol",
    }
}

#[cfg(target_os = "android")]
unsafe fn function<T: Copy>(pointer: *mut c_void) -> T {
    debug_assert!(!pointer.is_null());
    std::mem::transmute_copy(&pointer)
}

#[cfg(target_os = "android")]
fn status_result(status: i32, operation: &'static str) -> Result<(), WindowError> {
    if status == 0 {
        Ok(())
    } else {
        Err(WindowError::Backend(format!(
            "{operation} failed: {status}"
        )))
    }
}

fn project_display_info(
    width: u32,
    height: u32,
    orientation: u8,
    density: f32,
    refresh_rate: f32,
) -> Result<DisplayInfo, WindowError> {
    if width == 0 || height == 0 {
        return Err(WindowError::Backend("invalid display geometry".into()));
    }
    let orientation = match orientation {
        0 => Orientation::Portrait,
        1 => Orientation::Landscape,
        2 => Orientation::ReversePortrait,
        3 => Orientation::ReverseLandscape,
        _ => return Err(WindowError::Backend("invalid display orientation".into())),
    };
    Ok(DisplayInfo::new(
        width.min(height),
        width.max(height),
        orientation,
        density,
        refresh_rate,
        0,
    ))
}

#[cfg(target_os = "android")]
struct AndroidSurface {
    control: OwnedStrongPointer,
    native_surface: Option<OwnedStrongPointer>,
    size: Size,
    skip_screenshot: bool,
}

#[cfg(target_os = "android")]
unsafe impl Send for AndroidSurfaceComposerBackend {}

#[cfg(target_os = "android")]
impl AndroidSurfaceComposerBackend {
    pub fn Resolve() -> Result<Self, WindowError> {
        let release = android_release()?;
        let mut plan = AndroidAbiPlan::for_release(release).ok_or(WindowError::Unsupported)?;
        plan.validate_refbase_contract()?;
        plan.validate_storage()?;
        let gui_handle = open_library(b"libgui.so\0")?;
        let utils_handle = open_library(b"libutils.so\0")?;
        let android_handle = open_library(b"libandroid.so\0")?;
        let cpp_handle = if release >= 14 {
            Some(open_library(b"libc++.so\0")?)
        } else {
            None
        };
        let libraries = AndroidLibraries {
            cpp: cpp_handle,
            android: android_handle,
            utils: utils_handle,
            gui: gui_handle,
        };

        let mut names = plan.required_symbols(false)?;
        if let Some(stack_abi) = MirrorLayerStackAbi::for_release(release) {
            names.extend([MIRROR_SURFACE, MIRROR_SURFACE_WITH_STOP_AT]);
            names.extend(MIRROR_TRANSACTION_SYMBOLS);
            names.push(stack_abi.symbol());
        }
        if matches!(
            plan.skip_screenshot,
            SkipScreenshotAbi::LayerMetadata { .. }
        ) {
            names.push(LAYER_METADATA_SET_I32);
        }
        names.sort_unstable();
        names.dedup();
        let mut pointers = HashMap::new();
        for name in names {
            let pointer = symbol_library(name, &libraries)
                .zip(CStr::from_bytes_with_nul(name).ok())
                .and_then(|(handle, symbol)| unsafe {
                    xdl_sym(handle, symbol)
                        .or_else(|error| match error {
                            XdlError::SymbolNotFound => xdl_dsym(handle, symbol),
                            error => Err(error),
                        })
                        .ok()
                })
                .map_or(std::ptr::null_mut(), |symbol| symbol.address as *mut c_void);
            pointers.insert(name, pointer);
        }
        let symbols = AndroidSymbols { pointers };
        if let Some(missing) = first_missing_symbol(&symbols, plan, false) {
            return Err(WindowError::AbiUnavailable(missing));
        }
        plan.mirror_display = MirrorDisplayAbi::select(
            release,
            !symbols.get(MIRROR_SURFACE).is_null(),
            !symbols.get(MIRROR_SURFACE_WITH_STOP_AT).is_null(),
            cfg!(any(feature = "jni", feature = "binder"))
                && MirrorLayerStackAbi::for_release(release)
                    .is_some_and(|abi| !symbols.get(abi.symbol()).is_null())
                && MIRROR_TRANSACTION_SYMBOLS
                    .iter()
                    .all(|name| !symbols.get(name).is_null()),
        );
        crate::espframe_log!(
            "surface.mirror.abi",
            "release={} abi={:?}",
            release,
            plan.mirror_display
        );

        let client = Box::new(SurfaceComposerClientStorage::new());
        let client_pointer = NonNull::new(Box::into_raw(client)).unwrap();
        let client_identity = Box::new(0);
        unsafe {
            let ctor: unsafe extern "C" fn(*mut c_void) = function(symbols.get(CLIENT_CTOR));
            ctor(client_pointer.as_ptr().cast());
            let retain: RefBaseFn = function(symbols.get(REFBASE_INC_STRONG));
            retain(
                client_pointer.as_ptr().cast_const().cast(),
                (&*client_identity as *const u8).cast(),
            );
        }
        let client = unsafe {
            RetainedPlacementObject::new(
                client_pointer,
                function(symbols.get(REFBASE_DEC_STRONG)),
                client_identity,
            )
        };
        let transaction = if let Some(destroy) = plan.transaction_destroy {
            let mut transaction = Box::new(TransactionStorage::new());
            unsafe {
                let ctor: unsafe extern "C" fn(*mut c_void) =
                    function(symbols.get(TRANSACTION_CTOR));
                ctor(transaction.pointer());
            }
            Some(match destroy {
                TransactionDestroyAbi::Direct => TransactionPlacement::Direct(unsafe {
                    DestroyedPlacementObject::new(
                        transaction,
                        function(symbols.get(TRANSACTION_DTOR)),
                    )
                }),
                TransactionDestroyAbi::Virtual => TransactionPlacement::Virtual(unsafe {
                    VirtualDestroyedPlacementObject::new(transaction)
                }),
            })
        } else {
            None
        };
        Ok(Self {
            _libraries: libraries,
            plan,
            symbols,
            client: Some(client),
            transaction,
            display_token: None,
            source_layer_stack: std::cell::Cell::new(None),
            surfaces: HashMap::new(),
            pending_skip_screenshot: false,
            mirror_state: mirror_android::MirrorState::default(),
        })
    }

    fn client_ptr(&mut self) -> *mut c_void {
        self.client.as_mut().unwrap().pointer()
    }

    fn transaction_ptr(&mut self) -> Result<*mut c_void, WindowError> {
        self.transaction
            .as_mut()
            .map(TransactionPlacement::pointer)
            .ok_or(WindowError::AbiUnavailable("transaction object ABI"))
    }

    fn dec_strong(&self) -> RefBaseFn {
        unsafe { function(self.symbols.get(REFBASE_DEC_STRONG)) }
    }

    fn inc_strong(&self) -> RefBaseFn {
        unsafe { function(self.symbols.get(REFBASE_INC_STRONG)) }
    }

    unsafe fn adopt_returned(
        &self,
        returned: &mut CppStrongPointerReturn,
    ) -> Option<OwnedStrongPointer> {
        unsafe {
            OwnedStrongPointer::adopt_returned(returned, self.inc_strong(), self.dec_strong())
        }
    }

    fn surface(&self, handle: &SurfaceHandle) -> Result<&AndroidSurface, WindowError> {
        self.surfaces
            .get(&handle.0)
            .ok_or_else(|| WindowError::Backend("unknown SurfaceControl".into()))
    }

    fn configure_surface(
        &mut self,
        handle: &SurfaceHandle,
        config: SurfaceConfig,
    ) -> Result<(), WindowError> {
        if config.skip_screenshot && !self.surface(handle)?.skip_screenshot {
            return Err(WindowError::Backend(
                "skip screenshot was not encoded during createSurface".into(),
            ));
        }
        let control_pointer = self.surface(handle)?.control.pointer();
        if let Some(set_layer_symbol) = self.plan.legacy_set_layer {
            unsafe {
                let open: unsafe extern "C" fn() =
                    function(self.symbols.get(OPEN_GLOBAL_TRANSACTION));
                let close: unsafe extern "C" fn(bool) =
                    function(self.symbols.get(CLOSE_GLOBAL_TRANSACTION));
                open();
                if set_layer_symbol == SET_LAYER_U32 {
                    let set_layer: unsafe extern "C" fn(*mut c_void, u32) =
                        function(self.symbols.get(set_layer_symbol));
                    set_layer(control_pointer, config.layer as u32);
                } else {
                    let set_layer: unsafe extern "C" fn(*mut c_void, i32) =
                        function(self.symbols.get(set_layer_symbol));
                    set_layer(control_pointer, config.layer);
                }
                close(false);
            }
            return Ok(());
        }
        let control = CppStrongPointerRef::new(control_pointer);
        let transaction = self.transaction_ptr()?;
        unsafe {
            let set_layer: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                i32,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_SET_LAYER));
            set_layer(transaction, &control, config.layer);
            if self.plan.trusted_overlay {
                let trusted: unsafe extern "C" fn(
                    *mut c_void,
                    *const CppStrongPointerRef,
                    bool,
                ) -> *mut c_void = function(self.symbols.get(TRANSACTION_SET_TRUSTED_OVERLAY));
                trusted(transaction, &control, config.trusted_overlay);
            }
            let show: unsafe extern "C" fn(*mut c_void, *const CppStrongPointerRef) -> *mut c_void =
                function(self.symbols.get(TRANSACTION_SHOW));
            show(transaction, &control);
        }
        self.apply_transaction()
    }

    fn apply_transaction(&mut self) -> Result<(), WindowError> {
        let transaction = self.transaction_ptr()?;
        let status = unsafe {
            match self.plan.apply {
                Some(TransactionApplyAbi::OneBool) => {
                    let apply: unsafe extern "C" fn(*mut c_void, bool) -> i32 =
                        function(self.symbols.get(TRANSACTION_APPLY_ONE_BOOL));
                    apply(transaction, false)
                }
                Some(TransactionApplyAbi::TwoBools) => {
                    let apply: unsafe extern "C" fn(*mut c_void, bool, bool) -> i32 =
                        function(self.symbols.get(TRANSACTION_APPLY_TWO_BOOLS));
                    apply(transaction, false, true)
                }
                None => return Err(WindowError::AbiUnavailable("transaction apply ABI")),
            }
        };
        status_result(status, "Transaction::apply")
    }

    fn release_surface(&self, mut surface: AndroidSurface) {
        let native_surface = surface
            .native_surface
            .as_ref()
            .map(|native_surface| native_surface.pointer());
        DisconnectLegacySurfaceBeforeNativeRelease(
            self.plan.release,
            native_surface,
            |native_surface, api| unsafe {
                let disconnect: unsafe extern "C" fn(*mut c_void, i32) =
                    function(self.symbols.get(SURFACE_DISCONNECT));
                disconnect(native_surface, api);
            },
        );
        surface.native_surface.take();
        if self.plan.release >= 7 {
            unsafe {
                let disconnect: unsafe extern "C" fn(*mut c_void) =
                    function(self.symbols.get(SURFACE_CONTROL_DISCONNECT));
                disconnect(surface.control.pointer());
            }
        }
        drop(surface);
    }

    pub fn Capabilities(&self) -> SurfaceCapabilities {
        let callable = first_missing_symbol(&self.symbols, self.plan, false).is_none();
        let screenshot = first_missing_symbol(&self.symbols, self.plan, true).is_none();
        SurfaceCapabilities {
            get_display_info: callable,
            create_surface: callable,
            set_layer: callable,
            set_trusted_overlay: callable,
            set_skip_screenshot: screenshot,
            set_buffer_size: callable,
            acquire_native_window: callable,
            release_native_window: callable,
            destroy_surface: callable,
            mirror_display: self.plan.mirror_display != MirrorDisplayAbi::Unavailable,
        }
    }

    pub fn CapabilityReport(&self) -> SurfaceCapabilityReport {
        SurfaceCapabilityReport {
            resolved_symbols: SurfaceCapabilities {
                get_display_info: first_missing_symbol(&self.symbols, self.plan, false).is_none(),
                create_surface: !self.symbols.get(self.plan.create_surface).is_null(),
                set_layer: self
                    .plan
                    .legacy_set_layer
                    .map(|name| !self.symbols.get(name).is_null())
                    .unwrap_or_else(|| !self.symbols.get(TRANSACTION_SET_LAYER).is_null()),
                set_trusted_overlay: !self.plan.trusted_overlay
                    || !self.symbols.get(TRANSACTION_SET_TRUSTED_OVERLAY).is_null(),
                set_skip_screenshot: first_missing_symbol(&self.symbols, self.plan, true).is_none(),
                set_buffer_size: !self
                    .symbols
                    .get(ANATIVE_WINDOW_SET_BUFFERS_GEOMETRY)
                    .is_null(),
                acquire_native_window: !self.symbols.get(self.plan.get_surface).is_null(),
                release_native_window: !self.symbols.get(REFBASE_DEC_STRONG).is_null(),
                destroy_surface: !self.symbols.get(REFBASE_DEC_STRONG).is_null(),
                mirror_display: self.plan.mirror_display != MirrorDisplayAbi::Unavailable,
            },
            callable_abi: self.Capabilities(),
        }
    }

    pub fn RequireProductionCapabilities(&self, skip_screenshot: bool) -> Result<(), WindowError> {
        self.Capabilities().Require(skip_screenshot)
    }

    pub fn ResolveProduction(skip_screenshot: bool) -> Result<Self, WindowError> {
        let backend = Self::Resolve()?;
        backend.RequireProductionCapabilities(skip_screenshot)?;
        Ok(backend)
    }
}

#[cfg(target_os = "android")]
impl Drop for AndroidSurfaceComposerBackend {
    fn drop(&mut self) {
        self.stop_mirrors();
        let surfaces: Vec<_> = self.surfaces.drain().map(|(_, surface)| surface).collect();
        for surface in surfaces {
            self.release_surface(surface);
        }
        self.display_token.take();
        drop_placement_owners(&mut self.transaction, &mut self.client);
    }
}

#[cfg(target_os = "android")]
impl AndroidSurfaceComposerBackend {
    fn acquire_display_token(&self) -> Result<OwnedStrongPointer, WindowError> {
        let mut returned = unsafe {
            match self.plan.display_token {
                DisplayTokenAbi::BuiltIn => {
                    let get: unsafe extern "C" fn(i32) -> CppStrongPointerReturn =
                        function(self.symbols.get(GET_BUILT_IN_DISPLAY));
                    get(0)
                }
                DisplayTokenAbi::Internal => {
                    let get: unsafe extern "C" fn() -> CppStrongPointerReturn =
                        function(self.symbols.get(GET_INTERNAL_DISPLAY_TOKEN));
                    get()
                }
                DisplayTokenAbi::Physical => {
                    let get_ids: unsafe extern "C" fn() -> CppPhysicalDisplayIdVector =
                        function(self.symbols.get(GET_PHYSICAL_DISPLAY_IDS));
                    let ids = get_ids();
                    let begin = ids.begin;
                    let id = if begin.is_null()
                        || ids.end as usize <= begin as usize
                        || !(ids.end as usize - begin as usize)
                            .is_multiple_of(std::mem::size_of::<u64>())
                    {
                        None
                    } else {
                        Some(*begin)
                    };
                    if !begin.is_null() {
                        let delete: unsafe extern "C" fn(*mut c_void) =
                            function(self.symbols.get(CPP_OPERATOR_DELETE));
                        delete(begin.cast());
                    }
                    let id =
                        id.ok_or_else(|| WindowError::Backend("no physical display id".into()))?;
                    let get: unsafe extern "C" fn(u64) -> CppStrongPointerReturn =
                        function(self.symbols.get(GET_PHYSICAL_DISPLAY_TOKEN));
                    get(id)
                }
            }
        };
        // 三种显示查询都返回 sp<IBinder>。查询继续用原始 IBinder*，引用计数用虚基地址。
        let display_token = unsafe {
            OwnedStrongPointer::adopt_returned_as(
                &mut returned,
                RefBaseLayout::BinderVirtual,
                self.inc_strong(),
                self.dec_strong(),
            )
        };
        display_token.ok_or_else(|| WindowError::Backend("display token is null".into()))
    }

    fn query_display_token(&self, token: &OwnedStrongPointer) -> Result<DisplayInfo, WindowError> {
        let token = token.raw();
        match self.plan.display_info {
            DisplayInfoAbi::Legacy => {
                let mut info = LegacyDisplayInfo::default();
                let status = unsafe {
                    let get: unsafe extern "C" fn(
                        *const CppStrongPointerRef,
                        *mut LegacyDisplayInfo,
                    ) -> i32 = function(self.symbols.get(GET_DISPLAY_INFO));
                    get(&token, &mut info)
                };
                status_result(status, "getDisplayInfo")?;
                project_display_info(
                    info.width,
                    info.height,
                    info.orientation,
                    info.density,
                    info.fps,
                )
            }
            DisplayInfoAbi::State => {
                let mut state = UiDisplayState::default();
                let status = unsafe {
                    let get: unsafe extern "C" fn(
                        *const CppStrongPointerRef,
                        *mut UiDisplayState,
                    ) -> i32 = function(self.symbols.get(GET_DISPLAY_STATE));
                    get(&token, &mut state)
                };
                status_result(status, "getDisplayState")?;
                if state.layer_stack_space_rect.width <= 0
                    || state.layer_stack_space_rect.height <= 0
                {
                    return Err(WindowError::Backend("invalid display geometry".into()));
                }
                let display = project_display_info(
                    state.layer_stack_space_rect.width as u32,
                    state.layer_stack_space_rect.height as u32,
                    state.orientation as u8,
                    0.0,
                    0.0,
                )?;
                self.source_layer_stack.set(Some(state.layer_stack));
                Ok(display)
            }
        }
    }
}

#[cfg(target_os = "android")]
impl AndroidSurfaceComposerBackend {
    fn create_control(
        &mut self,
        name: &CStr,
        size: Size,
        mut flags: u32,
        skip_screenshot: bool,
    ) -> Result<OwnedStrongPointer, WindowError> {
        let mut window_name_storage = Box::new(String8Storage::new());
        let string_dtor: PlacementDtor = unsafe { function(self.symbols.get(STRING8_DTOR)) };
        unsafe {
            let ctor: unsafe extern "C" fn(*mut c_void, *const libc::c_char) =
                function(self.symbols.get(STRING8_CTOR));
            ctor(window_name_storage.pointer(), name.as_ptr());
        }
        let mut window_name =
            unsafe { DestroyedPlacementObject::new(window_name_storage, string_dtor) };

        let mut metadata = if self.plan.release >= 10 {
            let mut storage = Box::new(LayerMetadataStorage::new());
            let ctor_symbol = layer_metadata_constructor_symbol(self.plan.release);
            unsafe {
                let ctor: unsafe extern "C" fn(*mut c_void) =
                    function(self.symbols.get(ctor_symbol));
                ctor(storage.pointer());
                Some(VirtualDestroyedPlacementObject::new(storage))
            }
        } else {
            None
        };
        let mut window_type_u32 = 0u32;
        let mut window_type_i32 = -1i32;
        if skip_screenshot {
            match self.plan.skip_screenshot {
                SkipScreenshotAbi::Unsupported => {}
                SkipScreenshotAbi::WindowType => {
                    window_type_u32 = 441_731;
                    window_type_i32 = 441_731;
                }
                SkipScreenshotAbi::LayerMetadata { key, value } => unsafe {
                    let set: unsafe extern "C" fn(*mut c_void, u32, i32) =
                        function(self.symbols.get(LAYER_METADATA_SET_I32));
                    set(metadata.as_mut().unwrap().pointer(), key, value);
                },
                SkipScreenshotAbi::Flag(flag) => flags |= flag,
            }
        }
        let client = self.client_ptr();
        let parent: *mut c_void = std::ptr::null_mut();
        let format = 1i32;
        let metadata_pointer = metadata
            .as_mut()
            .map(VirtualDestroyedPlacementObject::pointer)
            .unwrap_or(std::ptr::null_mut());
        let control = unsafe {
            match self.plan.release {
                5..=7 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        u32,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags,
                        )
                    )
                }
                8 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        u32,
                        *mut c_void,
                        u32,
                        u32,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags,
                            parent,
                            window_type_u32,
                            0,
                        )
                    )
                }
                9 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        u32,
                        *mut c_void,
                        i32,
                        i32,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags,
                            parent,
                            window_type_i32,
                            -1,
                        )
                    )
                }
                10 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        u32,
                        *mut c_void,
                        *mut c_void,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags,
                            parent,
                            metadata_pointer,
                        )
                    )
                }
                11 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        u32,
                        *mut c_void,
                        *mut c_void,
                        *mut u32,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags,
                            parent,
                            metadata_pointer,
                            std::ptr::null_mut(),
                        )
                    )
                }
                12..=13 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        u32,
                        *const *mut c_void,
                        *mut c_void,
                        *mut u32,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags,
                            &parent,
                            metadata_pointer,
                            std::ptr::null_mut(),
                        )
                    )
                }
                14..=16 => {
                    let create: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        u32,
                        u32,
                        i32,
                        i32,
                        *const *mut c_void,
                        *mut c_void,
                        *mut u32,
                    )
                        -> CppStrongPointerReturn =
                        function(self.symbols.get(self.plan.create_surface));
                    adopt_cpp_strong_return!(
                        self,
                        create(
                            client,
                            window_name.pointer(),
                            size.width,
                            size.height,
                            format,
                            flags as i32,
                            &parent,
                            metadata_pointer,
                            std::ptr::null_mut(),
                        )
                    )
                }
                _ => return Err(WindowError::Unsupported),
            }
        };
        drop(metadata);
        drop(window_name);
        let control =
            control.ok_or_else(|| WindowError::Backend("createSurface returned null".into()))?;
        Ok(control)
    }
}

#[cfg(target_os = "android")]
impl SurfaceComposerBackend for AndroidSurfaceComposerBackend {
    fn Preflight(&mut self, skip_screenshot: bool) -> Result<(), WindowError> {
        self.RequireProductionCapabilities(skip_screenshot)?;
        self.pending_skip_screenshot = skip_screenshot;
        Ok(())
    }

    fn GetDisplayInfo(&mut self) -> Result<DisplayInfo, WindowError> {
        let mut token = self.display_token.take();
        let result = display_cache::query_cached(
            &mut token,
            || self.acquire_display_token(),
            |token| self.query_display_token(token),
        );
        self.display_token = token;
        result
    }

    fn CreateSurface(&mut self, name: &CStr, size: Size) -> Result<SurfaceHandle, WindowError> {
        let control = self.create_control(name, size, 0, self.pending_skip_screenshot)?;
        let key = control.pointer() as usize;
        if self.surfaces.contains_key(&key) {
            return Err(WindowError::Backend("duplicate SurfaceControl".into()));
        }
        self.surfaces.insert(
            key,
            AndroidSurface {
                control,
                native_surface: None,
                size,
                skip_screenshot: self.pending_skip_screenshot,
            },
        );
        self.mirror_state.mark_sources_changed();
        Ok(SurfaceHandle(key))
    }
    fn SetLayer(&mut self, surface: &SurfaceHandle, layer: i32) -> Result<(), WindowError> {
        self.configure_surface(
            surface,
            SurfaceConfig {
                layer,
                trusted_overlay: false,
                skip_screenshot: false,
                buffer_size: Size::new(1, 1),
            },
        )
    }
    fn SetTrustedOverlay(
        &mut self,
        surface: &SurfaceHandle,
        enabled: bool,
    ) -> Result<(), WindowError> {
        if !self.plan.trusted_overlay {
            return Ok(());
        }
        let control = CppStrongPointerRef::new(self.surface(surface)?.control.pointer());
        let transaction = self.transaction_ptr()?;
        unsafe {
            let trusted: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                bool,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_SET_TRUSTED_OVERLAY));
            trusted(transaction, &control, enabled);
        }
        self.apply_transaction()
    }
    fn SetSkipScreenshot(
        &mut self,
        surface: &SurfaceHandle,
        enabled: bool,
    ) -> Result<(), WindowError> {
        if !enabled {
            return Ok(());
        }
        if self.surface(surface)?.skip_screenshot {
            Ok(())
        } else {
            Err(WindowError::Backend(
                "skip screenshot must be encoded by createSurface".into(),
            ))
        }
    }
    fn SetBufferSize(&mut self, surface: &SurfaceHandle, size: Size) -> Result<(), WindowError> {
        let native = self
            .surface(surface)?
            .native_surface
            .as_ref()
            .and_then(|surface| surface_to_native_window(surface.pointer()))
            .ok_or_else(|| WindowError::Backend("native window is not acquired".into()))?;
        let status = unsafe {
            let geometry: unsafe extern "C" fn(*mut ANativeWindow, i32, i32, i32) -> i32 =
                function(self.symbols.get(ANATIVE_WINDOW_SET_BUFFERS_GEOMETRY));
            geometry(native.as_ptr(), size.width as i32, size.height as i32, 0)
        };
        status_result(status, "ANativeWindow_setBuffersGeometry")
    }
    fn Configure(
        &mut self,
        surface: &SurfaceHandle,
        config: SurfaceConfig,
    ) -> Result<(), WindowError> {
        self.configure_surface(surface, config)
    }
    fn AcquireNativeWindow(
        &mut self,
        surface: &SurfaceHandle,
    ) -> Result<NonNull<ANativeWindow>, WindowError> {
        if let Some(native) = self.surface(surface)?.native_surface.as_ref() {
            return surface_to_native_window(native.pointer())
                .ok_or_else(|| WindowError::Backend("getSurface returned null".into()));
        }
        let control = self.surface(surface)?.control.pointer();
        let native_surface = unsafe {
            let get: unsafe extern "C" fn(*mut c_void) -> CppStrongPointerReturn =
                function(self.symbols.get(self.plan.get_surface));
            adopt_cpp_strong_return!(self, get(control))
        };
        let native_surface = native_surface
            .ok_or_else(|| WindowError::Backend("getSurface returned null".into()))?;
        let window = surface_to_native_window(native_surface.pointer())
            .ok_or_else(|| WindowError::Backend("getSurface returned null".into()))?;
        self.surfaces.get_mut(&surface.0).unwrap().native_surface = Some(native_surface);
        Ok(window)
    }
    fn ReleaseNativeWindow(&mut self, window: NonNull<ANativeWindow>) {
        let base = native_window_to_surface(window);
        for surface in self.surfaces.values_mut() {
            if surface
                .native_surface
                .as_ref()
                .map(|owner| owner.pointer() == base)
                .unwrap_or(false)
            {
                // Android 5 and 6 have no SurfaceControl::disconnect.  The
                // producer must be disconnected while the Surface strong
                // reference is still retained; release_surface will see the
                // cleared native owner afterward and therefore cannot repeat
                // this call.
                let native_surface = surface
                    .native_surface
                    .as_ref()
                    .map(|native_surface| native_surface.pointer());
                DisconnectLegacySurfaceBeforeNativeRelease(
                    self.plan.release,
                    native_surface,
                    |native_surface, api| unsafe {
                        let disconnect: unsafe extern "C" fn(*mut c_void, i32) =
                            function(self.symbols.get(SURFACE_DISCONNECT));
                        disconnect(native_surface, api);
                    },
                );
                surface.native_surface.take();
                break;
            }
        }
    }
    fn ProcessMirrorDisplay(&mut self) -> Result<(), WindowError> {
        self.refresh_mirrors()
    }

    fn MirrorEnabled(&self) -> bool {
        !matches!(self.plan.mirror_display, MirrorDisplayAbi::Unavailable)
    }
    fn DestroySurface(&mut self, surface: SurfaceHandle) {
        crate::espframe_log!("surface.destroy", "surface={:#x}", surface.0);
        self.clear_source_mirrors(surface.0);
        if let Some(surface) = self.surfaces.remove(&surface.0) {
            self.release_surface(surface);
        }
    }
}

#[cfg(test)]
mod android_abi_tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RETAINS: AtomicUsize = AtomicUsize::new(0);
    static RELEASES: AtomicUsize = AtomicUsize::new(0);
    static RETAIN_IDENTITIES: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static RELEASE_IDENTITIES: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static METADATA_DTORS: AtomicUsize = AtomicUsize::new(0);
    static TEARDOWN_EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    static AOSP_REFBASE_MODEL: Mutex<AospRefBaseModel> = Mutex::new(AospRefBaseModel {
        strong_count: 0,
        last_strong_calls: 0,
        original_identity: 0,
        retained_identity: 0,
        released_identities: Vec::new(),
    });

    struct AospRefBaseModel {
        strong_count: usize,
        last_strong_calls: usize,
        original_identity: usize,
        retained_identity: usize,
        released_identities: Vec<usize>,
    }

    unsafe extern "C" fn record_retain(_: *const c_void, identity: *const c_void) {
        RETAINS.fetch_add(1, Ordering::SeqCst);
        RETAIN_IDENTITIES.lock().unwrap().push(identity as usize);
    }

    unsafe extern "C" fn record_release(_: *const c_void, identity: *const c_void) {
        RELEASES.fetch_add(1, Ordering::SeqCst);
        RELEASE_IDENTITIES.lock().unwrap().push(identity as usize);
    }

    unsafe extern "C" fn record_client_release(pointer: *const c_void, _: *const c_void) {
        TEARDOWN_EVENTS.lock().unwrap().push("client_dec_strong");
        drop(unsafe { Box::from_raw(pointer.cast_mut().cast::<SurfaceComposerClientStorage>()) });
    }

    unsafe extern "C" fn record_transaction_dtor(_: *mut c_void) {
        TEARDOWN_EVENTS.lock().unwrap().push("transaction_dtor");
    }

    unsafe extern "C" fn record_metadata_dtor(_: *mut c_void) {
        METADATA_DTORS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn model_aosp_retain(_: *const c_void, identity: *const c_void) {
        let mut model = AOSP_REFBASE_MODEL.lock().unwrap();
        model.strong_count += 1;
        model.retained_identity = identity as usize;
    }

    unsafe extern "C" fn model_aosp_release(_: *const c_void, identity: *const c_void) {
        let mut model = AOSP_REFBASE_MODEL.lock().unwrap();
        model.released_identities.push(identity as usize);
        model.strong_count -= 1;
        if model.strong_count == 0 {
            model.last_strong_calls += 1;
        }
    }

    #[test]
    fn aosp_debug_only_refbase_contract_balances_nrvo_and_moved_returns() {
        fn exercise(moved_local: bool) {
            let pointer = NonNull::<u8>::dangling().as_ptr().cast();
            let mut returned = CppStrongPointerReturn::uninitialized();
            let return_object_identity = returned.identity() as usize;
            let local_identity = if moved_local {
                return_object_identity.wrapping_add(align_of::<CppStrongPointerReturn>())
            } else {
                return_object_identity
            };
            if moved_local {
                assert_ne!(local_identity, return_object_identity);
            }
            unsafe { returned.write_pointer_for_foreign_return(pointer) };
            *AOSP_REFBASE_MODEL.lock().unwrap() = AospRefBaseModel {
                strong_count: 1,
                last_strong_calls: 0,
                original_identity: local_identity,
                retained_identity: 0,
                released_identities: Vec::new(),
            };

            let owner = unsafe {
                OwnedStrongPointer::adopt_returned(
                    &mut returned,
                    model_aosp_retain,
                    model_aosp_release,
                )
            }
            .unwrap();
            {
                let model = AOSP_REFBASE_MODEL.lock().unwrap();
                assert_eq!(model.strong_count, 1);
                assert_eq!(model.last_strong_calls, 0);
                assert_ne!(model.retained_identity, return_object_identity);
                assert_eq!(model.released_identities, [return_object_identity]);
                if moved_local {
                    assert_ne!(model.original_identity, model.released_identities[0]);
                }
            }

            drop(owner);
            let model = AOSP_REFBASE_MODEL.lock().unwrap();
            assert_eq!(model.strong_count, 0);
            assert_eq!(model.last_strong_calls, 1);
            assert_eq!(model.released_identities.len(), 2);
            assert_eq!(model.released_identities[1], model.retained_identity);
            let _ = local_identity;
        }

        let plan = AndroidAbiPlan::for_release(12).unwrap();
        assert_eq!(
            plan.refbase_id_contract,
            Some(RefBaseIdsDebugOnly::AospAndroid5To14)
        );
        let mut unqualified = plan;
        unqualified.refbase_id_contract = None;
        assert_eq!(
            unqualified.validate_refbase_contract(),
            Err(WindowError::AbiUnavailable("RefBase ID contract"))
        );
        exercise(false);
        exercise(true);
    }

    #[test]
    fn legacy_cpp_proxy_layouts_match_the_arm64_header() {
        assert_eq!(size_of::<CppStrongPointerReturn>(), 32);
        assert_eq!(align_of::<CppStrongPointerReturn>(), 16);
        assert_eq!(size_of::<CppStrongPointerRef>(), size_of::<usize>());
        assert_eq!(align_of::<CppStrongPointerRef>(), align_of::<usize>());
        assert_eq!(size_of::<String8Storage>(), 8);
        assert!(align_of::<String8Storage>() >= align_of::<usize>());
        assert_eq!(size_of::<LayerMetadataStorage>(), 64);
        assert!(align_of::<LayerMetadataStorage>() >= align_of::<usize>());
        assert_eq!(size_of::<SurfaceComposerClientStorage>(), 256);
        assert!(align_of::<SurfaceComposerClientStorage>() >= align_of::<usize>());
        assert_eq!(size_of::<TransactionStorage>(), 2048);
        assert!(align_of::<TransactionStorage>() >= align_of::<usize>());
        for release in 5..=16 {
            assert_eq!(
                AndroidAbiPlan::for_release(release)
                    .unwrap()
                    .validate_storage(),
                Ok(())
            );
        }
        assert_eq!(
            validate_placement_layout::<[u8; 1]>(
                STRING8_LAYOUT_ANDROID_5_TO_14,
                "String8 placement ABI"
            ),
            Err(WindowError::AbiUnavailable("String8 placement ABI"))
        );
        assert_eq!(size_of::<UiDisplayState>(), 16);
        assert_eq!(offset_of!(UiDisplayState, orientation), 4);
        assert_eq!(offset_of!(UiDisplayState, layer_stack_space_rect), 8);
        assert_eq!(size_of::<LegacyDisplayInfo>(), 56);
        assert_eq!(offset_of!(LegacyDisplayInfo, orientation), 24);
        assert_eq!(offset_of!(LegacyDisplayInfo, app_vsync_offset), 32);
        assert_eq!(size_of::<CppPhysicalDisplayIdVector>(), 24);
    }

    #[test]
    fn release_plan_selects_only_the_matching_mangled_abi() {
        let android_5 = AndroidAbiPlan::for_release(5).unwrap();
        assert_eq!(android_5.create_surface, CREATE_SURFACE_5_TO_7);
        assert_eq!(android_5.display_token, DisplayTokenAbi::BuiltIn);
        assert_eq!(android_5.display_info, DisplayInfoAbi::Legacy);
        assert_eq!(android_5.get_surface, GET_SURFACE_CONST);
        assert_eq!(android_5.legacy_set_layer, Some(SET_LAYER_I32));

        let android_6 = AndroidAbiPlan::for_release(6).unwrap();
        assert_eq!(android_6.legacy_set_layer, Some(SET_LAYER_U32));

        let android_8 = AndroidAbiPlan::for_release(8).unwrap();
        assert_eq!(android_8.create_surface, CREATE_SURFACE_8);
        assert_eq!(android_8.legacy_set_layer, Some(SET_LAYER_I32));

        let android_9 = AndroidAbiPlan::for_release(9).unwrap();
        assert_eq!(android_9.create_surface, CREATE_SURFACE_9);
        assert_eq!(android_9.apply, Some(TransactionApplyAbi::OneBool));

        let android_10 = AndroidAbiPlan::for_release(10).unwrap();
        assert_eq!(android_10.create_surface, CREATE_SURFACE_10);
        assert_eq!(android_10.display_token, DisplayTokenAbi::Internal);
        assert_eq!(android_10.display_info, DisplayInfoAbi::Legacy);

        let android_11 = AndroidAbiPlan::for_release(11).unwrap();
        assert_eq!(android_11.create_surface, CREATE_SURFACE_11);
        assert_eq!(android_11.display_info, DisplayInfoAbi::State);

        let android_12 = AndroidAbiPlan::for_release(12).unwrap();
        assert_eq!(android_12.create_surface, CREATE_SURFACE_12_TO_13);
        assert_eq!(android_12.get_surface, GET_SURFACE_MUT);
        assert!(android_12.trusted_overlay);
        assert_eq!(android_12.apply, Some(TransactionApplyAbi::OneBool));

        let android_13 = AndroidAbiPlan::for_release(13).unwrap();
        assert_eq!(android_13.apply, Some(TransactionApplyAbi::TwoBools));

        let android_14 = AndroidAbiPlan::for_release(14).unwrap();
        assert_eq!(android_14.create_surface, CREATE_SURFACE_14);
        assert_eq!(android_14.display_token, DisplayTokenAbi::Physical);
        assert_eq!(android_14.apply, Some(TransactionApplyAbi::TwoBools));

        let android_15 = AndroidAbiPlan::for_release(15).unwrap();
        assert_eq!(android_15.create_surface, CREATE_SURFACE_14);
        assert_eq!(android_15.display_token, DisplayTokenAbi::Physical);
        assert_eq!(android_15.display_info, DisplayInfoAbi::State);
        assert_eq!(android_15.apply, Some(TransactionApplyAbi::TwoBools));

        let android_16 = AndroidAbiPlan::for_release(16).unwrap();
        assert_eq!(android_16.create_surface, CREATE_SURFACE_14);
        assert_eq!(android_16.display_token, DisplayTokenAbi::Physical);
        assert_eq!(android_16.display_info, DisplayInfoAbi::State);
        assert_eq!(android_16.apply, Some(TransactionApplyAbi::TwoBools));

        assert!(AndroidAbiPlan::for_release(4).is_none());
        assert!(AndroidAbiPlan::for_release(17).is_none());
        assert!(AndroidAbiPlan::for_release(u32::MAX).is_none());
    }

    #[test]
    fn metadata_constructor_uses_gui_namespace_on_android_14_through_16() {
        assert_eq!(layer_metadata_constructor_symbol(13), LAYER_METADATA_CTOR);
        assert_eq!(
            layer_metadata_constructor_symbol(14),
            GUI_LAYER_METADATA_CTOR
        );
        assert_eq!(
            layer_metadata_constructor_symbol(15),
            GUI_LAYER_METADATA_CTOR
        );
        assert_eq!(
            layer_metadata_constructor_symbol(16),
            GUI_LAYER_METADATA_CTOR
        );
    }

    #[test]
    fn skip_screenshot_encoding_matches_the_historical_create_surface_call() {
        assert_eq!(
            AndroidAbiPlan::for_release(7).unwrap().skip_screenshot,
            SkipScreenshotAbi::Unsupported
        );
        assert_eq!(
            AndroidAbiPlan::for_release(8).unwrap().skip_screenshot,
            SkipScreenshotAbi::WindowType
        );
        assert_eq!(
            AndroidAbiPlan::for_release(10).unwrap().skip_screenshot,
            SkipScreenshotAbi::LayerMetadata {
                key: 2,
                value: 441_731,
            }
        );
        assert_eq!(
            AndroidAbiPlan::for_release(12).unwrap().skip_screenshot,
            SkipScreenshotAbi::Flag(0x40)
        );
    }

    #[test]
    fn mirror_stays_unavailable_until_runtime_symbols_are_resolved() {
        for release in 5..=16 {
            assert_eq!(
                AndroidAbiPlan::for_release(release).unwrap().mirror_display,
                MirrorDisplayAbi::Unavailable
            );
        }
    }

    #[test]
    fn mirror_abi_uses_resolved_symbols_not_android_16_version_alone() {
        assert_eq!(
            MirrorDisplayAbi::select(12, true, true, true),
            MirrorDisplayAbi::Legacy
        );
        assert_eq!(
            MirrorDisplayAbi::select(16, true, false, true),
            MirrorDisplayAbi::Legacy
        );
        assert_eq!(
            MirrorDisplayAbi::select(16, false, true, true),
            MirrorDisplayAbi::WithStopAt
        );
        assert_eq!(
            MirrorDisplayAbi::select(16, true, true, true),
            MirrorDisplayAbi::Legacy
        );
        assert_eq!(
            MirrorDisplayAbi::select(16, false, false, true),
            MirrorDisplayAbi::Unavailable
        );
        assert_eq!(
            MirrorDisplayAbi::select(16, true, true, false),
            MirrorDisplayAbi::Unavailable
        );
    }

    #[test]
    fn mirror_layer_stack_symbol_keeps_android_12_and_13_prototypes_separate() {
        assert_eq!(
            MirrorLayerStackAbi::for_release(12),
            Some(MirrorLayerStackAbi::U32)
        );
        assert!(MirrorLayerStackAbi::U32.symbol().ends_with(b"EEEj\0"));
        for release in 13..=16 {
            assert_eq!(
                MirrorLayerStackAbi::for_release(release),
                Some(MirrorLayerStackAbi::UiLayerStack)
            );
            assert_eq!(
                MirrorLayerStackAbi::for_release(release).unwrap().symbol(),
                TRANSACTION_SET_LAYER_STACK
            );
        }
        for release in [11, 17] {
            assert_eq!(MirrorLayerStackAbi::for_release(release), None);
            assert_eq!(
                MirrorDisplayAbi::select(release, true, true, true),
                MirrorDisplayAbi::Unavailable
            );
        }
        assert_eq!(
            MirrorDisplayAbi::select(12, true, false, false),
            MirrorDisplayAbi::Unavailable
        );
    }

    #[test]
    fn legacy_surface_disconnect_precedes_native_release_and_is_skipped_on_newer_android() {
        let pointer = NonNull::<u8>::dangling().as_ptr().cast();
        let mut events = Vec::new();
        DisconnectLegacySurfaceBeforeNativeRelease(6, Some(pointer), |_, api| {
            events.push(("disconnect", api));
        });
        events.push(("native-release", 0));
        assert_eq!(events, [("disconnect", 1), ("native-release", 0)]);

        let mut events = Vec::new();
        DisconnectLegacySurfaceBeforeNativeRelease(7, Some(pointer), |_, api| {
            events.push(("disconnect", api));
        });
        events.push(("native-release", 0));
        assert_eq!(events, [("native-release", 0)]);
    }

    #[test]
    fn adopted_and_retained_strong_pointers_release_exactly_once_each() {
        RETAINS.store(0, Ordering::SeqCst);
        RELEASES.store(0, Ordering::SeqCst);
        RETAIN_IDENTITIES.lock().unwrap().clear();
        RELEASE_IDENTITIES.lock().unwrap().clear();
        let pointer = NonNull::<u8>::dangling().as_ptr().cast();
        let mut raw = CppStrongPointerReturn::uninitialized();
        let return_identity = raw.identity() as usize;
        unsafe { raw.write_pointer_for_foreign_return(pointer) };
        let owner =
            unsafe { OwnedStrongPointer::adopt_returned(&mut raw, record_retain, record_release) }
                .unwrap();
        assert_eq!(RETAINS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(
            RELEASE_IDENTITIES.lock().unwrap().as_slice(),
            [return_identity]
        );
        let owner_identity = RETAIN_IDENTITIES.lock().unwrap()[0];

        let retained = unsafe { owner.retain(record_retain) };
        assert_eq!(RETAINS.load(Ordering::SeqCst), 2);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
        let retained_identity = RETAIN_IDENTITIES.lock().unwrap()[1];
        drop(retained);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
        assert_eq!(RELEASE_IDENTITIES.lock().unwrap()[1], retained_identity);
        drop(owner);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 3);
        assert_eq!(RELEASE_IDENTITIES.lock().unwrap()[2], owner_identity);

        RETAINS.store(0, Ordering::SeqCst);
        RELEASES.store(0, Ordering::SeqCst);
        let mut null = CppStrongPointerReturn::uninitialized();
        unsafe { null.write_pointer_for_foreign_return(std::ptr::null_mut()) };
        assert!(unsafe {
            OwnedStrongPointer::adopt_returned(&mut null, record_retain, record_release)
        }
        .is_none());
        assert_eq!(RETAINS.load(Ordering::SeqCst), 0);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 0);

        RETAINS.store(0, Ordering::SeqCst);
        RELEASES.store(0, Ordering::SeqCst);
        RETAIN_IDENTITIES.lock().unwrap().clear();
        RELEASE_IDENTITIES.lock().unwrap().clear();
        let mut duplicate = CppStrongPointerReturn::uninitialized();
        let duplicate_return_identity = duplicate.identity() as usize;
        unsafe { duplicate.write_pointer_for_foreign_return(pointer) };
        let duplicate_owner = unsafe {
            OwnedStrongPointer::adopt_returned(&mut duplicate, record_retain, record_release)
        }
        .unwrap();
        let duplicate_owner_identity = RETAIN_IDENTITIES.lock().unwrap()[0];
        drop(duplicate_owner);
        assert_eq!(RETAINS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
        assert_eq!(
            RELEASE_IDENTITIES.lock().unwrap().as_slice(),
            [duplicate_return_identity, duplicate_owner_identity]
        );
    }

    #[test]
    fn preflight_symbol_contract_is_version_specific_and_fail_closed() {
        let android_8 = AndroidAbiPlan::for_release(8).unwrap();
        let required_8 = android_8.required_symbols(false).unwrap();
        assert!(required_8.contains(&CREATE_SURFACE_8));
        assert!(required_8.contains(&GET_BUILT_IN_DISPLAY));
        assert!(required_8.contains(&GET_DISPLAY_INFO));
        assert!(required_8.contains(&OPEN_GLOBAL_TRANSACTION));
        assert!(!required_8.contains(&TRANSACTION_SET_TRUSTED_OVERLAY));

        let android_12 = AndroidAbiPlan::for_release(12).unwrap();
        let required_12 = android_12.required_symbols(true).unwrap();
        assert!(required_12.contains(&CREATE_SURFACE_12_TO_13));
        assert!(required_12.contains(&GET_INTERNAL_DISPLAY_TOKEN));
        assert!(required_12.contains(&GET_DISPLAY_STATE));
        assert!(required_12.contains(&LAYER_METADATA_CTOR));
        assert!(required_12.contains(&b"_ZTVN7android13LayerMetadataE\0".as_slice()));
        assert!(required_12.contains(&TRANSACTION_SET_TRUSTED_OVERLAY));
        assert!(required_12.contains(&TRANSACTION_DTOR));
        assert!(!required_12.contains(&LAYER_METADATA_SET_I32));

        let android_14 = AndroidAbiPlan::for_release(14).unwrap();
        let required_14 = android_14.required_symbols(true).unwrap();
        assert!(required_14.contains(&GET_PHYSICAL_DISPLAY_IDS));
        assert!(required_14.contains(&GET_PHYSICAL_DISPLAY_TOKEN));
        assert!(required_14.contains(&CPP_OPERATOR_DELETE));
        assert!(required_14.contains(&b"_ZTVN7android3gui13LayerMetadataE\0".as_slice()));

        let android_16 = AndroidAbiPlan::for_release(16).unwrap();
        let required_16 = android_16.required_symbols(true).unwrap();
        assert!(required_16.contains(&GET_PHYSICAL_DISPLAY_IDS));
        assert!(required_16.contains(&GET_PHYSICAL_DISPLAY_TOKEN));
        assert!(required_16.contains(&TRANSACTION_VTABLE));
        assert!(!required_16.contains(&TRANSACTION_DTOR));

        assert_eq!(
            AndroidAbiPlan::for_release(7)
                .unwrap()
                .required_symbols(true),
            Err(WindowError::AbiUnavailable("skip screenshot ABI"))
        );
    }

    #[test]
    fn placement_owner_teardown_is_balanced_and_precedes_library_close() {
        TEARDOWN_EVENTS.lock().unwrap().clear();
        let client_storage = Box::into_raw(Box::new(SurfaceComposerClientStorage::new()));
        let mut client = Some(unsafe {
            RetainedPlacementObject::new(
                NonNull::new(client_storage).unwrap(),
                record_client_release,
                Box::new(0),
            )
        });
        let mut transaction = Some(TransactionPlacement::Direct(unsafe {
            DestroyedPlacementObject::new(
                Box::new(TransactionStorage::new()),
                record_transaction_dtor,
            )
        }));

        drop_placement_owners(&mut transaction, &mut client);
        TEARDOWN_EVENTS.lock().unwrap().push("dlclose");

        assert_eq!(
            TEARDOWN_EVENTS.lock().unwrap().as_slice(),
            ["transaction_dtor", "client_dec_strong", "dlclose"]
        );
    }

    #[test]
    fn metadata_destructor_runs_once_on_success_and_early_return() {
        fn simulate_create_surface(fail: bool) -> Result<(), WindowError> {
            let virtual_functions = [record_metadata_dtor as *const c_void];
            let mut storage = Box::new(LayerMetadataStorage::new());
            unsafe {
                storage
                    .pointer()
                    .cast::<*const *const c_void>()
                    .write(virtual_functions.as_ptr());
            }
            let metadata = unsafe { VirtualDestroyedPlacementObject::new(storage) };
            if fail {
                return Err(WindowError::Backend(
                    "simulated createSurface failure".into(),
                ));
            }
            drop(metadata);
            Ok(())
        }

        METADATA_DTORS.store(0, Ordering::SeqCst);
        assert_eq!(simulate_create_surface(false), Ok(()));
        assert_eq!(METADATA_DTORS.load(Ordering::SeqCst), 1);

        METADATA_DTORS.store(0, Ordering::SeqCst);
        assert!(simulate_create_surface(true).is_err());
        assert_eq!(METADATA_DTORS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_window_subobject_offset_round_trips_the_surface_base() {
        let base = 0x1000usize as *mut c_void;
        let native = surface_to_native_window(base).unwrap();
        assert_eq!(native.as_ptr() as usize, 0x1010);
        assert_eq!(native_window_to_surface(native), base);
    }

    #[test]
    fn display_geometry_is_normalized_before_orientation_projection() {
        let portrait = project_display_info(2400, 1080, 0, 3.0, 60.0).unwrap();
        assert_eq!(portrait.physical_width, 1080);
        assert_eq!(portrait.physical_height, 2400);
        assert_eq!(portrait.oriented_size(), Size::new(1080, 2400));

        let landscape = project_display_info(2400, 1080, 1, 3.0, 60.0).unwrap();
        assert_eq!(landscape.physical_width, 1080);
        assert_eq!(landscape.physical_height, 2400);
        assert_eq!(landscape.oriented_size(), Size::new(2400, 1080));
    }
}
