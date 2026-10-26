#![cfg_attr(
    not(any(feature = "jni", feature = "binder")),
    allow(dead_code, unused_imports)
)]

use super::*;
use crate::window::mirror::{
    mirror_layout, snapshot_changed, DisplayQueryMode, DisplaySnapshot, MirrorTransform,
};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

// Preserve main's working mirror-root layer type; this is not the container bit.
const MAIN_MIRROR_ROOT_FLAGS: u32 = 0x0000_4000;

struct MirrorOwner {
    mirror: OwnedStrongPointer,
    root: OwnedStrongPointer,
    source: usize,
    source_size: Size,
    display: DisplaySnapshot,
}

#[derive(Default)]
pub(super) struct MirrorState {
    query_mode: DisplayQueryMode,
    #[cfg(feature = "binder")]
    binder: crate::window::mirror_binder::NativeDisplayClient,
    mirrors: BTreeMap<(usize, u32), MirrorOwner>,
    last_check: Option<Instant>,
    snapshot: Vec<DisplaySnapshot>,
    source_stack: Option<u32>,
    dirty: bool,
}

impl MirrorState {
    pub(super) fn mark_sources_changed(&mut self) {
        self.dirty = true;
        self.last_check = None;
    }
}

impl AndroidSurfaceComposerBackend {
    /// Auto uses JNI for a local display service and Binder for a remote service.
    /// Explicit modes require their Cargo feature and never fall back to another backend.
    pub fn SetDisplayQueryMode(&mut self, mode: DisplayQueryMode) -> Result<(), WindowError> {
        match mode {
            DisplayQueryMode::Jni if !cfg!(feature = "jni") => {
                return Err(WindowError::AbiUnavailable("JNI display backend"));
            }
            DisplayQueryMode::Binder if !cfg!(feature = "binder") => {
                return Err(WindowError::AbiUnavailable("Binder display backend"));
            }
            _ => {}
        }
        if self.mirror_state.query_mode != mode {
            self.mirror_state.query_mode = mode;
            self.mirror_state.mark_sources_changed();
            crate::espframe_log!("surface.mirror.query_mode", "mode={:?}", mode);
        }
        Ok(())
    }

    pub fn DisplayQueryMode(&self) -> DisplayQueryMode {
        self.mirror_state.query_mode
    }

    fn mirror_transaction(&self) -> Result<TransactionPlacement, WindowError> {
        let mut storage = Box::new(TransactionStorage::new());
        unsafe {
            let ctor: unsafe extern "C" fn(*mut c_void) =
                function(self.symbols.get(TRANSACTION_CTOR));
            ctor(storage.pointer());
            match self.plan.transaction_destroy {
                Some(TransactionDestroyAbi::Direct) => {
                    Ok(TransactionPlacement::Direct(DestroyedPlacementObject::new(
                        storage,
                        function(self.symbols.get(TRANSACTION_DTOR)),
                    )))
                }
                Some(TransactionDestroyAbi::Virtual) => Ok(TransactionPlacement::Virtual(
                    VirtualDestroyedPlacementObject::new(storage),
                )),
                None => Err(WindowError::AbiUnavailable("mirror transaction")),
            }
        }
    }

    fn mirror_apply(&self, transaction: *mut c_void) -> Result<(), WindowError> {
        let abi = self
            .plan
            .apply
            .ok_or(WindowError::AbiUnavailable("mirror Transaction::apply"))?;
        let symbol = match abi {
            TransactionApplyAbi::OneBool => TRANSACTION_APPLY_ONE_BOOL,
            TransactionApplyAbi::TwoBools => TRANSACTION_APPLY_TWO_BOOLS,
        };
        status_result(
            unsafe { mirror_abi::invoke_apply(abi, self.symbols.get(symbol), transaction)? },
            "mirror Transaction::apply",
        )
    }

    fn configure_mirror(
        &self,
        owner: &MirrorOwner,
        transform: MirrorTransform,
    ) -> Result<(), WindowError> {
        let mut transaction = self.mirror_transaction()?;
        let tx = transaction.pointer();
        let mirror = owner.mirror.raw();
        let root = owner.root.raw();
        let stack_abi = MirrorLayerStackAbi::for_release(self.plan.release).ok_or(
            WindowError::AbiUnavailable("mirror Transaction::setLayerStack"),
        )?;
        unsafe {
            let set_layer: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                i32,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_SET_LAYER));
            let reparent: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                *const CppStrongPointerRef,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_REPARENT));
            let matrix: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                f32,
                f32,
                f32,
                f32,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_SET_MATRIX));
            let position: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                f32,
                f32,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_SET_POSITION));
            let show: unsafe extern "C" fn(*mut c_void, *const CppStrongPointerRef) -> *mut c_void =
                function(self.symbols.get(TRANSACTION_SHOW));
            set_layer(tx, &root, i32::MAX);
            mirror_abi::invoke_set_layer_stack(
                stack_abi,
                self.symbols.get(stack_abi.symbol()),
                tx,
                &root,
                owner.display.layer_stack,
            )?;
            mirror_abi::invoke_set_layer_stack(
                stack_abi,
                self.symbols.get(stack_abi.symbol()),
                tx,
                &mirror,
                owner.display.layer_stack,
            )?;
            reparent(tx, &mirror, &root);
            matrix(tx, &mirror, transform.scale, 0.0, 0.0, transform.scale);
            position(tx, &mirror, transform.x, transform.y);
            show(tx, &mirror);
            show(tx, &root);
        }
        self.mirror_apply(tx)
    }

    fn detach_mirror(&self, owner: &MirrorOwner) -> Result<(), WindowError> {
        let mut transaction = self.mirror_transaction()?;
        let tx = transaction.pointer();
        let null = CppStrongPointerRef::new(std::ptr::null_mut());
        unsafe {
            let hide: unsafe extern "C" fn(*mut c_void, *const CppStrongPointerRef) -> *mut c_void =
                function(self.symbols.get(TRANSACTION_HIDE));
            let reparent: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                *const CppStrongPointerRef,
            ) -> *mut c_void = function(self.symbols.get(TRANSACTION_REPARENT));
            for control in [owner.mirror.raw(), owner.root.raw()] {
                hide(tx, &control);
                reparent(tx, &control, &null);
            }
        }
        self.mirror_apply(tx)
    }

    fn create_mirror(
        &mut self,
        source: usize,
        source_size: Size,
        display: &DisplaySnapshot,
    ) -> Result<MirrorOwner, WindowError> {
        let transform = mirror_layout(source_size, display)?;
        let name = std::ffi::CString::new(format!("MirrorRoot@{}:{source:x}", display.layer_stack))
            .unwrap();
        let root = self.create_control(&name, source_size, MAIN_MIRROR_ROOT_FLAGS, false)?;
        let symbol = match self.plan.mirror_display {
            MirrorDisplayAbi::Legacy => MIRROR_SURFACE,
            MirrorDisplayAbi::WithStopAt => MIRROR_SURFACE_WITH_STOP_AT,
            MirrorDisplayAbi::Unavailable => {
                return Err(WindowError::AbiUnavailable("mirrorSurface"))
            }
        };
        let client = self.client_ptr();
        let mut returned = unsafe {
            mirror_abi::invoke_mirror(
                self.plan.mirror_display,
                self.symbols.get(symbol),
                client,
                source as *mut c_void,
            )?
        };
        let mirror = unsafe { self.adopt_returned(&mut returned) }
            .ok_or_else(|| WindowError::Backend("mirrorSurface returned null".into()))?;
        let owner = MirrorOwner {
            mirror,
            root,
            source,
            source_size,
            display: display.clone(),
        };
        if let Err(error) = self.configure_mirror(&owner, transform) {
            let _ = self.detach_mirror(&owner);
            return Err(error);
        }
        crate::espframe_log!(
            "surface.mirror.created",
            "stack={} source={:#x}",
            display.layer_stack,
            source
        );
        Ok(owner)
    }

    pub(super) fn clear_source_mirrors(&mut self, source: usize) {
        let keys: Vec<_> = self
            .mirror_state
            .mirrors
            .iter()
            .filter(|(_, owner)| owner.source == source)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            if let Some(owner) = self.mirror_state.mirrors.remove(&key) {
                if let Err(error) = self.detach_mirror(&owner) {
                    crate::espframe_log!("surface.mirror.detach_error", "error={}", error);
                }
            }
        }
        self.mirror_state.mark_sources_changed();
    }

    pub(super) fn stop_mirrors(&mut self) {
        let mirrors = std::mem::take(&mut self.mirror_state.mirrors);
        for (_, owner) in mirrors {
            if let Err(error) = self.detach_mirror(&owner) {
                crate::espframe_log!("surface.mirror.detach_error", "error={}", error);
            }
        }
    }

    #[cfg(not(any(feature = "jni", feature = "binder")))]
    pub(super) fn refresh_mirrors(&mut self) -> Result<(), WindowError> {
        Err(WindowError::AbiUnavailable("display enumeration backend"))
    }

    #[cfg(any(feature = "jni", feature = "binder"))]
    pub(super) fn refresh_mirrors(&mut self) -> Result<(), WindowError> {
        if self.plan.mirror_display == MirrorDisplayAbi::Unavailable {
            return Err(WindowError::AbiUnavailable("mirrorSurface"));
        }
        if self
            .mirror_state
            .last_check
            .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return Ok(());
        }
        self.mirror_state.last_check = Some(Instant::now());
        let displays = self.mirror_display_snapshot()?;
        if displays != self.mirror_state.snapshot {
            self.display_token.take();
            self.GetDisplayInfo()?;
            self.mirror_state.dirty = true;
        }
        let source_stack = self
            .source_layer_stack
            .get()
            .ok_or(WindowError::AbiUnavailable("primary display layer stack"))?;
        self.mirror_state.dirty |= snapshot_changed(
            &self.mirror_state.snapshot,
            &displays,
            self.mirror_state.source_stack,
            source_stack,
        );
        if !self.mirror_state.dirty {
            return Ok(());
        }
        let sources: Vec<_> = self
            .surfaces
            .iter()
            .filter(|(_, surface)| !surface.skip_screenshot)
            .map(|(key, surface)| (*key, surface.size))
            .collect();
        let mut desired = BTreeMap::new();
        for display in &displays {
            if display.layer_stack == source_stack {
                continue;
            }
            for &(source, size) in &sources {
                desired.insert((source, display.layer_stack), (size, display.clone()));
            }
        }
        let removed: Vec<_> = self
            .mirror_state
            .mirrors
            .keys()
            .filter(|key| !desired.contains_key(key))
            .copied()
            .collect();
        for key in removed {
            let owner = self.mirror_state.mirrors.get(&key).unwrap();
            self.detach_mirror(owner)?;
            self.mirror_state.mirrors.remove(&key);
        }
        for ((source, stack), (size, display)) in desired {
            let key = (source, stack);
            if let Some(owner) = self.mirror_state.mirrors.get(&key) {
                if owner.source_size != size || owner.display != display {
                    let transform = mirror_layout(size, &display)?;
                    self.configure_mirror(owner, transform)?;
                    let owner = self.mirror_state.mirrors.get_mut(&key).unwrap();
                    owner.source_size = size;
                    owner.display = display;
                }
            } else {
                let owner = self.create_mirror(source, size, &display)?;
                self.mirror_state.mirrors.insert(key, owner);
            }
        }
        self.mirror_state.snapshot = displays;
        self.mirror_state.source_stack = Some(source_stack);
        self.mirror_state.dirty = false;
        Ok(())
    }

    #[cfg(any(feature = "jni", feature = "binder"))]
    fn mirror_display_snapshot(&mut self) -> Result<Vec<DisplaySnapshot>, WindowError> {
        #[cfg(all(feature = "jni", feature = "binder"))]
        if self.mirror_state.query_mode == DisplayQueryMode::Auto {
            // Releasing a local Java Binder may enter Java too. Keep the probe,
            // dispatch, and local reference release inside the existing JNI scope.
            return match crate::jni::with_attached_env(|_| {
                Ok(self.mirror_display_snapshot_scoped(true))
            }) {
                Ok(result) => result,
                Err(jni::errors::Error::NullPtr("registered JavaVM")) => {
                    self.mirror_display_snapshot_scoped(false)
                }
                Err(error) => Err(WindowError::Backend(format!("display Auto JNI context: {error}"))),
            };
        }
        self.mirror_display_snapshot_scoped(true)
    }

    #[cfg(any(feature = "jni", feature = "binder"))]
    fn mirror_display_snapshot_scoped(
        &mut self,
        _jni_available: bool,
    ) -> Result<Vec<DisplaySnapshot>, WindowError> {
        #[cfg(feature = "binder")]
        let remote = if self.mirror_state.query_mode == DisplayQueryMode::Auto {
            self.mirror_state.binder.is_remote()
        } else {
            Ok(false)
        };
        #[cfg(not(feature = "binder"))]
        let remote = Err(WindowError::AbiUnavailable("Binder display backend"));
        #[cfg(feature = "jni")]
        let jni = _jni_available.then_some(crate::window::mirror_jni::display_snapshot);
        #[cfg(not(feature = "jni"))]
        let jni: Option<fn() -> Result<Vec<DisplaySnapshot>, WindowError>> = None;
        #[cfg(feature = "binder")]
        let binder = Some(|| {
            self.mirror_state
                .binder
                .snapshot(crate::window::mirror_binder::android_sdk()?)
        });
        #[cfg(not(feature = "binder"))]
        let binder: Option<fn() -> Result<Vec<DisplaySnapshot>, WindowError>> = None;
        self.mirror_state.query_mode.query(|| remote, jni, binder)
    }
}
