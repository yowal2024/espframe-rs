use core::ffi::{c_char, c_void};
type Ptr = *mut c_void;
#[link(name = "binder_ndk")]
extern "C" {
    fn AIBinder_Class_define(
        name: *const c_char,
        create: unsafe extern "C" fn(Ptr) -> Ptr,
        destroy: unsafe extern "C" fn(Ptr),
        transact: unsafe extern "C" fn(Ptr, u32, *const c_void, Ptr) -> i32,
    ) -> Ptr;
    fn AIBinder_associateClass(binder: Ptr, class: Ptr) -> bool;
    fn AIBinder_prepareTransaction(binder: Ptr, parcel: *mut Ptr) -> i32;
    fn AParcel_writeInt32(parcel: Ptr, value: i32) -> i32;
    fn AIBinder_transact(
        binder: Ptr,
        code: u32,
        input: *mut Ptr,
        output: *mut Ptr,
        flags: u32,
    ) -> i32;
    fn AParcel_delete(parcel: Ptr);
    fn AIBinder_decStrong(binder: Ptr);
}
unsafe extern "C" fn create(_: Ptr) -> Ptr {
    core::ptr::null_mut()
}
unsafe extern "C" fn destroy(_: Ptr) {}
unsafe extern "C" fn transact(_: Ptr, _: u32, _: *const c_void, _: Ptr) -> i32 {
    -74
}
pub unsafe fn open() -> Ptr {
    let lib = libc::dlopen(
        c"libbinder_ndk.so".as_ptr(),
        libc::RTLD_NOW | libc::RTLD_LOCAL,
    );
    if lib.is_null() {
        return core::ptr::null_mut();
    }
    let lookup = libc::dlsym(lib, c"AServiceManager_checkService".as_ptr());
    let binder = if lookup.is_null() {
        core::ptr::null_mut()
    } else {
        let f: unsafe extern "C" fn(*const c_char) -> Ptr = core::mem::transmute(lookup);
        f(c"SurfaceFlinger".as_ptr())
    };
    libc::dlclose(lib);
    if binder.is_null() {
        return binder;
    }
    static CLASS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let class = *CLASS.get_or_init(|| {
        AIBinder_Class_define(
            c"android.ui.ISurfaceComposer".as_ptr(),
            create,
            destroy,
            transact,
        ) as usize
    }) as Ptr;
    if class.is_null() || !AIBinder_associateClass(binder, class) {
        AIBinder_decStrong(binder);
        return core::ptr::null_mut();
    }
    binder
}
pub unsafe fn tick(binder: Ptr) -> i32 {
    if binder.is_null() {
        return -1;
    }
    let (mut input, mut output) = (core::ptr::null_mut(), core::ptr::null_mut());
    let mut rc = AIBinder_prepareTransaction(binder, &mut input);
    if rc == 0 {
        rc = AParcel_writeInt32(input, 1);
    }
    if rc == 0 {
        rc = AIBinder_transact(binder, 1008, &mut input, &mut output, 0);
    }
    if !input.is_null() {
        AParcel_delete(input);
    }
    if !output.is_null() {
        AParcel_delete(output);
    }
    rc
}
pub unsafe fn close(binder: Ptr) {
    if !binder.is_null() {
        AIBinder_decStrong(binder);
    }
}

#[link(name = "binder_ndk")]
extern "C" {
    fn AParcel_readInt32(parcel: *const c_void, value: *mut i32) -> i32;
}
pub(super) struct Repaint {
    binder: Ptr,
    old_hwc: i32,
    changed: bool,
}
impl Repaint {
    pub(super) unsafe fn open() -> Result<Self, String> {
        let binder = open();
        if binder.is_null() {
            return Err("SurfaceFlinger Binder unavailable".into());
        }
        let (mut input, mut output) = (core::ptr::null_mut(), core::ptr::null_mut());
        let mut rc = AIBinder_prepareTransaction(binder, &mut input);
        if rc == 0 {
            rc = AIBinder_transact(binder, 1010, &mut input, &mut output, 0);
        }
        let mut words = [0i32; 5];
        if rc == 0 {
            for word in &mut words {
                rc = AParcel_readInt32(output, word);
                if rc != 0 {
                    break;
                }
            }
        }
        if !input.is_null() {
            AParcel_delete(input);
        }
        if !output.is_null() {
            AParcel_delete(output);
        }
        if rc != 0 || !matches!(words[4], 0 | 1) {
            close(binder);
            return Err("unsupported SurfaceFlinger HWC state reply".into());
        }
        Ok(Self {
            binder,
            old_hwc: words[4],
            changed: false,
        })
    }
    pub(super) fn tick(&mut self) -> Result<(), String> {
        let rc = unsafe { tick(self.binder) };
        if rc != 0 {
            return Err(format!("SurfaceFlinger repaint failed: {rc}"));
        }
        self.changed = true;
        Ok(())
    }
}
impl Drop for Repaint {
    fn drop(&mut self) {
        unsafe {
            if self.changed {
                let (mut input, mut output) = (core::ptr::null_mut(), core::ptr::null_mut());
                let mut rc = AIBinder_prepareTransaction(self.binder, &mut input);
                if rc == 0 {
                    rc = AParcel_writeInt32(input, self.old_hwc);
                }
                if rc == 0 {
                    let _ = AIBinder_transact(self.binder, 1008, &mut input, &mut output, 0);
                }
                if !input.is_null() {
                    AParcel_delete(input);
                }
                if !output.is_null() {
                    AParcel_delete(output);
                }
            }
            close(self.binder);
        }
    }
}
