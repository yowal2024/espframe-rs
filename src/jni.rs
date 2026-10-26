//! Optional JNI class resolution, value conversion, and native registration.

#[path = "jni/values.rs"]
pub mod values;

use jni::objects::{JClass, JValue};
use jni::sys::{self, jint};
use jni::{JNIEnv, JavaVM, NativeMethod};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Mutex;

pub const JNI_VERSION: jint = sys::JNI_VERSION_1_4;

static REGISTERED_VM: AtomicPtr<sys::JavaVM> = AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn with_attached_env<T>(
    action: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>,
) -> jni::errors::Result<T> {
    let pointer = REGISTERED_VM.load(Ordering::Acquire);
    #[cfg(all(target_os = "android", feature = "xdl"))]
    let pointer = if pointer.is_null() {
        let found = current_process_vm()?;
        if !found.is_null() {
            REGISTERED_VM.store(found, Ordering::Release);
        }
        found
    } else {
        pointer
    };
    if pointer.is_null() {
        return Err(jni::errors::Error::NullPtr("registered JavaVM"));
    }
    let vm = unsafe { JavaVM::from_raw(pointer)? };
    let mut env = vm.attach_current_thread()?;
    let result = action(&mut env);
    if result.is_err() {
        values::clear_exception(&mut env);
    }
    result
}

#[cfg(all(target_os = "android", feature = "xdl"))]
fn current_process_vm() -> jni::errors::Result<*mut sys::JavaVM> {
    use crate::xdl::{xdl_close, xdl_iterate_phdr, xdl_open2, xdl_sym, XDL_DEFAULT};
    let mut discovery_error = None;
    for library in [c"libnativehelper.so", c"libart.so", c"libartd.so"] {
        let mut found = None;
        xdl_iterate_phdr(XDL_DEFAULT, |snapshot| {
            if snapshot.pathname().to_bytes().rsplit(|byte| *byte == b'/').next()
                == Some(library.to_bytes())
            {
                found = Some(xdl_open2(snapshot));
                1
            } else {
                0
            }
        })
        .map_err(|_| jni::errors::Error::NullPtr("JavaVM library enumeration"))?;
        // Keep a matched module's parse error distinct from an absent runtime.
        let Some(handle) = found
            .transpose()
            .map_err(|_| jni::errors::Error::NullPtr("JavaVM library metadata"))?
        else {
            continue;
        };
        let mut vm = std::ptr::null_mut();
        let mut count = 0;
        let result = unsafe {
            xdl_sym(&handle, c"JNI_GetCreatedJavaVMs")
                .map_err(|_| jni::errors::Error::NullPtr("JNI_GetCreatedJavaVMs symbol"))
                .and_then(|symbol| {
                    let get: unsafe extern "system" fn(
                        *mut *mut sys::JavaVM,
                        sys::jsize,
                        *mut sys::jsize,
                    ) -> jint = std::mem::transmute(symbol.address as *const ());
                    validate_created_vm(get(&mut vm, 1, &mut count), count, vm)
                })
        };
        if let Some(linker) = xdl_close(handle) {
            unsafe { linker.close() };
        }
        match result {
            Ok(vm) => return Ok(vm),
            Err(error) => discovery_error = Some(error),
        }
    }
    match discovery_error {
        Some(error) => Err(error),
        None => Ok(std::ptr::null_mut()),
    }
}

#[cfg(any(test, all(target_os = "android", feature = "xdl")))]
fn validate_created_vm(
    status: jint,
    count: sys::jsize,
    vm: *mut sys::JavaVM,
) -> jni::errors::Result<*mut sys::JavaVM> {
    match (status, count, vm.is_null()) {
        (sys::JNI_OK, 0, true) => Ok(std::ptr::null_mut()),
        (sys::JNI_OK, 1, false) => Ok(vm),
        _ => Err(jni::errors::Error::NullPtr("invalid JNI_GetCreatedJavaVMs result")),
    }
}

pub trait JniClassResolver {
    type Class;
    type Thread;
    type Loader;
    type Error;

    fn find_class(&mut self, name: &str) -> Result<Option<Self::Class>, Self::Error>;
    fn missing(&mut self, what: &'static str) -> Self::Error;
    fn clear_exception(&mut self);
    fn current_thread(&mut self, thread_class: &Self::Class) -> Result<Self::Thread, Self::Error>;
    fn context_loader(
        &mut self,
        thread: &Self::Thread,
    ) -> Result<Option<Self::Loader>, Self::Error>;
    fn load_class(
        &mut self,
        loader: &Self::Loader,
        name: &str,
    ) -> Result<Option<Self::Class>, Self::Error>;
}

pub fn resolve_app_class<R: JniClassResolver>(
    resolver: &mut R,
    binary_name: &str,
) -> Result<R::Class, R::Error> {
    if let Some(class) = resolver.find_class(binary_name)? {
        return Ok(class);
    }
    resolver.clear_exception();
    let thread_class = resolver
        .find_class("java/lang/Thread")?
        .ok_or_else(|| resolver.missing("Thread class"))?;
    let thread = resolver.current_thread(&thread_class)?;
    let loader = resolver
        .context_loader(&thread)?
        .ok_or_else(|| resolver.missing("context class loader"))?;
    resolver
        .load_class(&loader, &binary_name.replace('/', "."))?
        .ok_or_else(|| resolver.missing("loaded application class"))
}

struct EnvClassResolver<'a, 'local> {
    env: &'a mut JNIEnv<'local>,
}

impl<'a, 'local> JniClassResolver for EnvClassResolver<'a, 'local> {
    type Class = JClass<'local>;
    type Thread = jni::objects::JObject<'local>;
    type Loader = jni::objects::JObject<'local>;
    type Error = jni::errors::Error;

    fn find_class(&mut self, name: &str) -> Result<Option<Self::Class>, Self::Error> {
        match self.env.find_class(name) {
            Ok(class) => Ok(Some(class)),
            Err(_) => Ok(None),
        }
    }

    fn clear_exception(&mut self) {
        let _ = self.env.exception_clear();
    }

    fn missing(&mut self, what: &'static str) -> Self::Error {
        jni::errors::Error::NullPtr(what)
    }

    fn current_thread(&mut self, thread_class: &Self::Class) -> Result<Self::Thread, Self::Error> {
        self.env
            .call_static_method(thread_class, "currentThread", "()Ljava/lang/Thread;", &[])?
            .l()
    }

    fn context_loader(
        &mut self,
        thread: &Self::Thread,
    ) -> Result<Option<Self::Loader>, Self::Error> {
        let loader = self
            .env
            .call_method(
                thread,
                "getContextClassLoader",
                "()Ljava/lang/ClassLoader;",
                &[],
            )?
            .l()?;
        Ok((!loader.is_null()).then_some(loader))
    }

    fn load_class(
        &mut self,
        loader: &Self::Loader,
        name: &str,
    ) -> Result<Option<Self::Class>, Self::Error> {
        let name = self.env.new_string(name)?;
        let class = self
            .env
            .call_method(
                loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(name.as_ref())],
            )?
            .l()?;
        Ok((!class.is_null()).then_some(JClass::from(class)))
    }
}

/// Registration cache for exactly one VM, application class, and native table.
///
/// Use a separate instance for each binding. After success, subsequent calls
/// return the JNI version without resolving the class or registering again.
/// Failed or panicking attempts can be retried.
#[derive(Default)]
pub struct NativeRegistration {
    registered: AtomicBool,
    guard: Mutex<()>,
}

impl NativeRegistration {
    pub const fn new() -> Self {
        Self {
            registered: AtomicBool::new(false),
            guard: Mutex::new(()),
        }
    }

    /// Resolve an application class and register its native method table.
    ///
    /// # Safety
    /// `vm` must be null or a live JVM pointer, and the current thread must be
    /// attached to that JVM. Every method pointer must have the ABI and signature
    /// specified by its descriptor and remain valid while the JVM may invoke it.
    /// All calls on this instance must refer to the same VM, class, and table.
    pub unsafe fn register(
        &self,
        vm: *mut sys::JavaVM,
        binary_name: &str,
        methods: &[NativeMethod],
    ) -> jni::errors::Result<jint> {
        if vm.is_null() {
            return Err(jni::errors::Error::NullPtr("JavaVM"));
        }
        let result = self.register_with(|| {
            let jvm = unsafe { JavaVM::from_raw(vm)? };
            let mut env = jvm.get_env()?;
            let result = (|| {
                let mut resolver = EnvClassResolver { env: &mut env };
                let class = resolve_app_class(&mut resolver, binary_name)?;
                resolver.env.register_native_methods(class, methods)?;
                Ok(JNI_VERSION)
            })();
            if result.is_err() {
                values::clear_exception(&mut env);
            }
            result
        });
        if result.is_ok() {
            REGISTERED_VM.store(vm, Ordering::Release);
        }
        result
    }

    fn register_with(
        &self,
        register: impl FnOnce() -> jni::errors::Result<jint>,
    ) -> jni::errors::Result<jint> {
        match catch_unwind(AssertUnwindSafe(|| {
            if self.registered.load(Ordering::Acquire) {
                return Ok(JNI_VERSION);
            }
            let _guard = self
                .guard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.registered.load(Ordering::Acquire) {
                return Ok(JNI_VERSION);
            }
            register()?;
            self.registered.store(true, Ordering::Release);
            Ok(JNI_VERSION)
        })) {
            Ok(result) => result,
            Err(_) => Err(jni::errors::Error::NullPtr("panic in JNI registration")),
        }
    }
}

#[cfg(test)]
mod tests;
