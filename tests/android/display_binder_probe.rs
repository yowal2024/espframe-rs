//! Self-contained app_process fixture for local Binder rejection and Auto routing.
#![allow(dead_code, non_snake_case)]

#[cfg(target_os = "android")]
pub use espframe::{espframe_log, xdl};
#[cfg(target_os = "android")]
pub use espframe::window::{Orientation, Size, WindowError};
#[cfg(target_os = "android")]
use ::jni as jni_api;

#[cfg(target_os = "android")]
#[path = "../../src/jni.rs"]
mod jni;

#[cfg(target_os = "android")]
#[path = "../../src/window/mirror.rs"]
mod mirror;
#[cfg(target_os = "android")]
#[path = "../../src/window/binder_display_codec.rs"]
mod binder_display_codec;
#[cfg(target_os = "android")]
#[path = "../../src/window/mirror_binder.rs"]
mod mirror_binder;

#[cfg(target_os = "android")]
#[link(name = "binder_ndk")]
extern "C" {
    fn AIBinder_fromJavaBinder(
        env: *mut jni_api::sys::JNIEnv,
        binder: jni_api::sys::jobject,
    ) -> *mut core::ffi::c_void;
}

#[cfg(target_os = "android")]
fn check_local_binder(
    env: &mut jni_api::JNIEnv<'_>,
    binder: &jni_api::objects::JObject<'_>,
) -> Result<jni_api::sys::jint, String> {
    // Keep the original Java object strongly reachable until every NDK owner
    // has dropped on this attached thread.
    let keep_alive = env.new_global_ref(binder).map_err(|error| error.to_string())?;
    let pointer = unsafe { AIBinder_fromJavaBinder(env.get_raw(), binder.as_raw()) };
    let service = unsafe { binder_ndk::unstable_api::new_spibinder(pointer.cast()) }
        .ok_or_else(|| "AIBinder_fromJavaBinder returned null".to_owned())?;
    if service.is_remote() {
        return Err("fixture unexpectedly supplied a remote Binder".to_owned());
    }
    let mut client = mirror_binder::NativeDisplayClient::default();
    let mut acquisitions = 0;
    let mut rejected = 0;
    for _ in 0..2 {
        let result = client.snapshot_with(36, || {
            acquisitions += 1;
            Ok(service.clone())
        });
        if result == Err(WindowError::AbiUnavailable("remote display Binder required")) {
            rejected += 1;
        }
    }
    let mut jni_queries = 0;
    for _ in 0..2 {
        let result = jni::with_attached_env(|current_env| {
            let remote = client.is_remote_with(|| {
                acquisitions += 1;
                Ok(service.clone())
            });
            Ok(mirror::DisplayQueryMode::Auto.query(
                || remote,
                Some(|| {
                    let same = current_env
                        .is_same_object(binder, keep_alive.as_obj())
                        .map_err(|error| WindowError::Backend(error.to_string()))?;
                    if !same {
                        return Err(WindowError::Backend("JNI object identity changed".into()));
                    }
                    jni_queries += 1;
                    Ok(Vec::new())
                }),
                Some(|| panic!("Auto sent a local object to the native Binder backend")),
            ))
        })
        .map_err(|error| format!("Auto JNI scope: {error}"))?;
        result.map_err(|error| format!("Auto query: {error}"))?;
    }
    drop(client);
    drop(service);
    drop(keep_alive);
    if acquisitions != 4 || jni_queries != 2 {
        return Err(format!("rejected local Binder was cached: acquisitions={acquisitions}"));
    }
    let mut remote_client = mirror_binder::NativeDisplayClient::default();
    let mut remote_queries = 0;
    for _ in 0..2 {
        let result = jni::with_attached_env(|_| {
            let remote = remote_client.is_remote();
            Ok(mirror::DisplayQueryMode::Auto.query(
                || remote,
                Some(|| panic!("Auto selected JNI for the remote display service")),
                Some(|| {
                    remote_queries += 1;
                    remote_client.snapshot(mirror_binder::android_sdk()?)
                }),
            ))
        })
        .map_err(|error| format!("remote Auto JNI scope: {error}"))?;
        let displays = result.map_err(|error| format!("remote Auto query: {error}"))?;
        if displays.is_empty() {
            return Err("remote display service returned no displays".into());
        }
    }
    if remote_queries != 2 {
        return Err("Auto did not use Binder for both remote queries".into());
    }
    Ok(rejected)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_DisplayBinderProbe_run(
    mut env: jni_api::JNIEnv<'_>,
    _class: jni_api::objects::JClass<'_>,
    binder: jni_api::objects::JObject<'_>,
) -> jni_api::sys::jint {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check_local_binder(&mut env, &binder))) {
        Ok(Ok(rejected)) => rejected,
        result => {
            let message = match result {
                Ok(Err(message)) => message,
                _ => "panic in local Binder fixture".to_owned(),
            };
            let _ = env.exception_clear();
            let _ = env.throw_new("java/lang/AssertionError", message);
            -1
        }
    }
}
