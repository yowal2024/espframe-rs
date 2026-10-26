#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use super::mirror::{normalize_displays, DisplaySnapshot};
use super::WindowError;
use jni::objects::{JIntArray, JValue};

pub(super) fn display_snapshot() -> Result<Vec<DisplaySnapshot>, WindowError> {
    let raw = crate::jni::with_attached_env(|env| {
        env.with_local_frame(16, |env| {
            let manager = env
                .call_static_method(
                    "android/hardware/display/DisplayManagerGlobal",
                    "getInstance",
                    "()Landroid/hardware/display/DisplayManagerGlobal;",
                    &[],
                )?
                .l()?;
            if manager.is_null() {
                return Err(jni::errors::Error::NullPtr("DisplayManagerGlobal"));
            }
            let internal_class =
                env.find_class("android/hardware/display/DisplayManagerInternal")?;
            let internal = env
                .call_static_method(
                    "com/android/server/LocalServices",
                    "getService",
                    "(Ljava/lang/Class;)Ljava/lang/Object;",
                    &[JValue::Object(internal_class.as_ref())],
                )?
                .l()?;
            if internal.is_null() {
                return Err(jni::errors::Error::NullPtr("DisplayManagerInternal"));
            }
            let ids = match env.call_method(&manager, "getDisplayIds", "()[I", &[]) {
                Ok(value) => value.l()?,
                Err(_) => {
                    crate::jni::values::clear_exception(env);
                    env.call_method(&manager, "getDisplayIds", "(Z)[I", &[JValue::Bool(0)])?
                        .l()?
                }
            };
            let ids = JIntArray::from(ids);
            let count = env.get_array_length(&ids)?;
            if !(0..=256).contains(&count) {
                return Err(jni::errors::Error::NullPtr("invalid display count"));
            }
            let mut values = vec![0; count as usize];
            env.get_int_array_region(&ids, 0, &mut values)?;
            let mut displays = Vec::with_capacity(values.len());
            for id in values {
                let raw = env.with_local_frame(16, |env| -> jni::errors::Result<_> {
                    let info = env
                        .call_method(
                            &internal,
                            "getDisplayInfo",
                            "(I)Landroid/view/DisplayInfo;",
                            &[JValue::Int(id)],
                        )?
                        .l()?;
                    if info.is_null() {
                        return Err(jni::errors::Error::NullPtr(
                            "display changed during enumeration",
                        ));
                    }
                    let stack = env.get_field(&info, "layerStack", "I")?.i()?;
                    let width = env.get_field(&info, "logicalWidth", "I")?.i()?;
                    let height = env.get_field(&info, "logicalHeight", "I")?.i()?;
                    let rotation = env.get_field(&info, "rotation", "I")?.i()?;
                    Ok((id, stack, width, height, rotation))
                })?;
                displays.push(raw);
            }
            Ok(displays)
        })
    })
    .map_err(|error| WindowError::Backend(format!("JNI display snapshot failed: {error}")))?;
    normalize_displays(
        raw.into_iter()
            .filter(|(_, stack, _, _, _)| *stack != -1)
            .map(|(id, stack, w, h, rotation)| {
                DisplaySnapshot::from_java(id, stack, w, h, rotation)
            })
            .collect::<Result<_, _>>()?,
    )
}
