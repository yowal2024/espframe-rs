use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct UiLayerStack {
    value: u32,
}

pub(super) unsafe fn invoke_apply(
    abi: TransactionApplyAbi,
    address: *mut c_void,
    transaction: *mut c_void,
) -> Result<i32, WindowError> {
    if address.is_null() || transaction.is_null() {
        return Err(WindowError::AbiUnavailable("mirror Transaction::apply"));
    }
    Ok(match abi {
        TransactionApplyAbi::OneBool => {
            let call: unsafe extern "C" fn(*mut c_void, bool) -> i32 =
                unsafe { std::mem::transmute(address) };
            unsafe { call(transaction, false) }
        }
        TransactionApplyAbi::TwoBools => {
            let call: unsafe extern "C" fn(*mut c_void, bool, bool) -> i32 =
                unsafe { std::mem::transmute(address) };
            unsafe { call(transaction, false, true) }
        }
    })
}

pub(super) unsafe fn invoke_set_layer_stack(
    abi: MirrorLayerStackAbi,
    address: *mut c_void,
    transaction: *mut c_void,
    surface: *const CppStrongPointerRef,
    value: u32,
) -> Result<*mut c_void, WindowError> {
    if address.is_null() || transaction.is_null() || surface.is_null() {
        return Err(WindowError::AbiUnavailable(
            "mirror Transaction::setLayerStack",
        ));
    }
    Ok(match abi {
        MirrorLayerStackAbi::U32 => {
            let call: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                u32,
            ) -> *mut c_void = unsafe { std::mem::transmute(address) };
            unsafe { call(transaction, surface, value) }
        }
        MirrorLayerStackAbi::UiLayerStack => {
            let call: unsafe extern "C" fn(
                *mut c_void,
                *const CppStrongPointerRef,
                UiLayerStack,
            ) -> *mut c_void = unsafe { std::mem::transmute(address) };
            unsafe { call(transaction, surface, UiLayerStack { value }) }
        }
    })
}

pub(super) unsafe fn invoke_mirror(
    abi: MirrorDisplayAbi,
    address: *mut c_void,
    client: *mut c_void,
    source: *mut c_void,
) -> Result<CppStrongPointerReturn, WindowError> {
    if address.is_null() || client.is_null() || source.is_null() {
        return Err(WindowError::AbiUnavailable("mirrorSurface arguments"));
    }
    match abi {
        MirrorDisplayAbi::Legacy => {
            let call: unsafe extern "C" fn(*mut c_void, *mut c_void) -> CppStrongPointerReturn =
                unsafe { std::mem::transmute(address) };
            Ok(unsafe { call(client, source) })
        }
        MirrorDisplayAbi::WithStopAt => {
            let call: unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> CppStrongPointerReturn = unsafe { std::mem::transmute(address) };
            Ok(unsafe { call(client, source, std::ptr::null_mut()) })
        }
        MirrorDisplayAbi::Unavailable => Err(WindowError::AbiUnavailable("mirrorSurface")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ARGUMENTS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static APPLY_ARGUMENTS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static STACK_ARGUMENTS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn apply_one(transaction: *mut c_void, synchronous: bool) -> i32 {
        *APPLY_ARGUMENTS.lock().unwrap() = vec![transaction as usize, synchronous as usize];
        -7
    }

    unsafe extern "C" fn apply_two(
        transaction: *mut c_void,
        synchronous: bool,
        one_way: bool,
    ) -> i32 {
        *APPLY_ARGUMENTS.lock().unwrap() =
            vec![transaction as usize, synchronous as usize, one_way as usize];
        0
    }

    unsafe extern "C" fn stack_u32(
        transaction: *mut c_void,
        surface: *const CppStrongPointerRef,
        value: u32,
    ) -> *mut c_void {
        *STACK_ARGUMENTS.lock().unwrap() =
            vec![transaction as usize, surface as usize, value as usize];
        transaction
    }

    unsafe extern "C" fn stack_ui(
        transaction: *mut c_void,
        surface: *const CppStrongPointerRef,
        value: UiLayerStack,
    ) -> *mut c_void {
        *STACK_ARGUMENTS.lock().unwrap() =
            vec![transaction as usize, surface as usize, value.value as usize];
        transaction
    }

    #[test]
    fn typed_mirror_apply_uses_one_bool_on_android_12_and_two_on_android_13() {
        let tx = 0x3000usize as *mut c_void;
        unsafe {
            assert_eq!(
                invoke_apply(TransactionApplyAbi::OneBool, apply_one as *mut c_void, tx).unwrap(),
                -7
            );
            assert_eq!(*APPLY_ARGUMENTS.lock().unwrap(), [0x3000, 0]);
            assert_eq!(
                invoke_apply(TransactionApplyAbi::TwoBools, apply_two as *mut c_void, tx).unwrap(),
                0
            );
            assert_eq!(*APPLY_ARGUMENTS.lock().unwrap(), [0x3000, 0, 1]);
            assert!(invoke_apply(TransactionApplyAbi::OneBool, std::ptr::null_mut(), tx).is_err());
        }
    }

    #[test]
    fn typed_mirror_layer_stack_preserves_u32_bits_and_passes_the_sp_address() {
        let tx = 0x3000usize as *mut c_void;
        let surface = CppStrongPointerRef::new(0x4000usize as *mut c_void);
        for (abi, callback) in [
            (MirrorLayerStackAbi::U32, stack_u32 as *mut c_void),
            (MirrorLayerStackAbi::UiLayerStack, stack_ui as *mut c_void),
        ] {
            unsafe {
                assert_eq!(
                    invoke_set_layer_stack(abi, callback, tx, &surface, 0xF000_0001).unwrap(),
                    tx
                );
                assert_eq!(
                    *STACK_ARGUMENTS.lock().unwrap(),
                    [0x3000, &surface as *const _ as usize, 0xF000_0001]
                );
                assert!(
                    invoke_set_layer_stack(abi, std::ptr::null_mut(), tx, &surface, 1).is_err()
                );
            }
        }
    }

    unsafe extern "C" fn legacy(
        client: *mut c_void,
        source: *mut c_void,
    ) -> CppStrongPointerReturn {
        *ARGUMENTS.lock().unwrap() = vec![client as usize, source as usize];
        let mut value = CppStrongPointerReturn::uninitialized();
        value.pointer.write(source);
        value
    }

    unsafe extern "C" fn with_stop_at(
        client: *mut c_void,
        source: *mut c_void,
        stop_at: *mut c_void,
    ) -> CppStrongPointerReturn {
        *ARGUMENTS.lock().unwrap() = vec![client as usize, source as usize, stop_at as usize];
        let mut value = CppStrongPointerReturn::uninitialized();
        value.pointer.write(source);
        value
    }

    #[test]
    fn typed_mirror_call_passes_this_and_raw_source_with_null_stop_at() {
        let client = 0x1000usize as *mut c_void;
        let source = 0x2000usize as *mut c_void;
        unsafe {
            let result = invoke_mirror(
                MirrorDisplayAbi::Legacy,
                legacy as *mut c_void,
                client,
                source,
            )
            .unwrap();
            assert_eq!(result.pointer(), source);
            assert_eq!(*ARGUMENTS.lock().unwrap(), [0x1000, 0x2000]);
            let result = invoke_mirror(
                MirrorDisplayAbi::WithStopAt,
                with_stop_at as *mut c_void,
                client,
                source,
            )
            .unwrap();
            assert_eq!(result.pointer(), source);
            assert_eq!(*ARGUMENTS.lock().unwrap(), [0x1000, 0x2000, 0]);
            assert!(invoke_mirror(
                MirrorDisplayAbi::Unavailable,
                std::ptr::null_mut(),
                client,
                source
            )
            .is_err());
        }
    }
}
