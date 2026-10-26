use espframe::soloader::tls::{global_tls_registry, TlsIndex, TlsRegistry};

#[test]
fn tls_registry_copies_initial_image_into_thread_local_block() {
    let registry = TlsRegistry::new();
    let module = registry.register_module(&[0x11, 0x22], 8, 4).unwrap();

    let ptr = registry.get_addr(TlsIndex { module, offset: 1 }).unwrap();

    unsafe {
        assert_eq!(*(ptr as *const u8), 0x22);
        *ptr = 0x99;
    }

    let ptr_again = registry.get_addr(TlsIndex { module, offset: 1 }).unwrap();
    unsafe {
        assert_eq!(*(ptr_again as *const u8), 0x99);
    }
}

#[test]
fn tls_registry_honors_large_module_alignment() {
    let registry = TlsRegistry::new();
    let module = registry.register_module(&[0x11], 8, 4096).unwrap();

    let ptr = registry.get_addr(TlsIndex { module, offset: 0 }).unwrap();

    assert_eq!((ptr as usize) % 4096, 0);
    unsafe {
        assert_eq!(*ptr, 0x11);
    }
}

#[test]
fn tls_registry_keeps_existing_block_when_other_module_changes() {
    let registry = TlsRegistry::new();
    let module_a = registry.register_module(&[0x11], 8, 8).unwrap();
    let ptr_a = registry
        .get_addr(TlsIndex {
            module: module_a,
            offset: 0,
        })
        .unwrap();
    unsafe {
        *ptr_a = 0x77;
    }

    let module_b = registry.register_module(&[0x22], 8, 8).unwrap();
    let _ = registry
        .get_addr(TlsIndex {
            module: module_b,
            offset: 0,
        })
        .unwrap();

    let ptr_again = registry
        .get_addr(TlsIndex {
            module: module_a,
            offset: 0,
        })
        .unwrap();
    assert_eq!(ptr_again, ptr_a);
    unsafe {
        assert_eq!(*ptr_again, 0x77);
    }
}

#[test]
fn tls_registry_rejects_unregistered_module_after_unregister() {
    let registry = TlsRegistry::new();
    let module = registry.register_module(&[0x11], 4, 1).unwrap();
    registry.unregister_module(module);

    assert!(registry.get_addr(TlsIndex { module, offset: 0 }).is_none());
}

#[test]
fn crate_deinit_clears_global_tls_registry() {
    let registry = global_tls_registry();
    registry.deinit();
    let module = registry.register_module(&[0x11], 4, 1).unwrap();

    espframe::soloader::deinit();

    assert!(registry.get_addr(TlsIndex { module, offset: 0 }).is_none());
}
