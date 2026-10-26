use std::fs;

use espframe::soloader::deps::{basename, find_library_path};

#[test]
fn basename_returns_final_path_component() {
    assert_eq!(basename("/tmp/libsample.so"), "libsample.so");
    assert_eq!(basename("libsample.so"), "libsample.so");
}

#[test]
fn find_library_path_uses_first_matching_root() {
    let temp = std::env::temp_dir().join("soloader-deps-test");
    let root = temp.join("root1");
    let nested = root.join("libdemo.so");
    fs::create_dir_all(&root).unwrap();
    fs::write(&nested, b"demo").unwrap();

    let found = find_library_path("libdemo.so", std::slice::from_ref(&root)).unwrap();
    assert_eq!(found, nested);

    let _ = fs::remove_file(&nested);
    let _ = fs::remove_dir_all(&temp);
}
