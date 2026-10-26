use espframe::soloader::SoLoader;

#[test]
fn crate_exports_loader_type() {
    let _ = core::mem::size_of::<SoLoader>();
}
