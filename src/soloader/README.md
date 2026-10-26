# soloader provenance

This module was ported from the local `rust/csoloader-rs` crate, package
`csoloader-rs` version `0.1.0`, library name `csoloader`, Rust edition `2021`.
The original `Cargo.toml` declares `license = "AGPL-3.0-only"`.
These source files and the associated `espframe/tests/soloader` tests retain
that license designation; moving them into EspFrame does not relicense them.
The original crate contained no separate license file or additional source
copyright/license notices.

The implementation is preserved, with `lib.rs` renamed to `mod.rs`, internal
`crate::` paths rebased to `crate::soloader::`, and `CsoLoader` renamed to
`SoLoader` without a compatibility alias. Integration tests use
`espframe::soloader::` in place of `csoloader::`. No loader behavior is changed.

Enable EspFrame's `soloader` Cargo feature to expose the module. The original
dependencies were `libc = "0.2"`, `goblin = "0.10.7"`, and `thiserror = "2"`.
