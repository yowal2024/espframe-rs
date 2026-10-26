# EspFrame xDL

This module is the physical integration of this repository's former
`rust/xdl-rs` implementation. `api.rs`, `elf.rs`, `xdl.rs`, and `lzma.rs` retain
that implementation and its public Rust API, now under `espframe::xdl`.
Internal crate paths were rebased to that module. The force-load API now tries
ordinary `dlopen` before the existing namespace-aware loader path, preserving
an owned linker reference on Android releases before linker namespaces.

The original xDL project is maintained by the HexHacking Team:
https://github.com/hexhacking/xDL

Its upstream MIT license is reproduced in `LICENSE.xDL`. That notice records
xDL attribution; it does not relicense the rest of EspFrame. The prior Rust
crate contained no separate license file or package license declaration.

The XZ/LZMA bridge continues to resolve Android's system `liblzma.so` unpacker
at runtime. No decoder implementation is copied or linked into this module.
