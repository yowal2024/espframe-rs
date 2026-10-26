#![deny(unsafe_op_in_unsafe_fn)]

pub mod backtrace;
pub mod carray;
pub mod deps;
pub mod elf;
pub mod error;
mod loader;
pub mod mapping;
pub mod reloc;
pub mod runtime;
pub mod sleb128;
pub mod tls;

pub use error::{LoaderError, Result};
pub use loader::SoLoader;

pub fn deinit() {
    backtrace::deinit_backtrace_registry();
    tls::global_tls_registry().deinit();
}
