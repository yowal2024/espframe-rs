#[cfg(not(target_pointer_width = "64"))]
compile_error!("xdl-rs currently supports only 64-bit ELF targets");

mod api;
pub mod elf;
pub mod lzma;
pub mod xdl;

pub use api::{
    xdl_addr, xdl_addr4, xdl_addr_clean, xdl_close, xdl_dsym, xdl_info, xdl_iterate_phdr, xdl_open,
    xdl_open2, xdl_sym, XdlAddressCache, XdlHandle, XdlInfo, XdlLinkerHandle,
    XDL_ALWAYS_FORCE_LOAD, XDL_DEFAULT, XDL_DI_DLINFO, XDL_FULL_PATHNAME, XDL_NON_SYM,
    XDL_TRY_FORCE_LOAD,
};
pub use elf::Elf64Phdr;
pub use lzma::{xdl_lzma_decompress, xdl_lzma_decompress_bounded, LzmaError};
pub use xdl::{
    find_loaded_module, open_loaded, resolve_dynamic_symbol, DynamicSymbol, LoadedElf,
    LoadedModuleSnapshot, XdlError,
};
