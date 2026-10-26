use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(unix, test))]
use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};
#[cfg(unix)]
use std::{
    ffi::{CStr, CString},
    fs::File,
    os::fd::AsRawFd,
};

#[cfg(unix)]
use crate::soloader::backtrace;
use crate::soloader::backtrace::BacktraceHandle;
#[cfg(any(unix, test))]
use crate::soloader::deps::enqueue_needed_libraries;
#[cfg(unix)]
use crate::soloader::deps::{
    basename, find_library_path_with_source, system_library_search_roots, LibrarySearchSource,
};
use crate::soloader::elf::ElfImage;
#[cfg(unix)]
use crate::soloader::elf::SymbolInfo;
use crate::soloader::error::Result;
#[cfg(unix)]
use crate::soloader::mapping;
use crate::soloader::reloc::{RelocationApplyConfig, RelocationKinds, SymbolResolver};
#[cfg(unix)]
use crate::soloader::reloc::{SymbolResolution, TlsRelocationContext, TlsSymbolResolution};
#[cfg(unix)]
use crate::soloader::runtime::{destructor_addresses, LibraryView, RuntimeGraph};
#[cfg(unix)]
use crate::soloader::tls::{global_tls_registry, TlsIndex};

#[cfg(unix)]
const MAX_DEPS: usize = 64;

#[cfg(any(unix, test))]
#[derive(Debug, Default)]
struct LoadGroupLease {
    mappings: Vec<(usize, usize)>,
    #[cfg(unix)]
    tls_modules: Vec<usize>,
    #[cfg(unix)]
    // TLS indices are registered by address, so each allocation must remain
    // stable even when the lease vector grows.
    #[allow(clippy::vec_box)]
    tls_indices: Vec<Box<TlsIndex>>,
    #[cfg(unix)]
    backtrace_handles: Vec<BacktraceHandle>,
    #[cfg(unix)]
    abandoned: AtomicBool,
}

#[cfg(any(unix, test))]
impl LoadGroupLease {
    #[cfg(unix)]
    fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
    }

    fn contains_address(&self, address: usize) -> bool {
        self.mappings.iter().any(|&(base, size)| {
            base.checked_add(size)
                .is_some_and(|end| address >= base && address < end)
        })
    }
}

#[cfg(unix)]
impl Drop for LoadGroupLease {
    fn drop(&mut self) {
        for handle in self.backtrace_handles.drain(..).rev() {
            let _ = backtrace::unregister_backtrace_library(handle);
        }
        for module_id in self.tls_modules.drain(..).rev() {
            global_tls_registry().unregister_module(module_id);
        }
        self.tls_indices.clear();
        if !self.abandoned.load(Ordering::Acquire) {
            for (base, size) in self.mappings.drain(..).rev() {
                unsafe {
                    mapping::unmap_address_space(base as *mut libc::c_void, size);
                }
            }
        }
    }
}

#[cfg(any(unix, test))]
#[derive(Copy, Clone)]
struct ThreadAtExitFunction {
    function: unsafe extern "C" fn(*mut libc::c_void),
    argument: usize,
}

#[cfg(any(unix, test))]
struct ThreadAtExitEntry {
    callback: ThreadAtExitFunction,
    _lease: Arc<LoadGroupLease>,
}

#[cfg(any(unix, test))]
impl ThreadAtExitEntry {
    unsafe fn call(self) {
        unsafe {
            (self.callback.function)(self.callback.argument as *mut libc::c_void);
        }
    }
}

#[cfg(any(unix, test))]
#[derive(Default)]
struct ThreadAtExitStack {
    entries: Vec<ThreadAtExitEntry>,
}

#[cfg(any(unix, test))]
impl Drop for ThreadAtExitStack {
    fn drop(&mut self) {
        while let Some(entry) = self.entries.pop() {
            unsafe {
                entry.call();
            }
        }
    }
}

#[cfg(any(unix, test))]
thread_local! {
    static THREAD_ATEXIT_STACK: RefCell<ThreadAtExitStack> = RefCell::new(ThreadAtExitStack::default());
}

#[cfg(any(unix, test))]
#[derive(Default)]
struct ThreadAtExitRegistry {
    dsos: HashMap<usize, Weak<LoadGroupLease>>,
    groups: Vec<Weak<LoadGroupLease>>,
}

#[cfg(any(unix, test))]
fn thread_atexit_registry() -> &'static Mutex<ThreadAtExitRegistry> {
    static REGISTRY: OnceLock<Mutex<ThreadAtExitRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(ThreadAtExitRegistry::default()))
}

#[cfg(any(unix, test))]
fn register_thread_atexit_dso(dso_handle: *mut libc::c_void, lease: &Arc<LoadGroupLease>) {
    if dso_handle.is_null() {
        return;
    }
    thread_atexit_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .dsos
        .insert(dso_handle as usize, Arc::downgrade(lease));
}

#[cfg(any(unix, test))]
fn register_thread_atexit_group(lease: &Arc<LoadGroupLease>) {
    let mut registry = thread_atexit_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.groups.retain(|group| group.strong_count() != 0);
    registry.groups.push(Arc::downgrade(lease));
}

#[cfg(any(unix, test))]
fn thread_atexit_lease(dso_handle: *mut libc::c_void) -> Option<Arc<LoadGroupLease>> {
    if dso_handle.is_null() {
        return None;
    }
    let mut registry = thread_atexit_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lease) = registry
        .dsos
        .get(&(dso_handle as usize))
        .and_then(Weak::upgrade)
    {
        return Some(lease);
    }
    registry.dsos.remove(&(dso_handle as usize));
    let address = dso_handle as usize;
    let mut found = None;
    registry.groups.retain(|weak| {
        let Some(group) = weak.upgrade() else {
            return false;
        };
        if found.is_none() && group.contains_address(address) {
            found = Some(group);
        }
        true
    });
    found
}

#[derive(Debug, Default)]
pub struct SoLoader {
    main: Option<LoadedImage>,
    dependencies: Vec<LoadedImage>,
    state: LoaderState,
    #[cfg(any(unix, test))]
    load_group: Option<Arc<LoadGroupLease>>,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug)]
struct LoadedImage {
    image: ElfImage,
    map_size: usize,
    manual: bool,
    unmap_on_drop: bool,
    tls_module_id: Option<usize>,
    backtrace_handle: Option<BacktraceHandle>,
    // Boxed descriptors keep raw TLSDESC pointers stable when the Vec grows.
    #[allow(clippy::vec_box)]
    tls_indices: Vec<Box<crate::soloader::tls::TlsIndex>>,
}

impl Clone for LoadedImage {
    fn clone(&self) -> Self {
        Self {
            image: self.image.clone(),
            map_size: self.map_size,
            manual: self.manual,
            unmap_on_drop: false,
            tls_module_id: None,
            backtrace_handle: None,
            tls_indices: Vec::new(),
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
impl LoadedImage {
    fn new(image: ElfImage, map_size: usize, manual: bool) -> Self {
        Self {
            image,
            map_size,
            manual,
            unmap_on_drop: true,
            tls_module_id: None,
            backtrace_handle: None,
            tls_indices: Vec::new(),
        }
    }

    fn abandon_mapping(&mut self) {
        self.unmap_on_drop = false;
    }
}

#[cfg(unix)]
impl Drop for LoadedImage {
    fn drop(&mut self) {
        unsafe {
            unregister_backtrace_segment(self);
            unregister_tls_segment(self);
            if self.unmap_on_drop && self.manual && self.map_size != 0 {
                mapping::unmap_address_space(self.image.base() as *mut _, self.map_size);
            }
        }
    }
}

#[cfg(unix)]
impl LibraryView for LoadedImage {
    fn name(&self) -> &str {
        self.image.name()
    }

    fn needed_libraries(&self) -> &[String] {
        self.image.needed_libraries()
    }

    fn symbol_address(&self, name: &str) -> Option<usize> {
        self.image.symbol_address(name)
    }

    fn exported_symbol_address(&self, name: &str) -> Option<usize> {
        self.image.exported_symbol_address(name)
    }

    fn is_manual_load(&self) -> bool {
        self.manual
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
enum LoaderState {
    #[default]
    Empty,
    #[cfg_attr(not(unix), allow(dead_code))]
    Linked,
    Abandoned,
}

impl SoLoader {
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let image = ElfImage::parse_file(path, 0)?;
        platform_link_file(self, path, image)
    }

    pub fn load_from_memory(&mut self, name: impl Into<String>, data: &[u8]) -> Result<()> {
        let image = ElfImage::parse_memory(name, data, 0)?;
        platform_link_memory(self, image)
    }

    pub fn unload(&mut self) -> Result<()> {
        let destructor_result = {
            #[cfg(unix)]
            {
                unsafe { self.run_destructors() }
            }
            #[cfg(not(unix))]
            {
                Ok(())
            }
        };
        self.release_loaded_images(true);
        self.state = LoaderState::Empty;
        destructor_result
    }

    pub fn abandon(&mut self) -> Result<()> {
        self.release_loaded_images(false);
        self.state = LoaderState::Abandoned;
        Ok(())
    }

    pub fn get_symbol(&self, name: &str) -> Option<*mut libc::c_void> {
        self.main
            .as_ref()
            .and_then(|main| main.image.symbol_address(name))
            .map(|addr| addr as *mut libc::c_void)
    }

    fn release_loaded_images(&mut self, _unmap: bool) {
        #[cfg(unix)]
        {
            if !_unmap {
                if let Some(group) = &self.load_group {
                    group.abandon();
                }
                if let Some(main) = &mut self.main {
                    main.abandon_mapping();
                }
                for loaded in &mut self.dependencies {
                    loaded.abandon_mapping();
                }
            }

            while let Some(loaded) = self.dependencies.pop() {
                drop(loaded);
            }
            drop(self.main.take());
        }

        #[cfg(not(unix))]
        let _ = _unmap;

        self.dependencies.clear();
        self.main = None;
        #[cfg(any(unix, test))]
        drop(self.load_group.take());
    }

    #[cfg(unix)]
    unsafe fn run_destructors(&self) -> Result<()> {
        if self.state != LoaderState::Linked {
            return Ok(());
        }

        if let Some(main) = &self.main {
            unsafe {
                call_destructors(&main.image)?;
            }
        }

        for loaded in &self.dependencies {
            if loaded.manual {
                unsafe {
                    call_destructors(&loaded.image)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(not(unix))]
fn platform_link_file(_loader: &mut SoLoader, _path: &Path, _image: ElfImage) -> Result<()> {
    Err(crate::soloader::error::LoaderError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn platform_link_memory(_loader: &mut SoLoader, _image: ElfImage) -> Result<()> {
    Err(crate::soloader::error::LoaderError::UnsupportedPlatform)
}

#[cfg(unix)]
fn platform_link_file(loader: &mut SoLoader, path: &Path, image: ElfImage) -> Result<()> {
    loader.release_loaded_images(true);

    let mut main = unsafe { map_image_from_file(path, image)? };
    let mut dependencies = load_dependencies(&main.image, path.parent())?;

    register_tls_segments(&mut main, &mut dependencies)?;
    unsafe {
        link_loaded_images(&mut main, &mut dependencies)?;
        register_backtrace_segments(&mut main, &mut dependencies);
        let load_group = retain_load_group(&mut main, &mut dependencies);
        call_manual_dependency_constructors(&main, &dependencies)?;
        call_constructors(&main.image)?;
        loader.load_group = Some(load_group);
    }

    loader.main = Some(main);
    loader.dependencies = dependencies;
    loader.state = LoaderState::Linked;
    Ok(())
}

#[cfg(unix)]
fn platform_link_memory(loader: &mut SoLoader, mut image: ElfImage) -> Result<()> {
    loader.release_loaded_images(true);
    let origin_dir = library_origin_dir(image.name());

    let phdrs = image.program_headers().to_vec();
    let layout = mapping::load_size(&phdrs).ok_or_else(|| {
        crate::soloader::error::LoaderError::InvalidElf(format!("no loadable segments in {}", image.name()))
    })?;
    let mapped = unsafe {
        mapping::map_memory_segments(image.bytes(), &phdrs, layout)
            .map_err(crate::soloader::error::LoaderError::Io)?
    };
    image.set_base(mapped.base as usize);

    let mut main = LoadedImage::new(image, mapped.map_size, true);
    let mut dependencies = load_dependencies(&main.image, origin_dir.as_deref())?;
    register_tls_segments(&mut main, &mut dependencies)?;
    unsafe {
        link_loaded_images(&mut main, &mut dependencies)?;
        register_backtrace_segments(&mut main, &mut dependencies);
        let load_group = retain_load_group(&mut main, &mut dependencies);
        call_manual_dependency_constructors(&main, &dependencies)?;
        call_constructors(&main.image)?;
        loader.load_group = Some(load_group);
    }

    loader.main = Some(main);
    loader.dependencies = dependencies;
    loader.state = LoaderState::Linked;
    Ok(())
}

#[cfg(unix)]
unsafe fn map_image_from_file(path: &Path, mut image: ElfImage) -> Result<LoadedImage> {
    let file = File::open(path)?;
    let phdrs = image.program_headers().to_vec();
    let layout = mapping::load_size(&phdrs).ok_or_else(|| {
        crate::soloader::error::LoaderError::InvalidElf(format!("no loadable segments in {}", image.name()))
    })?;
    let mapped = unsafe {
        mapping::map_file_segments(file.as_raw_fd(), &phdrs, layout)
            .map_err(crate::soloader::error::LoaderError::Io)?
    };
    image.set_base(mapped.base as usize);

    Ok(LoadedImage::new(image, mapped.map_size, true))
}

#[cfg(unix)]
fn load_dependencies(main: &ElfImage, origin_dir: Option<&Path>) -> Result<Vec<LoadedImage>> {
    let mut queue = Vec::new();
    enqueue_needed_libraries(&mut queue, main.needed_libraries());

    let mut dependencies = Vec::new();
    let mut cursor = 0usize;

    while cursor < queue.len() {
        let lib_name = queue[cursor].clone();
        cursor += 1;

        if is_loaded_by_name(main, &dependencies, &lib_name) {
            continue;
        }

        let Some(found) =
            find_library_path_with_source(&lib_name, origin_dir, system_library_search_roots())
        else {
            continue;
        };
        let path = found.path;
        let search_source = found.source;

        let path_string = path.to_string_lossy();
        if is_loaded_by_name(main, &dependencies, &path_string) {
            continue;
        }

        if dependencies.len() >= MAX_DEPS {
            return Err(crate::soloader::error::LoaderError::Link(format!(
                "maximum dependency count ({MAX_DEPS}) exceeded while loading {lib_name}"
            )));
        }

        let loaded = match find_host_library(&lib_name)
            .filter(|_| can_reuse_host_library_for_dependency(search_source))
        {
            Some(host) => {
                let host_path = if host.path.as_os_str().is_empty() {
                    path.clone()
                } else {
                    host.path
                };
                match ElfImage::parse_file(&host_path, host.base) {
                    Ok(image) => LoadedImage::new(image, 0, false),
                    Err(_) => unsafe {
                        let image = ElfImage::parse_file(&path, 0)?;
                        map_image_from_file(&path, image)?
                    },
                }
            }
            None => unsafe {
                let image = ElfImage::parse_file(&path, 0)?;
                map_image_from_file(&path, image)?
            },
        };

        enqueue_transitive_needed_libraries(
            &mut queue,
            loaded.manual,
            loaded.image.needed_libraries(),
        );
        dependencies.push(loaded);
    }

    Ok(dependencies)
}

#[cfg(any(unix, test))]
fn enqueue_transitive_needed_libraries(
    queue: &mut Vec<String>,
    manual: bool,
    needed_libraries: &[String],
) {
    if manual {
        enqueue_needed_libraries(queue, needed_libraries);
    }
}

#[cfg(unix)]
fn library_origin_dir(name: &str) -> Option<PathBuf> {
    let parent = Path::new(name).parent()?;
    (!parent.as_os_str().is_empty()).then(|| parent.to_path_buf())
}

#[cfg(unix)]
fn is_loaded_by_name(main: &ElfImage, dependencies: &[LoadedImage], name_or_path: &str) -> bool {
    image_name_matches(main.name(), name_or_path)
        || dependencies
            .iter()
            .any(|dep| image_name_matches(dep.image.name(), name_or_path))
}

#[cfg(unix)]
fn image_name_matches(image_name: &str, name_or_path: &str) -> bool {
    image_name == name_or_path
        || basename(image_name) == basename(name_or_path)
        || image_name.contains(name_or_path)
        || name_or_path.contains(image_name)
}

#[cfg(unix)]
struct HostLibrary {
    path: std::path::PathBuf,
    base: usize,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn find_host_library(lib_name: &str) -> Option<HostLibrary> {
    struct SearchState<'a> {
        needle: &'a str,
        found: Option<HostLibrary>,
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        if info.is_null() || data.is_null() {
            return 0;
        }

        let state = unsafe { &mut *(data as *mut SearchState<'_>) };
        let dlpi_name = unsafe { (*info).dlpi_name };
        if dlpi_name.is_null() {
            return 0;
        }

        let path = unsafe { CStr::from_ptr(dlpi_name) }
            .to_string_lossy()
            .into_owned();
        if path.is_empty() || !image_name_matches(&path, state.needle) {
            return 0;
        }

        state.found = Some(HostLibrary {
            path: std::path::PathBuf::from(path),
            base: unsafe { (*info).dlpi_addr as usize },
        });
        1
    }

    let mut state = SearchState {
        needle: lib_name,
        found: None,
    };
    unsafe {
        libc::dl_iterate_phdr(Some(callback), &mut state as *mut _ as *mut libc::c_void);
    }
    state.found
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn find_host_library(_lib_name: &str) -> Option<HostLibrary> {
    None
}

#[cfg(unix)]
fn can_reuse_host_library_for_dependency(source: LibrarySearchSource) -> bool {
    match source {
        LibrarySearchSource::System => true,
        LibrarySearchSource::Origin => false,
    }
}

#[cfg(unix)]
fn register_tls_segments(main: &mut LoadedImage, dependencies: &mut [LoadedImage]) -> Result<()> {
    register_tls_segment(main)?;

    for dependency in dependencies.iter_mut().filter(|dep| dep.manual) {
        register_tls_segment(dependency)?;
    }

    Ok(())
}

#[cfg(unix)]
fn register_tls_segment(loaded: &mut LoadedImage) -> Result<()> {
    let Some(tls) = loaded.image.tls() else {
        return Ok(());
    };
    if tls.file_size > tls.mem_size {
        return Err(crate::soloader::error::LoaderError::InvalidElf(
            "PT_TLS file size exceeds memory size".into(),
        ));
    }
    let tls_file_end = tls.address.checked_add(tls.file_size).ok_or_else(|| {
        crate::soloader::error::LoaderError::InvalidElf("PT_TLS address range overflow".into())
    })?;
    let tls_end = tls.address.checked_add(tls.mem_size).ok_or_else(|| {
        crate::soloader::error::LoaderError::InvalidElf("PT_TLS memory range overflow".into())
    })?;
    if !loaded
        .image
        .program_headers()
        .iter()
        .filter(|ph| ph.p_type == crate::soloader::mapping::PT_LOAD)
        .any(|ph| {
            let start = loaded.image.absolute_address(ph.p_vaddr);
            let end = start.checked_add(ph.p_memsz as usize);
            matches!(end, Some(end) if tls.address >= start && tls_end <= end)
        })
    {
        return Err(crate::soloader::error::LoaderError::InvalidElf(
            "PT_TLS initializer outside PT_LOAD".into(),
        ));
    }

    if tls.file_size != 0
        && !loaded
            .image
            .program_headers()
            .iter()
            .filter(|ph| ph.p_type == crate::soloader::mapping::PT_LOAD)
            .any(|ph| {
                let start = loaded.image.absolute_address(ph.p_vaddr);
                let end = start.checked_add(ph.p_memsz as usize);
                matches!(end, Some(end) if tls.address >= start && tls_file_end <= end)
            })
    {
        return Err(crate::soloader::error::LoaderError::InvalidElf(
            "PT_TLS initializer outside PT_LOAD".into(),
        ));
    }
    let init = if tls.file_size == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(tls.address as *const u8, tls.file_size) }
    };
    let module_id = global_tls_registry()
        .register_module(init, tls.mem_size, tls.align)
        .ok_or_else(|| {
            crate::soloader::error::LoaderError::Link(format!(
                "failed to register TLS segment for {}",
                loaded.image.name()
            ))
        })?;
    loaded.tls_module_id = Some(module_id);
    Ok(())
}

#[cfg(unix)]
unsafe fn unregister_tls_segment(loaded: &mut LoadedImage) {
    if let Some(module_id) = loaded.tls_module_id.take() {
        global_tls_registry().unregister_module(module_id);
    }
    loaded.tls_indices.clear();
}

#[cfg(unix)]
fn register_backtrace_segments(main: &mut LoadedImage, dependencies: &mut [LoadedImage]) {
    register_backtrace_segment(main);
    for dependency in dependencies.iter_mut().filter(|dep| dep.manual) {
        register_backtrace_segment(dependency);
    }
}

#[cfg(unix)]
fn register_backtrace_segment(loaded: &mut LoadedImage) {
    if !loaded.manual {
        return;
    }

    let handle = backtrace::register_backtrace_library(&loaded.image, loaded.tls_module_id);
    if let Some(handle) = handle {
        let _ = backtrace::register_backtrace_eh_frame(handle);
    }
    loaded.backtrace_handle = handle;
}

#[cfg(unix)]
unsafe fn unregister_backtrace_segment(loaded: &mut LoadedImage) {
    if let Some(handle) = loaded.backtrace_handle.take() {
        let _ = backtrace::unregister_backtrace_library(handle);
    }
}

#[cfg(unix)]
fn retain_load_group(
    main: &mut LoadedImage,
    dependencies: &mut [LoadedImage],
) -> Arc<LoadGroupLease> {
    let mut group = LoadGroupLease::default();
    let mut dso_handles = Vec::new();

    for loaded in std::iter::once(main).chain(dependencies.iter_mut()) {
        if !loaded.manual {
            continue;
        }
        if let Some(dso_handle) = dso_handle_for_image(&loaded.image) {
            dso_handles.push(dso_handle);
        }
        if loaded.unmap_on_drop && loaded.map_size != 0 {
            group.mappings.push((loaded.image.base(), loaded.map_size));
            loaded.unmap_on_drop = false;
        }
        if let Some(module_id) = loaded.tls_module_id.take() {
            group.tls_modules.push(module_id);
        }
        group.tls_indices.append(&mut loaded.tls_indices);
        if let Some(handle) = loaded.backtrace_handle.take() {
            group.backtrace_handles.push(handle);
        }
    }

    let group = Arc::new(group);
    register_thread_atexit_group(&group);
    for dso_handle in dso_handles {
        register_thread_atexit_dso(dso_handle, &group);
    }
    group
}

#[cfg(unix)]
unsafe fn link_loaded_images(
    main: &mut LoadedImage,
    dependencies: &mut [LoadedImage],
) -> Result<()> {
    make_relocations_writable(main)?;
    for dependency in dependencies.iter().filter(|dep| dep.manual) {
        make_relocations_writable(dependency)?;
    }

    let main_image = main.image.clone();
    let main_map_size = main.map_size;
    let mut main_context = LinkContext {
        main,
        dependencies,
        requester: Requester::Main,
    };
    unsafe {
        apply_mapped_image_relocations(&main_image, main_map_size, &mut main_context)?;
    }

    let dep_count = main_context.dependencies.len();
    for index in 0..dep_count {
        let (manual, image, map_size) = {
            let dependency = &main_context.dependencies[index];
            (
                dependency.manual,
                dependency.image.clone(),
                dependency.map_size,
            )
        };
        if !manual {
            continue;
        }

        main_context.requester = Requester::Dependency(index);
        unsafe {
            apply_mapped_image_relocations(&image, map_size, &mut main_context)?;
        }
    }

    restore_image_protections(main_context.main)?;
    for dependency in main_context.dependencies.iter().filter(|dep| dep.manual) {
        restore_image_protections(dependency)?;
    }

    Ok(())
}

#[cfg(unix)]
fn make_relocations_writable(loaded: &LoadedImage) -> Result<()> {
    let load_bias = loaded.image.base().wrapping_sub(loaded.image.bias());
    unsafe {
        mapping::protect_load_segments(loaded.image.program_headers(), load_bias, true)
            .map_err(crate::soloader::error::LoaderError::Io)
    }
}

#[cfg(unix)]
fn restore_image_protections(loaded: &LoadedImage) -> Result<()> {
    let load_bias = loaded.image.base().wrapping_sub(loaded.image.bias());
    unsafe {
        mapping::protect_load_segments(loaded.image.program_headers(), load_bias, false)
            .map_err(crate::soloader::error::LoaderError::Io)?;
        mapping::protect_gnu_relro(loaded.image.program_headers(), load_bias)
            .map_err(crate::soloader::error::LoaderError::Io)
    }
}

#[cfg(unix)]
unsafe fn apply_mapped_image_relocations(
    image: &ElfImage,
    map_size: usize,
    resolver: &mut dyn TlsRelocationContext,
) -> Result<()> {
    if map_size == 0 {
        return Ok(());
    }

    let mapped = unsafe { std::slice::from_raw_parts_mut(image.base() as *mut u8, map_size) };
    apply_image_relocations_with_tls(
        image,
        mapped,
        image.base().wrapping_sub(image.bias()),
        image.bias(),
        resolver,
    )
}

#[cfg(unix)]
fn apply_image_relocations_with_tls(
    image: &ElfImage,
    mapped: &mut [u8],
    load_bias: usize,
    memory_base_vaddr: usize,
    resolver: &mut dyn TlsRelocationContext,
) -> Result<()> {
    let kinds = RelocationKinds::for_machine(image.machine()).ok_or_else(|| {
        crate::soloader::error::LoaderError::Link(format!(
            "unsupported ELF machine {} in {}",
            image.machine(),
            image.name()
        ))
    })?;
    let config = RelocationApplyConfig {
        load_bias,
        memory_base_vaddr,
        word_size: image.word_size(),
        little_endian: image.is_little_endian(),
    };

    for offset in image.relr_offsets() {
        crate::soloader::reloc::apply_relr_offset(mapped, *offset, config)?;
    }
    for relocation in image.rela_relocations() {
        crate::soloader::reloc::apply_relocation_with_tls(mapped, relocation, &kinds, config, resolver)?;
    }
    for relocation in image.rel_relocations() {
        crate::soloader::reloc::apply_relocation_with_tls(mapped, relocation, &kinds, config, resolver)?;
    }
    if let Some(android) = image.android_relocations() {
        for relocation in &android.relocations {
            crate::soloader::reloc::apply_relocation_with_tls(mapped, relocation, &kinds, config, resolver)?;
        }
    }
    for relocation in image.plt_relocations() {
        crate::soloader::reloc::apply_relocation_with_tls(mapped, relocation, &kinds, config, resolver)?;
    }

    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Copy, Clone)]
enum Requester {
    Main,
    Dependency(usize),
}

#[cfg(unix)]
struct LinkContext<'a> {
    main: &'a mut LoadedImage,
    dependencies: &'a mut [LoadedImage],
    requester: Requester,
}

#[cfg(unix)]
#[derive(Debug, Copy, Clone)]
enum ImageSlot {
    Main,
    Dependency(usize),
}

#[cfg(unix)]
#[derive(Debug, Copy, Clone)]
struct SymbolLookup {
    address: usize,
    image: Option<ImageSlot>,
}

#[cfg(unix)]
impl<'a> LinkContext<'a> {
    fn requester_image(&self) -> &LoadedImage {
        match self.requester {
            Requester::Main => self.main,
            Requester::Dependency(index) => &self.dependencies[index],
        }
    }

    fn loaded_image(&self, slot: ImageSlot) -> &LoadedImage {
        match slot {
            ImageSlot::Main => self.main,
            ImageSlot::Dependency(index) => &self.dependencies[index],
        }
    }

    fn find_symbol_in_scope(&self, name: &str) -> Option<SymbolLookup> {
        match self.requester {
            Requester::Main => {
                if let Some(found) =
                    image_symbol_lookup(&self.main.image, name, false, Some(ImageSlot::Main))
                {
                    return Some(found);
                }
            }
            Requester::Dependency(index) => {
                if let Some(found) = image_symbol_lookup(
                    &self.dependencies[index].image,
                    name,
                    false,
                    Some(ImageSlot::Dependency(index)),
                ) {
                    return Some(found);
                }
            }
        }

        if !matches!(self.requester, Requester::Main) {
            if let Some(found) =
                image_symbol_lookup(&self.main.image, name, true, Some(ImageSlot::Main))
            {
                return Some(found);
            }
        }

        if let Some(address) = special_symbol_address(name) {
            return Some(SymbolLookup {
                address,
                image: None,
            });
        }

        for (index, dependency) in self.dependencies.iter().enumerate() {
            if matches!(self.requester, Requester::Dependency(requester) if requester == index) {
                continue;
            }
            if let Some(found) = image_symbol_lookup(
                &dependency.image,
                name,
                true,
                Some(ImageSlot::Dependency(index)),
            ) {
                return Some(found);
            }
        }

        unsafe { host_symbol_address(name) }.map(|address| SymbolLookup {
            address,
            image: None,
        })
    }

    fn resolve_tls_symbol_slot(&self, sym_idx: usize) -> Result<Option<ImageSlot>> {
        if sym_idx == 0 {
            return Ok(Some(match self.requester {
                Requester::Main => ImageSlot::Main,
                Requester::Dependency(index) => ImageSlot::Dependency(index),
            }));
        }

        let requester = self.requester_image();
        let symbol = requester.image.dynamic_symbol(sym_idx).ok_or_else(|| {
            crate::soloader::error::LoaderError::Link(format!(
                "TLS symbol index {sym_idx} out of range in {}",
                requester.image.name()
            ))
        })?;
        if symbol.bind() == 0 {
            return Err(crate::soloader::error::LoaderError::Link(format!(
                "unexpected local TLS symbol '{}' in {}",
                symbol.name,
                requester.image.name()
            )));
        }
        if symbol.name.is_empty() {
            return Ok(Some(match self.requester {
                Requester::Main => ImageSlot::Main,
                Requester::Dependency(index) => ImageSlot::Dependency(index),
            }));
        }

        if let Some(found) = self.find_symbol_in_scope(&symbol.name) {
            Ok(found.image)
        } else if symbol.bind() == 2 {
            Ok(None)
        } else {
            Err(crate::soloader::error::LoaderError::Link(format!(
                "TLS symbol '{}' not found in {}",
                symbol.name,
                requester.image.name()
            )))
        }
    }

    fn image_by_tls_module_mut(&mut self, module: usize) -> Option<&mut LoadedImage> {
        if self.main.tls_module_id == Some(module) {
            return Some(self.main);
        }
        self.dependencies
            .iter_mut()
            .find(|dependency| dependency.tls_module_id == Some(module))
    }
}

#[cfg(unix)]
impl<'a> SymbolResolver for LinkContext<'a> {
    fn resolve(&self, sym_idx: usize) -> Result<SymbolResolution> {
        let requester = self.requester_image();
        let symbol = requester.image.dynamic_symbol(sym_idx).ok_or_else(|| {
            crate::soloader::error::LoaderError::Link(format!(
                "symbol index {sym_idx} out of range in {}",
                requester.image.name()
            ))
        })?;

        if symbol.shndx == 0 && symbol.bind() == 2 {
            return Ok(SymbolResolution::UnresolvedWeak);
        }
        if symbol.name.is_empty() {
            let address = resolve_image_symbol(&requester.image, symbol).ok_or_else(|| {
                crate::soloader::error::LoaderError::Link("IFUNC resolver ABI is unsupported".into())
            })?;
            return Ok(SymbolResolution::Resolved(address));
        }
        if let Some(found) = self.find_symbol_in_scope(&symbol.name) {
            return Ok(SymbolResolution::Resolved(found.address));
        }

        if symbol.bind() == 2 {
            Ok(SymbolResolution::UnresolvedWeak)
        } else {
            Err(crate::soloader::error::LoaderError::Link(format!(
                "symbol '{}' not found in {}",
                symbol.name,
                requester.image.name()
            )))
        }
    }

    fn resolve_ifunc(&self, address: usize) -> Result<usize> {
        unsafe { resolve_ifunc_checked(address) }
    }
}

#[cfg(unix)]
impl<'a> TlsRelocationContext for LinkContext<'a> {
    fn resolve_tls(&self, sym_idx: usize, addend: i64) -> Result<TlsSymbolResolution> {
        let requester = self.requester_image();
        let symbol_value = if sym_idx == 0 {
            0
        } else {
            requester
                .image
                .dynamic_symbol(sym_idx)
                .ok_or_else(|| {
                    crate::soloader::error::LoaderError::Link(format!(
                        "TLS symbol index {sym_idx} out of range in {}",
                        requester.image.name()
                    ))
                })?
                .value as usize
        };

        let Some(slot) = self.resolve_tls_symbol_slot(sym_idx)? else {
            return Ok(TlsSymbolResolution::UnresolvedWeak);
        };
        let image = self.loaded_image(slot);
        if image.image.tls().is_none() {
            return Err(crate::soloader::error::LoaderError::Link(format!(
                "TLS relocation refers to module with no TLS segment in {}",
                image.image.name()
            )));
        }
        let Some(module) = image.tls_module_id else {
            return Err(crate::soloader::error::LoaderError::Link(format!(
                "TLS module not registered for {}",
                image.image.name()
            )));
        };

        Ok(TlsSymbolResolution::Resolved {
            module,
            offset: symbol_value.wrapping_add(addend as isize as usize),
        })
    }

    fn allocate_tls_index(&mut self, index: TlsIndex) -> Result<*mut TlsIndex> {
        let owner = self.image_by_tls_module_mut(index.module).ok_or_else(|| {
            crate::soloader::error::LoaderError::Link(format!(
                "cannot track TLS index for unknown module {}",
                index.module
            ))
        })?;
        owner.tls_indices.push(Box::new(index));
        Ok(owner
            .tls_indices
            .last_mut()
            .expect("TLS index was just pushed")
            .as_mut() as *mut TlsIndex)
    }
}

#[cfg(unix)]
fn image_symbol_lookup(
    image: &ElfImage,
    name: &str,
    exported_only: bool,
    slot: Option<ImageSlot>,
) -> Option<SymbolLookup> {
    let symbol = image.symbol_offset(name, exported_only)?;
    Some(SymbolLookup {
        address: resolve_image_symbol(image, &symbol)?,
        image: slot,
    })
}

#[cfg(unix)]
fn resolve_image_symbol(image: &ElfImage, symbol: &SymbolInfo) -> Option<usize> {
    let address = image.absolute_address(symbol.value);
    if symbol.is_ifunc() {
        unsafe { resolve_ifunc_checked(address).ok() }
    } else {
        Some(address)
    }
}

#[cfg(unix)]
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
#[repr(C)]
struct AndroidAarch64IfuncArg {
    size: libc::c_ulong,
    hwcap: libc::c_ulong,
    hwcap2: libc::c_ulong,
}

#[cfg(all(unix, target_os = "android", target_arch = "aarch64"))]
unsafe fn resolve_ifunc(address: usize) -> usize {
    const IFUNC_ARG_HWCAP: u64 = 1 << 62;
    type IfuncResolver = unsafe extern "C" fn(u64, *const AndroidAarch64IfuncArg) -> usize;

    let arg = AndroidAarch64IfuncArg {
        size: std::mem::size_of::<AndroidAarch64IfuncArg>() as libc::c_ulong,
        hwcap: unsafe { libc::getauxval(libc::AT_HWCAP) as libc::c_ulong },
        hwcap2: unsafe { libc::getauxval(libc::AT_HWCAP2) as libc::c_ulong },
    };
    let resolver: IfuncResolver = unsafe { std::mem::transmute(address) };
    unsafe { resolver((arg.hwcap as u64) | IFUNC_ARG_HWCAP, &arg) }
}

#[cfg(all(unix, target_os = "android", target_arch = "arm"))]
unsafe fn resolve_ifunc_checked(address: usize) -> Result<usize> {
    type IfuncResolver = unsafe extern "C" fn(libc::c_ulong) -> usize;
    let resolver: IfuncResolver = std::mem::transmute(address);
    Ok(resolver(unsafe {
        libc::getauxval(libc::AT_HWCAP) as libc::c_ulong
    }))
}

#[cfg(all(unix, target_os = "android", target_arch = "riscv64"))]
unsafe fn resolve_ifunc_checked(_address: usize) -> Result<usize> {
    Err(crate::soloader::error::LoaderError::Link(
        "Android RISC-V IRELATIVE resolver ABI is unavailable".into(),
    ))
}

#[cfg(all(unix, not(target_os = "android"), target_arch = "riscv64"))]
unsafe fn resolve_ifunc_checked(_address: usize) -> Result<usize> {
    Err(crate::soloader::error::LoaderError::Link(
        "RISC-V IRELATIVE resolver ABI is unavailable".into(),
    ))
}

#[cfg(all(unix, not(target_os = "android"), not(target_arch = "riscv64")))]
unsafe fn resolve_ifunc_checked(address: usize) -> Result<usize> {
    Ok(unsafe { resolve_ifunc(address) })
}

#[cfg(all(unix, target_os = "android", target_arch = "aarch64"))]
unsafe fn resolve_ifunc_checked(address: usize) -> Result<usize> {
    Ok(unsafe { resolve_ifunc(address) })
}

#[cfg(all(unix, target_os = "android", target_arch = "arm"))]
unsafe fn resolve_ifunc(address: usize) -> usize {
    type IfuncResolver = unsafe extern "C" fn(libc::c_ulong) -> usize;
    let resolver: IfuncResolver = std::mem::transmute(address);
    resolver(libc::getauxval(libc::AT_HWCAP) as libc::c_ulong)
}

#[cfg(all(unix, not(target_os = "android"), not(target_arch = "riscv64")))]
unsafe fn resolve_ifunc(address: usize) -> usize {
    type IfuncResolver = unsafe extern "C" fn() -> usize;
    let resolver: IfuncResolver = unsafe { std::mem::transmute(address) };
    unsafe { resolver() }
}

#[cfg(unix)]
fn special_symbol_address(name: &str) -> Option<usize> {
    match name {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "dl_iterate_phdr" => Some(backtrace::custom_dl_iterate_phdr as *const () as usize),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "dladdr" => Some(backtrace::custom_dladdr as *const () as usize),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "dlopen" => Some(backtrace::custom_dlopen as *const () as usize),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "dlsym" => Some(backtrace::custom_dlsym as *const () as usize),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "dlclose" => Some(backtrace::custom_dlclose as *const () as usize),
        "__tls_get_addr" => Some(crate::soloader::tls::tls_get_addr as *const () as usize),
        "__cxa_atexit" => Some(custom_cxa_atexit as *const () as usize),
        "__cxa_thread_atexit_impl" => Some(custom_cxa_thread_atexit_impl as *const () as usize),
        "__cxa_finalize" => Some(custom_cxa_finalize as *const () as usize),
        "atexit" => Some(custom_atexit as *const () as usize),
        _ => None,
    }
}

#[cfg(unix)]
unsafe fn host_symbol_address(name: &str) -> Option<usize> {
    let name = CString::new(name).ok()?;
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!address.is_null()).then_some(address as usize)
}

#[cfg(unix)]
unsafe extern "C" fn custom_cxa_atexit(
    func: Option<unsafe extern "C" fn(*mut libc::c_void)>,
    arg: *mut libc::c_void,
    dso_handle: *mut libc::c_void,
) -> libc::c_int {
    let Some(func) = func else {
        return -1;
    };

    register_atexit_entry(AtExitEntry {
        function: AtExitFunction::Cxa { func, arg },
        dso_handle,
    })
}

#[cfg(any(unix, test))]
unsafe extern "C" fn custom_cxa_thread_atexit_impl(
    func: Option<unsafe extern "C" fn(*mut libc::c_void)>,
    arg: *mut libc::c_void,
    dso_handle: *mut libc::c_void,
) -> libc::c_int {
    let (Some(function), Some(lease)) = (func, thread_atexit_lease(dso_handle)) else {
        return -1;
    };
    let entry = ThreadAtExitEntry {
        callback: ThreadAtExitFunction {
            function,
            argument: arg as usize,
        },
        _lease: lease,
    };
    THREAD_ATEXIT_STACK
        .try_with(|stack| stack.borrow_mut().entries.push(entry))
        .map_or(-1, |_| 0)
}

#[cfg(unix)]
unsafe extern "C" fn custom_cxa_finalize(dso_handle: *mut libc::c_void) {
    unsafe {
        run_cxa_finalize(dso_handle);
    }
}

#[cfg(unix)]
unsafe extern "C" fn custom_atexit(func: Option<unsafe extern "C" fn()>) -> libc::c_int {
    let Some(func) = func else {
        return -1;
    };

    register_atexit_entry(AtExitEntry {
        function: AtExitFunction::Plain { func },
        dso_handle: std::ptr::null_mut(),
    })
}

#[cfg(unix)]
#[derive(Copy, Clone)]
enum AtExitFunction {
    Cxa {
        func: unsafe extern "C" fn(*mut libc::c_void),
        arg: *mut libc::c_void,
    },
    Plain {
        func: unsafe extern "C" fn(),
    },
}

#[cfg(unix)]
#[derive(Copy, Clone)]
struct AtExitEntry {
    function: AtExitFunction,
    dso_handle: *mut libc::c_void,
}

#[cfg(unix)]
unsafe impl Send for AtExitEntry {}

#[cfg(unix)]
impl AtExitEntry {
    unsafe fn call(self) {
        match self.function {
            AtExitFunction::Cxa { func, arg } => unsafe {
                func(arg);
            },
            AtExitFunction::Plain { func } => unsafe {
                func();
            },
        }
    }
}

#[cfg(unix)]
fn register_atexit_entry(entry: AtExitEntry) -> libc::c_int {
    atexit_entries()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(entry);
    0
}

#[cfg(unix)]
unsafe fn run_cxa_finalize(dso_handle: *mut libc::c_void) {
    let callbacks = take_atexit_entries(dso_handle);
    for callback in callbacks {
        unsafe {
            callback.call();
        }
    }
}

#[cfg(unix)]
fn take_atexit_entries(dso_handle: *mut libc::c_void) -> Vec<AtExitEntry> {
    let mut entries = atexit_entries()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut callbacks = Vec::new();
    let mut index = entries.len();

    while index > 0 {
        index -= 1;
        if dso_handle.is_null() || entries[index].dso_handle == dso_handle {
            callbacks.push(entries.remove(index));
        }
    }

    callbacks
}

#[cfg(unix)]
fn atexit_entries() -> &'static Mutex<Vec<AtExitEntry>> {
    static ENTRIES: OnceLock<Mutex<Vec<AtExitEntry>>> = OnceLock::new();
    ENTRIES.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(unix)]
unsafe fn call_manual_dependency_constructors(
    main: &LoadedImage,
    dependencies: &[LoadedImage],
) -> Result<()> {
    let mut graph = RuntimeGraph::new(Box::new(main.clone()));
    for dependency in dependencies {
        graph.add_dependency(Box::new(dependency.clone()));
    }

    for name in graph.manual_constructor_order() {
        if let Some(dependency) = dependencies
            .iter()
            .find(|dep| dep.manual && image_name_matches(dep.image.name(), &name))
        {
            unsafe {
                call_constructors(&dependency.image)?;
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
unsafe fn call_constructors(image: &ElfImage) -> Result<()> {
    type InitFn = unsafe extern "C" fn();
    type CtorFn = unsafe extern "C" fn(libc::c_int, *mut *mut libc::c_char, *mut *mut libc::c_char);

    if let Some(init) = image.init().filter(|addr| *addr != 0) {
        let init_fn: InitFn = unsafe { std::mem::transmute(init) };
        unsafe {
            init_fn();
        }
    }

    if let Some(array) = image.init_array() {
        for index in 0..array.count {
            let entry_address = array
                .address
                .checked_add(index.saturating_mul(core::mem::size_of::<usize>()))
                .ok_or_else(|| {
                    crate::soloader::error::LoaderError::Link("init_array address overflow".into())
                })?;
            let function = unsafe { read_constructor_entry(entry_address) };
            if function == 0 {
                continue;
            }

            let ctor: CtorFn = unsafe { std::mem::transmute(function) };
            unsafe {
                ctor(0, std::ptr::null_mut(), std::ptr::null_mut());
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
unsafe fn call_destructors(image: &ElfImage) -> Result<()> {
    type DtorFn = unsafe extern "C" fn();

    if let Some(dso_handle) = dso_handle_for_image(image) {
        unsafe {
            run_cxa_finalize(dso_handle);
        }
    }

    for function in destructor_addresses(image.fini_array(), image.fini(), |addr| unsafe {
        Some(read_constructor_entry(addr))
    })? {
        if function == 0 {
            continue;
        }

        let dtor: DtorFn = unsafe { std::mem::transmute(function) };
        unsafe {
            dtor();
        }
    }

    Ok(())
}

#[cfg(unix)]
fn dso_handle_for_image(image: &ElfImage) -> Option<*mut libc::c_void> {
    image
        .symbol_address("__dso_handle")
        .or_else(|| image.symbol_address_by_prefix("__dso_handle"))
        .map(|address| address as *mut libc::c_void)
}

#[cfg(unix)]
unsafe fn read_constructor_entry(address: usize) -> usize {
    unsafe { std::ptr::read_unaligned(address as *const usize) }
}

#[allow(dead_code)]
fn apply_image_relocations(
    image: &ElfImage,
    mapped: &mut [u8],
    load_bias: usize,
    memory_base_vaddr: usize,
    resolver: &dyn SymbolResolver,
) -> Result<()> {
    let kinds = RelocationKinds::for_machine(image.machine()).ok_or_else(|| {
        crate::soloader::error::LoaderError::Link(format!(
            "unsupported ELF machine {} in {}",
            image.machine(),
            image.name()
        ))
    })?;
    let config = RelocationApplyConfig {
        load_bias,
        memory_base_vaddr,
        word_size: image.word_size(),
        little_endian: image.is_little_endian(),
    };

    for offset in image.relr_offsets() {
        crate::soloader::reloc::apply_relr_offset(mapped, *offset, config)?;
    }
    for relocation in image.rela_relocations() {
        crate::soloader::reloc::apply_relocation(mapped, relocation, &kinds, config, resolver)?;
    }
    for relocation in image.rel_relocations() {
        crate::soloader::reloc::apply_relocation(mapped, relocation, &kinds, config, resolver)?;
    }
    if let Some(android) = image.android_relocations() {
        for relocation in &android.relocations {
            crate::soloader::reloc::apply_relocation(mapped, relocation, &kinds, config, resolver)?;
        }
    }
    for relocation in image.plt_relocations() {
        crate::soloader::reloc::apply_relocation(mapped, relocation, &kinds, config, resolver)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soloader::reloc::SymbolResolution;

    struct FixedResolver(usize);

    impl SymbolResolver for FixedResolver {
        fn resolve(&self, _sym_idx: usize) -> Result<SymbolResolution> {
            Ok(SymbolResolution::Resolved(self.0))
        }
    }

    #[test]
    fn apply_image_relocations_processes_all_retained_tables_in_linker_order() {
        let image = relocation_test_image();
        let mut mapped = vec![0u8; 0x700];
        write_word(&mut mapped, 0x500, 0x20);
        write_word(&mut mapped, 0x508, 0x30);

        apply_image_relocations(&image, &mut mapped, 0x1000, 0, &FixedResolver(0x2000)).unwrap();

        assert_eq!(read_word(&mapped, 0x300), 0x2007);
        assert_eq!(read_word(&mapped, 0x318), 0x2000);
        assert_eq!(read_word(&mapped, 0x330), 0x200b);
        assert_eq!(read_word(&mapped, 0x500), 0x1020);
        assert_eq!(read_word(&mapped, 0x508), 0x1030);
        assert_eq!(read_word(&mapped, 0x608), 0x1003);
        assert_eq!(read_word(&mapped, 0x610), 0x1007);
    }

    #[cfg(unix)]
    #[test]
    fn library_origin_dir_only_uses_names_with_parent_components() {
        assert_eq!(library_origin_dir("libfoo.so"), None);
        assert_eq!(
            library_origin_dir("./libfoo.so").as_deref(),
            Some(Path::new("."))
        );
        assert_eq!(
            library_origin_dir("/data/local/tmp/libfoo.so").as_deref(),
            Some(Path::new("/data/local/tmp"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_library_reuse_respects_dependency_source() {
        assert!(!can_reuse_host_library_for_dependency(
            crate::soloader::deps::LibrarySearchSource::Origin
        ));
        assert!(can_reuse_host_library_for_dependency(
            crate::soloader::deps::LibrarySearchSource::System
        ));
    }

    #[test]
    fn only_manual_dependencies_expand_their_needed_libraries() {
        let needed = vec!["libchild.so".to_owned()];
        let mut host_queue = Vec::new();
        enqueue_transitive_needed_libraries(&mut host_queue, false, &needed);
        assert!(host_queue.is_empty());

        let mut manual_queue = Vec::new();
        enqueue_transitive_needed_libraries(&mut manual_queue, true, &needed);
        assert_eq!(manual_queue, needed);
    }

    #[test]
    fn cloned_loaded_image_does_not_release_original_mapping() {
        let image =
            ElfImage::parse_memory("mapped.so", relocation_test_image().bytes(), 0).unwrap();
        let original = LoadedImage::new(image, 0, true);
        let clone = original.clone();
        assert!(!clone.unmap_on_drop);
        assert!(clone.tls_module_id.is_none());
        assert!(clone.backtrace_handle.is_none());
        drop(clone);
        drop(original);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn special_dl_symbols_precede_dependency_exports() {
        let main_image = ElfImage::parse_memory(
            "main.so",
            &synthetic_elf_with_named_dynsym("main_symbol", 0x1000),
            0x7000_0000,
        )
        .unwrap();
        let dependency_image = ElfImage::parse_memory(
            "libdl.so",
            &synthetic_elf_with_named_dynsym("dladdr", 0x2222),
            0x7100_0000,
        )
        .unwrap();
        let mut main = LoadedImage::new(main_image, 0, true);
        let mut dependencies = vec![LoadedImage::new(dependency_image, 0, false)];
        let context = LinkContext {
            main: &mut main,
            dependencies: &mut dependencies,
            requester: Requester::Main,
        };

        let found = context.find_symbol_in_scope("dladdr").unwrap();

        assert!(found.image.is_none());
        assert_eq!(found.address, special_symbol_address("dladdr").unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn ifunc_symbol_resolution_calls_resolver() {
        unsafe extern "C" fn resolved_target() {}

        unsafe extern "C" fn resolver() -> usize {
            resolved_target as *const () as usize
        }

        let main_image = ElfImage::parse_memory(
            "main.so",
            &synthetic_elf_with_named_dynsym("main_symbol", 0x1000),
            0,
        )
        .unwrap();
        let dependency_image = ElfImage::parse_memory(
            "libc.so",
            &synthetic_elf_with_named_dynsym_info("memset", resolver as *const () as u64, 0x1a),
            0,
        )
        .unwrap();
        let mut main = LoadedImage::new(main_image, 0, true);
        let mut dependencies = vec![LoadedImage::new(dependency_image, 0, false)];
        let context = LinkContext {
            main: &mut main,
            dependencies: &mut dependencies,
            requester: Requester::Main,
        };

        let found = context.find_symbol_in_scope("memset").unwrap();

        assert_eq!(found.address, resolved_target as *const () as usize);
    }

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    #[test]
    fn android_aarch64_ifunc_resolver_receives_hwcap_arguments() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        static OBSERVED_HWCAP: AtomicU64 = AtomicU64::new(0);
        static OBSERVED_ARG_PRESENT: AtomicBool = AtomicBool::new(false);

        const IFUNC_ARG_HWCAP: u64 = 1 << 62;

        unsafe extern "C" fn resolved_target() {}
        unsafe extern "C" fn fallback_target() {}

        unsafe extern "C" fn resolver(hwcap: u64, arg: *const libc::c_void) -> usize {
            OBSERVED_HWCAP.store(hwcap, Ordering::SeqCst);
            OBSERVED_ARG_PRESENT.store(!arg.is_null(), Ordering::SeqCst);
            if hwcap & IFUNC_ARG_HWCAP != 0 && !arg.is_null() {
                resolved_target as *const () as usize
            } else {
                fallback_target as *const () as usize
            }
        }

        let main_image = ElfImage::parse_memory(
            "main.so",
            &synthetic_elf_with_named_dynsym("main_symbol", 0x1000),
            0,
        )
        .unwrap();
        let dependency_image = ElfImage::parse_memory(
            "libc.so",
            &synthetic_elf_with_named_dynsym_info("strlen", resolver as *const () as u64, 0x1a),
            0,
        )
        .unwrap();
        let mut main = LoadedImage::new(main_image, 0, true);
        let mut dependencies = vec![LoadedImage::new(dependency_image, 0, false)];
        let context = LinkContext {
            main: &mut main,
            dependencies: &mut dependencies,
            requester: Requester::Main,
        };

        let found = context.find_symbol_in_scope("strlen").unwrap();

        assert_eq!(found.address, resolved_target as *const () as usize);
        assert_ne!(OBSERVED_HWCAP.load(Ordering::SeqCst) & IFUNC_ARG_HWCAP, 0);
        assert!(OBSERVED_ARG_PRESENT.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn cxa_finalize_runs_matching_entries_in_reverse_order_once() {
        use std::sync::{Mutex, OnceLock};

        static CALLS: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

        unsafe extern "C" fn record(arg: *mut libc::c_void) {
            CALLS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .unwrap()
                .push(arg as usize);
        }

        let calls = CALLS.get_or_init(|| Mutex::new(Vec::new()));
        calls.lock().unwrap().clear();

        let dso_a = 0xaaausize as *mut libc::c_void;
        let dso_b = 0xbbbusize as *mut libc::c_void;

        unsafe {
            assert_eq!(
                custom_cxa_atexit(
                    Some(record),
                    std::ptr::dangling_mut::<libc::c_void>(),
                    dso_a,
                ),
                0
            );
            assert_eq!(
                custom_cxa_atexit(Some(record), 2usize as *mut libc::c_void, dso_b),
                0
            );
            assert_eq!(
                custom_cxa_atexit(Some(record), 3usize as *mut libc::c_void, dso_a),
                0
            );

            custom_cxa_finalize(dso_a);
            custom_cxa_finalize(dso_a);
            custom_cxa_finalize(std::ptr::null_mut());
        }

        assert_eq!(*calls.lock().unwrap(), vec![3, 1, 2]);
    }

    #[test]
    fn thread_atexit_runs_callbacks_in_lifo_order_with_original_arguments() {
        use std::sync::{Arc, Mutex, OnceLock};

        static CALLS: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

        unsafe extern "C" fn record(arg: *mut libc::c_void) {
            CALLS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .unwrap()
                .push(arg as usize);
        }

        let calls = CALLS.get_or_init(|| Mutex::new(Vec::new()));
        calls.lock().unwrap().clear();
        let dso = 0xc001usize;
        let lease = Arc::new(LoadGroupLease::default());
        register_thread_atexit_dso(dso as *mut libc::c_void, &lease);

        std::thread::spawn(move || unsafe {
            assert_eq!(
                custom_cxa_thread_atexit_impl(
                    Some(record),
                    std::ptr::dangling_mut::<libc::c_void>(),
                    dso as *mut libc::c_void,
                ),
                0
            );
            assert_eq!(
                custom_cxa_thread_atexit_impl(
                    Some(record),
                    2usize as *mut libc::c_void,
                    dso as *mut libc::c_void,
                ),
                0
            );
        })
        .join()
        .unwrap();

        assert_eq!(*calls.lock().unwrap(), vec![2, 1]);
    }

    #[test]
    fn thread_atexit_callbacks_are_isolated_per_thread() {
        use std::sync::{mpsc, Arc, Mutex, OnceLock};

        static CALLS: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

        unsafe extern "C" fn record(arg: *mut libc::c_void) {
            CALLS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .unwrap()
                .push(arg as usize);
        }

        let calls = CALLS.get_or_init(|| Mutex::new(Vec::new()));
        calls.lock().unwrap().clear();
        let dso = 0xc002usize;
        let lease = Arc::new(LoadGroupLease::default());
        register_thread_atexit_dso(dso as *mut libc::c_void, &lease);
        let (registered_tx, registered_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();

        let first = std::thread::spawn(move || unsafe {
            assert_eq!(
                custom_cxa_thread_atexit_impl(
                    Some(record),
                    std::ptr::dangling_mut::<libc::c_void>(),
                    dso as *mut libc::c_void,
                ),
                0
            );
            registered_tx.send(()).unwrap();
            exit_rx.recv().unwrap();
        });
        registered_rx.recv().unwrap();

        std::thread::spawn(move || unsafe {
            assert_eq!(
                custom_cxa_thread_atexit_impl(
                    Some(record),
                    2usize as *mut libc::c_void,
                    dso as *mut libc::c_void,
                ),
                0
            );
        })
        .join()
        .unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![2]);

        exit_tx.send(()).unwrap();
        first.join().unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![2, 1]);
    }

    #[test]
    fn thread_atexit_rejects_invalid_or_unowned_registrations() {
        unsafe extern "C" fn ignore(_arg: *mut libc::c_void) {}

        unsafe {
            assert_ne!(
                custom_cxa_thread_atexit_impl(
                    None,
                    std::ptr::null_mut(),
                    std::ptr::dangling_mut::<libc::c_void>(),
                ),
                0
            );
            assert_ne!(
                custom_cxa_thread_atexit_impl(
                    Some(ignore),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                0
            );
            assert_ne!(
                custom_cxa_thread_atexit_impl(
                    Some(ignore),
                    std::ptr::null_mut(),
                    2usize as *mut libc::c_void,
                ),
                0
            );
        }
    }

    #[test]
    fn thread_atexit_accepts_dso_handle_inside_a_retained_mapping() {
        use std::sync::Arc;

        unsafe extern "C" fn ignore(_arg: *mut libc::c_void) {}

        let mut lease = LoadGroupLease::default();
        lease.mappings.push((0xd000, 0x1000));
        let lease = Arc::new(lease);
        register_thread_atexit_group(&lease);

        std::thread::spawn(|| unsafe {
            assert_eq!(
                custom_cxa_thread_atexit_impl(
                    Some(ignore),
                    std::ptr::null_mut(),
                    0xd800usize as *mut libc::c_void,
                ),
                0
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn pending_thread_destructor_keeps_load_group_alive_after_loader_release() {
        use std::sync::{mpsc, Arc};

        unsafe extern "C" fn ignore(_arg: *mut libc::c_void) {}

        let dso = 0xc003usize;
        let lease = Arc::new(LoadGroupLease::default());
        let weak = Arc::downgrade(&lease);
        register_thread_atexit_dso(dso as *mut libc::c_void, &lease);
        let mut loader = SoLoader {
            load_group: Some(Arc::clone(&lease)),
            ..Default::default()
        };
        let (registered_tx, registered_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();

        let thread = std::thread::spawn(move || unsafe {
            assert_eq!(
                custom_cxa_thread_atexit_impl(
                    Some(ignore),
                    std::ptr::null_mut(),
                    dso as *mut libc::c_void,
                ),
                0
            );
            registered_tx.send(()).unwrap();
            exit_rx.recv().unwrap();
        });
        registered_rx.recv().unwrap();
        drop(lease);
        loader.release_loaded_images(true);
        assert!(weak.upgrade().is_some());

        exit_tx.send(()).unwrap();
        thread.join().unwrap();
        assert!(weak.upgrade().is_none());
    }

    fn relocation_test_image() -> ElfImage {
        let bytes = synthetic_elf_with_relocations();
        ElfImage::parse_memory("relocs.so", &bytes, 0).unwrap()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn synthetic_elf_with_named_dynsym(symbol_name: &str, value: u64) -> Vec<u8> {
        synthetic_elf_with_named_dynsym_info(symbol_name, value, 0x12)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn synthetic_elf_with_named_dynsym_info(symbol_name: &str, value: u64, info: u8) -> Vec<u8> {
        const EHDR_SIZE: usize = 64;
        const PHDR_SIZE: usize = 56;
        const SYM_SIZE: usize = 24;
        const DYN_SIZE: usize = 16;

        const DT_HASH: i64 = 4;
        const DT_STRTAB: i64 = 5;
        const DT_SYMTAB: i64 = 6;
        const DT_STRSZ: i64 = 10;
        const DT_SYMENT: i64 = 11;

        let phoff = EHDR_SIZE;
        let dynsym_off = align(phoff + (PHDR_SIZE * 2), 8);
        let mut dynstr = vec![0u8];
        let symbol_name_offset = dynstr.len() as u32;
        dynstr.extend_from_slice(symbol_name.as_bytes());
        dynstr.push(0);
        let dynstr_off = align(dynsym_off + (SYM_SIZE * 2), 8);
        let hash_off = align(dynstr_off + dynstr.len(), 8);
        let dynamic_off = align(hash_off + 16, 8);
        let dynamic_count = 6;
        let size = align(dynamic_off + (DYN_SIZE * dynamic_count), 8);

        let mut bytes = vec![0u8; size];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 3);
        put_u16(&mut bytes, 18, goblin::elf::header::EM_AARCH64);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, phoff as u64);
        put_u16(&mut bytes, 52, EHDR_SIZE as u16);
        put_u16(&mut bytes, 54, PHDR_SIZE as u16);
        put_u16(&mut bytes, 56, 2);
        put_u16(&mut bytes, 58, 64);

        put_sym(
            &mut bytes,
            dynsym_off + SYM_SIZE,
            symbol_name_offset,
            info,
            1,
            value,
            16,
        );
        bytes[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);
        put_u32(&mut bytes, hash_off, 1);
        put_u32(&mut bytes, hash_off + 4, 2);
        put_u32(&mut bytes, hash_off + 8, 1);
        put_u32(&mut bytes, hash_off + 12, 0);

        put_phdr(&mut bytes, phoff, 1, 6, 0, 0, size as u64, size as u64, 8);
        put_phdr(
            &mut bytes,
            phoff + PHDR_SIZE,
            2,
            4,
            dynamic_off as u64,
            dynamic_off as u64,
            (DYN_SIZE * dynamic_count) as u64,
            (DYN_SIZE * dynamic_count) as u64,
            8,
        );

        let mut dyn_cursor = dynamic_off;
        for (tag, value) in [
            (DT_STRTAB, dynstr_off as u64),
            (DT_STRSZ, dynstr.len() as u64),
            (DT_SYMTAB, dynsym_off as u64),
            (DT_SYMENT, SYM_SIZE as u64),
            (DT_HASH, hash_off as u64),
            (0, 0),
        ] {
            put_dyn(&mut bytes, dyn_cursor, tag, value);
            dyn_cursor += DYN_SIZE;
        }

        bytes
    }

    fn synthetic_elf_with_relocations() -> Vec<u8> {
        const EHDR_SIZE: usize = 64;
        const PHDR_SIZE: usize = 56;
        const SYM_SIZE: usize = 24;
        const DYN_SIZE: usize = 16;
        const REL_SIZE: usize = 16;
        const RELA_SIZE: usize = 24;

        const DT_PLTRELSZ: i64 = 2;
        const DT_STRTAB: i64 = 5;
        const DT_SYMTAB: i64 = 6;
        const DT_RELA: i64 = 7;
        const DT_RELASZ: i64 = 8;
        const DT_RELAENT: i64 = 9;
        const DT_STRSZ: i64 = 10;
        const DT_SYMENT: i64 = 11;
        const DT_REL: i64 = 17;
        const DT_RELSZ: i64 = 18;
        const DT_RELENT: i64 = 19;
        const DT_PLTREL: i64 = 20;
        const DT_JMPREL: i64 = 23;
        const DT_RELRSZ: i64 = 35;
        const DT_RELR: i64 = 36;
        const DT_RELRENT: i64 = 37;
        const DT_ANDROID_RELA: i64 = 0x6000_0011;
        const DT_ANDROID_RELASZ: i64 = 0x6000_0012;

        let phoff = EHDR_SIZE;
        let dynsym_off = align(phoff + (PHDR_SIZE * 2), 8);
        let dynstr = b"\0reloc_symbol\0";
        let dynstr_off = align(dynsym_off + (SYM_SIZE * 2), 8);
        let rela_off = align(dynstr_off + dynstr.len(), 8);
        let rel_off = align(rela_off + RELA_SIZE, 8);
        let plt_off = align(rel_off + REL_SIZE, 8);
        let relr_off = align(plt_off + RELA_SIZE, 8);
        let mut android = b"APS2".to_vec();
        push_sleb(&mut android, 2);
        push_sleb(&mut android, 0x600);
        push_sleb(&mut android, 2);
        push_sleb(
            &mut android,
            (crate::soloader::reloc::RELOCATION_GROUPED_BY_INFO
                | crate::soloader::reloc::RELOCATION_GROUPED_BY_OFFSET_DELTA
                | crate::soloader::reloc::RELOCATION_GROUPED_BY_ADDEND
                | crate::soloader::reloc::RELOCATION_GROUP_HAS_ADDEND) as i64,
        );
        push_sleb(&mut android, 8);
        push_sleb(&mut android, 8);
        push_sleb(&mut android, 3);
        push_sleb(&mut android, 4);
        let android_off = align(relr_off + 16, 8);
        let dynamic_off = align(android_off + android.len(), 8);
        let dynamic_count = 19;
        let size = align(dynamic_off + (DYN_SIZE * dynamic_count), 8);

        let mut bytes = vec![0u8; size];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 3);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, phoff as u64);
        put_u16(&mut bytes, 52, EHDR_SIZE as u16);
        put_u16(&mut bytes, 54, PHDR_SIZE as u16);
        put_u16(&mut bytes, 56, 2);
        put_u16(&mut bytes, 58, 64);

        put_sym(&mut bytes, dynsym_off + SYM_SIZE, 1, 0x12, 1, 0x700, 16);
        bytes[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr);
        put_rela(&mut bytes, rela_off, 0x300, 1, 1, 7);
        put_rel(&mut bytes, rel_off, 0x318, 1, 6);
        put_rela(&mut bytes, plt_off, 0x330, 1, 7, 11);
        put_u64(&mut bytes, relr_off, 0x500);
        put_u64(&mut bytes, relr_off + 8, 0b11);
        bytes[android_off..android_off + android.len()].copy_from_slice(&android);

        put_phdr(&mut bytes, phoff, 1, 6, 0, 0, size as u64, size as u64, 8);
        put_phdr(
            &mut bytes,
            phoff + PHDR_SIZE,
            2,
            4,
            dynamic_off as u64,
            dynamic_off as u64,
            (DYN_SIZE * dynamic_count) as u64,
            (DYN_SIZE * dynamic_count) as u64,
            8,
        );

        let mut dyn_cursor = dynamic_off;
        for (tag, value) in [
            (DT_STRTAB, dynstr_off as u64),
            (DT_STRSZ, dynstr.len() as u64),
            (DT_SYMTAB, dynsym_off as u64),
            (DT_SYMENT, SYM_SIZE as u64),
            (DT_RELA, rela_off as u64),
            (DT_RELASZ, RELA_SIZE as u64),
            (DT_RELAENT, RELA_SIZE as u64),
            (DT_REL, rel_off as u64),
            (DT_RELSZ, REL_SIZE as u64),
            (DT_RELENT, REL_SIZE as u64),
            (DT_JMPREL, plt_off as u64),
            (DT_PLTRELSZ, RELA_SIZE as u64),
            (DT_PLTREL, DT_RELA as u64),
            (DT_RELR, relr_off as u64),
            (DT_RELRSZ, 16),
            (DT_RELRENT, 8),
            (DT_ANDROID_RELA, android_off as u64),
            (DT_ANDROID_RELASZ, android.len() as u64),
            (0, 0),
        ] {
            put_dyn(&mut bytes, dyn_cursor, tag, value);
            dyn_cursor += DYN_SIZE;
        }

        bytes
    }

    fn align(value: usize, alignment: usize) -> usize {
        (value + alignment - 1) & !(alignment - 1)
    }

    fn push_sleb(bytes: &mut Vec<u8>, mut value: i64) {
        loop {
            let byte = (value as u8) & 0x7f;
            value >>= 7;
            let done = (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0);
            bytes.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn put_phdr(
        bytes: &mut [u8],
        offset: usize,
        p_type: u32,
        flags: u32,
        file_off: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) {
        put_u32(bytes, offset, p_type);
        put_u32(bytes, offset + 4, flags);
        put_u64(bytes, offset + 8, file_off);
        put_u64(bytes, offset + 16, vaddr);
        put_u64(bytes, offset + 32, filesz);
        put_u64(bytes, offset + 40, memsz);
        put_u64(bytes, offset + 48, align);
    }

    fn put_sym(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        info: u8,
        shndx: u16,
        value: u64,
        size: u64,
    ) {
        put_u32(bytes, offset, name);
        bytes[offset + 4] = info;
        put_u16(bytes, offset + 6, shndx);
        put_u64(bytes, offset + 8, value);
        put_u64(bytes, offset + 16, size);
    }

    fn put_dyn(bytes: &mut [u8], offset: usize, tag: i64, value: u64) {
        put_u64(bytes, offset, tag as u64);
        put_u64(bytes, offset + 8, value);
    }

    fn put_rel(bytes: &mut [u8], offset: usize, r_offset: u64, sym_idx: u64, kind: u64) {
        put_u64(bytes, offset, r_offset);
        put_u64(bytes, offset + 8, (sym_idx << 32) | kind);
    }

    fn put_rela(
        bytes: &mut [u8],
        offset: usize,
        r_offset: u64,
        sym_idx: u64,
        kind: u64,
        addend: i64,
    ) {
        put_rel(bytes, offset, r_offset, sym_idx, kind);
        put_u64(bytes, offset + 16, addend as u64);
    }

    fn read_word(bytes: &[u8], offset: usize) -> usize {
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_le_bytes(array) as usize
    }

    fn write_word(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 8].copy_from_slice(&(value as u64).to_le_bytes());
    }
}
