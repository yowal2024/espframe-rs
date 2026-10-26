use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

pub const MAX_TLS_MODULES: usize = 128;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TlsIndex {
    pub module: usize,
    pub offset: usize,
}

#[derive(Debug, Clone)]
struct TlsModule {
    init_image: Vec<u8>,
    mem_size: usize,
    align: usize,
}

#[derive(Debug, Default)]
struct TlsState {
    modules: Vec<Option<TlsModule>>,
    incarnations: Vec<usize>,
    generation: usize,
}

#[derive(Debug)]
pub struct TlsRegistry {
    id: usize,
    state: Mutex<TlsState>,
}

thread_local! {
    static THREAD_TLS_BLOCKS: RefCell<HashMap<(usize, usize), ThreadTlsBlock>> = RefCell::new(HashMap::new());
}

static GLOBAL_TLS_REGISTRY: OnceLock<TlsRegistry> = OnceLock::new();
static NEXT_TLS_REGISTRY_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug)]
struct ThreadTlsBlock {
    module_generation: usize,
    bytes: TlsBlock,
}

#[derive(Debug)]
struct TlsBlock {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl TlsBlock {
    fn new(module: &TlsModule) -> Option<Self> {
        let layout = Layout::from_size_align(module.mem_size, module.align).ok()?;
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                module.init_image.as_ptr(),
                ptr.as_ptr(),
                module.init_image.len(),
            );
        }
        Some(Self { ptr, layout })
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for TlsBlock {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

impl Default for TlsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsRegistry {
    pub fn new() -> Self {
        Self {
            id: NEXT_TLS_REGISTRY_ID.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(TlsState {
                modules: vec![None; MAX_TLS_MODULES],
                incarnations: vec![0; MAX_TLS_MODULES],
                generation: 0,
            }),
        }
    }

    pub fn register_module(
        &self,
        init_image: &[u8],
        mem_size: usize,
        align: usize,
    ) -> Option<usize> {
        let align = align.max(1);
        if mem_size == 0 || init_image.len() > mem_size || !align.is_power_of_two() {
            return None;
        }

        let mut state = lock_state(&self.state);
        let module_id = (1..MAX_TLS_MODULES).find(|&idx| state.modules[idx].is_none())?;
        state.modules[module_id] = Some(TlsModule {
            init_image: init_image.to_vec(),
            mem_size,
            align,
        });
        state.incarnations[module_id] = state.incarnations[module_id].saturating_add(1);
        state.generation = state.generation.saturating_add(1);

        Some(module_id)
    }

    pub fn unregister_module(&self, module_id: usize) {
        if module_id == 0 || module_id >= MAX_TLS_MODULES {
            return;
        }

        let mut state = lock_state(&self.state);
        if state.modules[module_id].take().is_some() {
            state.incarnations[module_id] = state.incarnations[module_id].saturating_add(1);
            state.generation = state.generation.saturating_add(1);
        }
    }

    pub fn get_addr(&self, index: TlsIndex) -> Option<*mut u8> {
        if index.module == 0 || index.module >= MAX_TLS_MODULES {
            return None;
        }

        let (module, incarnation) = {
            let state = lock_state(&self.state);
            let module = state.modules[index.module].clone()?;
            if index.offset >= module.mem_size {
                return None;
            }
            (module, state.incarnations[index.module])
        };

        THREAD_TLS_BLOCKS.with(|blocks| {
            let mut blocks = blocks.borrow_mut();
            let key = (self.id, index.module);
            let needs_refresh = blocks
                .get(&key)
                .is_none_or(|block| block.module_generation != incarnation);
            if needs_refresh {
                blocks.insert(
                    key,
                    ThreadTlsBlock {
                        module_generation: incarnation,
                        bytes: allocate_module_tls(&module)?,
                    },
                );
            }
            let block = blocks.get_mut(&key)?;

            Some(unsafe { block.bytes.as_mut_ptr().add(index.offset) })
        })
    }

    pub fn deinit(&self) {
        let mut state = lock_state(&self.state);
        state.modules.fill(None);
        state.generation = state.generation.saturating_add(1);
        THREAD_TLS_BLOCKS.with(|blocks| blocks.borrow_mut().retain(|(id, _), _| *id != self.id));
    }
}

pub fn global_tls_registry() -> &'static TlsRegistry {
    GLOBAL_TLS_REGISTRY.get_or_init(TlsRegistry::new)
}

/// Resolve a TLS descriptor for the current thread.
///
/// # Safety
/// `index` must be null or point to a readable `TlsIndex` for the duration of
/// this call.
pub unsafe extern "C" fn tls_get_addr(index: *const TlsIndex) -> *mut libc::c_void {
    if index.is_null() {
        return std::ptr::null_mut();
    }

    let index = unsafe { *index };
    global_tls_registry()
        .get_addr(index)
        .map_or(std::ptr::null_mut(), |addr| addr.cast())
}

fn allocate_module_tls(module: &TlsModule) -> Option<TlsBlock> {
    TlsBlock::new(module)
}

fn lock_state(state: &Mutex<TlsState>) -> MutexGuard<'_, TlsState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
