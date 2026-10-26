use crate::soloader::deps::basename;
use crate::soloader::elf::{ArrayInfo, ElfImage};
use crate::soloader::error::{LoaderError, Result};

pub trait LibraryView {
    fn name(&self) -> &str;
    fn needed_libraries(&self) -> &[String];
    fn symbol_address(&self, name: &str) -> Option<usize>;
    fn exported_symbol_address(&self, name: &str) -> Option<usize>;
    fn is_manual_load(&self) -> bool;
}

pub struct RuntimeGraph {
    main: Box<dyn LibraryView>,
    dependencies: Vec<Box<dyn LibraryView>>,
}

impl RuntimeGraph {
    pub fn new(main: Box<dyn LibraryView>) -> Self {
        Self {
            main,
            dependencies: Vec::new(),
        }
    }

    pub fn add_dependency(&mut self, dependency: Box<dyn LibraryView>) {
        self.dependencies.push(dependency);
    }

    pub fn resolve_symbol(&self, requester: Option<&str>, name: &str) -> Option<usize> {
        if let Some(requester_name) = requester {
            if same_library_name(self.main.name(), requester_name) {
                if let Some(addr) = self.main.symbol_address(name) {
                    return Some(addr);
                }
            } else if let Some(dep) = self
                .dependencies
                .iter()
                .find(|dep| same_library_name(dep.name(), requester_name))
            {
                if let Some(addr) = dep.symbol_address(name) {
                    return Some(addr);
                }
            }
        }

        if requester
            .is_none_or(|requester_name| !same_library_name(self.main.name(), requester_name))
        {
            if let Some(addr) = self.main.exported_symbol_address(name) {
                return Some(addr);
            }
        }

        self.dependencies
            .iter()
            .filter(|dep| {
                requester
                    .is_none_or(|requester_name| !same_library_name(dep.name(), requester_name))
            })
            .find_map(|dep| dep.exported_symbol_address(name))
    }

    pub fn manual_constructor_order(&self) -> Vec<String> {
        let mut state = vec![0u8; self.dependencies.len()];
        let mut order = Vec::new();

        for index in 0..self.dependencies.len() {
            self.visit_manual_constructor(index, &mut state, &mut order);
        }

        order
    }

    fn visit_manual_constructor(&self, index: usize, state: &mut [u8], order: &mut Vec<String>) {
        let dep = &self.dependencies[index];
        if !dep.is_manual_load() {
            return;
        }
        if state[index] != 0 {
            return;
        }

        state[index] = 1;
        for needed in dep.needed_libraries() {
            if needed == "ld-android.so" {
                continue;
            }
            if let Some(dep_index) = self
                .dependencies
                .iter()
                .position(|candidate| same_library_name(candidate.name(), needed))
            {
                self.visit_manual_constructor(dep_index, state, order);
            }
        }

        order.push(dep.name().to_owned());
        state[index] = 2;
    }
}

impl LibraryView for ElfImage {
    fn name(&self) -> &str {
        self.name()
    }

    fn needed_libraries(&self) -> &[String] {
        self.needed_libraries()
    }

    fn symbol_address(&self, name: &str) -> Option<usize> {
        self.symbol_address(name)
    }

    fn exported_symbol_address(&self, name: &str) -> Option<usize> {
        self.exported_symbol_address(name)
    }

    fn is_manual_load(&self) -> bool {
        true
    }
}

pub fn constructor_addresses(
    init: Option<usize>,
    init_array: Option<ArrayInfo>,
    mut read_word: impl FnMut(usize) -> Option<usize>,
) -> Result<Vec<usize>> {
    let mut addresses = Vec::new();
    if let Some(init) = init {
        addresses.push(init);
    }

    if let Some(array) = init_array {
        for index in 0..array.count {
            let entry_address = array
                .address
                .checked_add(index.saturating_mul(core::mem::size_of::<usize>()))
                .ok_or_else(|| LoaderError::Link("init_array address overflow".into()))?;
            if let Some(function) = read_word(entry_address) {
                if function != 0 {
                    addresses.push(function);
                }
            }
        }
    }

    Ok(addresses)
}

pub fn destructor_addresses(
    fini_array: Option<ArrayInfo>,
    fini: Option<usize>,
    mut read_word: impl FnMut(usize) -> Option<usize>,
) -> Result<Vec<usize>> {
    let mut addresses = Vec::new();

    if let Some(array) = fini_array {
        for index in (0..array.count).rev() {
            let entry_address = array
                .address
                .checked_add(index.saturating_mul(core::mem::size_of::<usize>()))
                .ok_or_else(|| LoaderError::Link("fini_array address overflow".into()))?;
            if let Some(function) = read_word(entry_address) {
                if function != 0 {
                    addresses.push(function);
                }
            }
        }
    }

    if let Some(fini) = fini {
        addresses.push(fini);
    }

    Ok(addresses)
}

fn same_library_name(left: &str, right: &str) -> bool {
    left == right || basename(left) == basename(right)
}
