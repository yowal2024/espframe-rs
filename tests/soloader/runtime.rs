use espframe::soloader::runtime::{LibraryView, RuntimeGraph};

#[derive(Clone)]
struct FakeLibrary {
    name: String,
    needed: Vec<String>,
    symbols: Vec<(String, usize)>,
    manual: bool,
}

impl FakeLibrary {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            needed: Vec::new(),
            symbols: Vec::new(),
            manual: true,
        }
    }

    fn needs(mut self, libs: &[&str]) -> Self {
        self.needed = libs.iter().map(|lib| (*lib).to_owned()).collect();
        self
    }

    fn symbol(mut self, name: &str, address: usize) -> Self {
        self.symbols.push((name.to_owned(), address));
        self
    }

    fn manual(mut self, manual: bool) -> Self {
        self.manual = manual;
        self
    }
}

impl LibraryView for FakeLibrary {
    fn name(&self) -> &str {
        &self.name
    }

    fn needed_libraries(&self) -> &[String] {
        &self.needed
    }

    fn symbol_address(&self, name: &str) -> Option<usize> {
        self.symbols
            .iter()
            .find(|(symbol, _)| symbol == name)
            .map(|(_, address)| *address)
    }

    fn exported_symbol_address(&self, name: &str) -> Option<usize> {
        self.symbol_address(name)
    }

    fn is_manual_load(&self) -> bool {
        self.manual
    }
}

#[test]
fn resolve_symbol_prefers_requester_then_main_then_dependencies() {
    let mut graph = RuntimeGraph::new(Box::new(
        FakeLibrary::new("main.so")
            .symbol("shared", 0x1000)
            .symbol("main_only", 0x1100),
    ));
    graph.add_dependency(Box::new(
        FakeLibrary::new("libdep.so")
            .symbol("shared", 0x2000)
            .symbol("dep_only", 0x2100),
    ));

    assert_eq!(graph.resolve_symbol(None, "shared"), Some(0x1000));
    assert_eq!(
        graph.resolve_symbol(Some("libdep.so"), "shared"),
        Some(0x2000)
    );
    assert_eq!(
        graph.resolve_symbol(Some("libdep.so"), "main_only"),
        Some(0x1100)
    );
    assert_eq!(
        graph.resolve_symbol(Some("main.so"), "dep_only"),
        Some(0x2100)
    );
}

#[test]
fn manual_constructor_order_walks_dependencies_depth_first() {
    let mut graph = RuntimeGraph::new(Box::new(
        FakeLibrary::new("main.so").needs(&["liba.so", "libb.so"]),
    ));
    graph.add_dependency(Box::new(FakeLibrary::new("liba.so").needs(&["libc.so"])));
    graph.add_dependency(Box::new(FakeLibrary::new("libb.so").needs(&["libc.so"])));
    graph.add_dependency(Box::new(FakeLibrary::new("libc.so")));

    assert_eq!(
        graph.manual_constructor_order(),
        vec!["libc.so", "liba.so", "libb.so"]
    );
}

#[test]
fn manual_constructor_order_skips_host_loaded_dependencies() {
    let mut graph = RuntimeGraph::new(Box::new(FakeLibrary::new("main.so")));
    graph.add_dependency(Box::new(FakeLibrary::new("libhost.so").manual(false)));
    graph.add_dependency(Box::new(FakeLibrary::new("libmanual.so")));

    assert_eq!(graph.manual_constructor_order(), vec!["libmanual.so"]);
}
