use espframe::jni::values::{checked_byte_array_len, from_raw, path_from};
use espframe::jni::{resolve_app_class, JniClassResolver};
use std::path::Path;

struct FakeResolver {
    calls: Vec<String>,
    direct: bool,
    loader: bool,
    loaded_class: bool,
}

impl Default for FakeResolver {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            direct: false,
            loader: true,
            loaded_class: true,
        }
    }
}

impl JniClassResolver for FakeResolver {
    type Class = u8;
    type Thread = u8;
    type Loader = u8;
    type Error = &'static str;

    fn find_class(&mut self, name: &str) -> Result<Option<u8>, Self::Error> {
        self.calls.push(format!("FindClass({name})"));
        Ok(if name == "java/lang/Thread" {
            Some(1)
        } else {
            self.direct.then_some(2)
        })
    }

    fn missing(&mut self, what: &'static str) -> Self::Error {
        what
    }

    fn clear_exception(&mut self) {
        self.calls.push("ExceptionClear".into());
    }

    fn current_thread(&mut self, class: &u8) -> Result<u8, Self::Error> {
        assert_eq!(*class, 1);
        self.calls.push("Thread.currentThread".into());
        Ok(3)
    }

    fn context_loader(&mut self, thread: &u8) -> Result<Option<u8>, Self::Error> {
        assert_eq!(*thread, 3);
        self.calls.push("Thread.getContextClassLoader".into());
        Ok(self.loader.then_some(4))
    }

    fn load_class(&mut self, loader: &u8, name: &str) -> Result<Option<u8>, Self::Error> {
        assert_eq!(*loader, 4);
        self.calls.push(format!("ClassLoader.loadClass({name})"));
        Ok(self.loaded_class.then_some(2))
    }
}

#[test]
fn resolver_uses_context_loader_after_clearing_find_class_exception() {
    let mut resolver = FakeResolver::default();
    assert_eq!(
        resolve_app_class(&mut resolver, "example/app/Natives"),
        Ok(2)
    );
    assert_eq!(
        resolver.calls,
        [
            "FindClass(example/app/Natives)",
            "ExceptionClear",
            "FindClass(java/lang/Thread)",
            "Thread.currentThread",
            "Thread.getContextClassLoader",
            "ClassLoader.loadClass(example.app.Natives)",
        ]
    );
}

#[test]
fn resolver_does_not_use_fallback_when_class_is_found_directly() {
    let mut resolver = FakeResolver {
        direct: true,
        ..Default::default()
    };
    assert_eq!(resolve_app_class(&mut resolver, "example/Natives"), Ok(2));
    assert_eq!(resolver.calls, ["FindClass(example/Natives)"]);
}

#[test]
fn resolver_rejects_a_missing_context_loader() {
    let mut resolver = FakeResolver {
        loader: false,
        ..Default::default()
    };
    assert_eq!(
        resolve_app_class(&mut resolver, "example/Natives"),
        Err("context class loader")
    );
    assert_eq!(
        resolver.calls.last().unwrap(),
        "Thread.getContextClassLoader"
    );
}

#[test]
fn resolver_rejects_a_null_loaded_class() {
    let mut resolver = FakeResolver {
        loaded_class: false,
        ..Default::default()
    };
    assert_eq!(
        resolve_app_class(&mut resolver, "example/Natives"),
        Err("loaded application class")
    );
}

#[test]
fn jni_value_helpers_fail_closed_for_null_invalid_and_oversize_inputs() {
    assert!(unsafe { from_raw(std::ptr::null_mut()) }.is_err());
    assert!(path_from(None).is_none());
    assert!(path_from(Some(String::new())).is_none());
    assert!(path_from(Some("bad\0path".to_owned())).is_none());
    assert_eq!(
        path_from(Some("valid/path".to_owned())).unwrap(),
        Path::new("valid/path")
    );
    assert_eq!(checked_byte_array_len(i32::MAX as usize), Some(i32::MAX));
    assert_eq!(checked_byte_array_len(i32::MAX as usize + 1), None);
}
