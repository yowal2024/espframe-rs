use std::path::{Path, PathBuf};

pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

pub fn find_library_path(lib_name: &str, roots: &[impl AsRef<Path>]) -> Option<PathBuf> {
    for root in roots {
        let candidate = root.as_ref().join(lib_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) enum LibrarySearchSource {
    Origin,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct LibrarySearchMatch {
    pub(crate) path: PathBuf,
    pub(crate) source: LibrarySearchSource,
}

#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn find_library_path_with_source(
    lib_name: &str,
    origin_dir: Option<&Path>,
    system_roots: &[impl AsRef<Path>],
) -> Option<LibrarySearchMatch> {
    if let Some(origin_dir) = origin_dir {
        if !origin_dir.as_os_str().is_empty() {
            let candidate = origin_dir.join(lib_name);
            if candidate.is_file() {
                return Some(LibrarySearchMatch {
                    path: candidate,
                    source: LibrarySearchSource::Origin,
                });
            }
        }
    }

    for root in system_roots {
        let candidate = root.as_ref().join(lib_name);
        if candidate.is_file() {
            return Some(LibrarySearchMatch {
                path: candidate,
                source: LibrarySearchSource::System,
            });
        }
    }

    None
}

pub fn library_search_roots(origin_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots =
        Vec::with_capacity(system_library_search_roots().len() + usize::from(origin_dir.is_some()));

    if let Some(origin_dir) = origin_dir {
        if !origin_dir.as_os_str().is_empty() {
            roots.push(origin_dir.to_path_buf());
        }
    }

    roots.extend(system_library_search_roots().iter().map(PathBuf::from));
    roots
}

pub fn enqueue_needed_libraries(queue: &mut Vec<String>, needed_libraries: &[String]) {
    for needed in needed_libraries {
        if basename(needed) == "ld-android.so" {
            continue;
        }
        if queue
            .iter()
            .any(|queued| basename(queued) == basename(needed))
        {
            continue;
        }
        queue.push(basename(needed).to_owned());
    }
}

pub fn system_library_search_roots() -> &'static [&'static str] {
    #[cfg(all(unix, target_pointer_width = "64"))]
    {
        &[
            "/apex/com.android.tethering/lib64/",
            "/apex/com.android.runtime/lib64/bionic/",
            "/apex/com.android.runtime/lib64/",
            "/apex/com.android.os.statsd/lib64/",
            "/apex/com.android.i18n/lib64/",
            "/apex/com.android.art/lib64/",
            "/system/lib64/",
            "/vendor/lib64/",
            "/lib64/",
            "/usr/lib64/",
            "/lib/x86_64-linux-gnu/",
            "/usr/lib/x86_64-linux-gnu/",
            "/usr/local/lib/",
        ]
    }

    #[cfg(all(unix, target_pointer_width = "32"))]
    {
        &[
            "/apex/com.android.tethering/lib/",
            "/apex/com.android.runtime/lib/bionic/",
            "/apex/com.android.runtime/lib/",
            "/apex/com.android.os.statsd/lib/",
            "/apex/com.android.i18n/lib/",
            "/apex/com.android.art/lib/",
            "/system/lib/",
            "/vendor/lib/",
            "/lib/",
            "/usr/lib/",
            "/lib/i386-linux-gnu/",
            "/usr/local/lib/",
        ]
    }

    #[cfg(not(unix))]
    {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn library_search_roots_prefers_origin_before_system_roots() {
        let origin = Path::new("/tmp/soloader-origin");

        let roots = library_search_roots(Some(origin));
        let system_roots = system_library_search_roots()
            .iter()
            .map(Path::new)
            .collect::<Vec<_>>();

        assert_eq!(roots.first().map(PathBuf::as_path), Some(origin));
        assert_eq!(roots.len(), system_library_search_roots().len() + 1);
        assert_eq!(
            roots
                .iter()
                .skip(1)
                .map(PathBuf::as_path)
                .collect::<Vec<_>>(),
            system_roots
        );
    }

    #[test]
    fn find_library_path_with_source_marks_origin_match() {
        let temp = std::env::temp_dir().join("soloader-deps-source-test");
        let origin = temp.join("origin");
        let system = temp.join("system");
        let origin_lib = origin.join("libdemo.so");
        let system_lib = system.join("libdemo.so");
        fs::create_dir_all(&origin).unwrap();
        fs::create_dir_all(&system).unwrap();
        fs::write(&origin_lib, b"origin").unwrap();
        fs::write(&system_lib, b"system").unwrap();

        let found = find_library_path_with_source("libdemo.so", Some(&origin), &[system]).unwrap();

        assert_eq!(found.path, origin_lib);
        assert_eq!(found.source, LibrarySearchSource::Origin);

        let _ = fs::remove_dir_all(&temp);
    }
}
