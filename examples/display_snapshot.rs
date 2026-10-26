#[cfg(target_os = "android")]
fn main() {
    if let Err(error) = run() {
        eprintln!("display query failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "android")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|arg| arg != "--uid-1000" && arg != "--primary")
    {
        return Err("usage: display_snapshot [--uid-1000] [--primary]".into());
    }
    let uid_1000 = arguments.iter().any(|arg| arg == "--uid-1000");
    let primary = arguments.iter().any(|arg| arg == "--primary");
    if uid_1000 {
        if unsafe { libc::geteuid() } != 0 {
            return Err("--uid-1000 requires an existing root shell".into());
        }
        // Drop identity before opening Binder so the connection uses the test UID.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(format!("setgroups: {}", std::io::Error::last_os_error()).into());
        }
        if unsafe { libc::setresgid(1000, 1000, 1000) } != 0 {
            return Err(format!("setresgid: {}", std::io::Error::last_os_error()).into());
        }
        if unsafe { libc::setresuid(1000, 1000, 1000) } != 0 {
            return Err(format!("setresuid: {}", std::io::Error::last_os_error()).into());
        }
    }

    let status = std::fs::read_to_string("/proc/self/status")?;
    for label in ["Uid:", "Gid:", "Groups:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .ok_or("missing process identity field")?
            .trim();
        println!("{label} {value}");
        if uid_1000 {
            let valid = match label {
                "Uid:" | "Gid:" => {
                    let ids: Vec<_> = value.split_whitespace().collect();
                    ids.len() == 4 && ids.iter().all(|id| *id == "1000")
                }
                "Groups:" => value.is_empty(),
                _ => u64::from_str_radix(value, 16) == Ok(0),
            };
            if !valid {
                return Err("UID 1000 identity or capability verification failed".into());
            }
        }
    }
    let context = std::fs::read_to_string("/proc/self/attr/current")?;
    println!("selinux={}", context.trim_matches(['\0', '\n', '\r']));
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let java_runtime_mapped = ["libart.so", "libnativehelper.so", "libandroid_runtime.so"]
        .iter()
        .any(|library| maps.lines().any(|line| line.ends_with(library)));
    println!("java_runtime_mapped={java_runtime_mapped}");

    if primary {
        let mut query = espframe::window::surface::PrimaryDisplayQuery::resolve()?;
        for _ in 0..3 {
            let info = query.query()?;
            let size = info.oriented_size();
            println!(
                "primary natural={}x{} logical={}x{} rotation={:?}",
                info.physical_width,
                info.physical_height,
                size.width,
                size.height,
                info.orientation
            );
        }
        return Ok(());
    }
    for display in espframe::window::query_displays_native()? {
        println!(
            "id={} stack={} logical={}x{} rotation={:?}",
            display.display_id,
            display.layer_stack,
            display.size.width,
            display.size.height,
            display.orientation
        );
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!("display_snapshot requires Android 12-16");
    std::process::exit(1);
}
