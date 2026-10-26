use super::{KernelDriver, KernelTransport};

#[cfg(target_os = "android")]
use std::os::unix::process::ExitStatusExt;

#[cfg(any(test, target_os = "android"))]
use std::ffi::CString;

pub trait RootShell {
    fn run(&mut self, command: &str) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRootShell;

impl RootShell for SystemRootShell {
    fn run(&mut self, command: &str) -> Result<(), String> {
        #[cfg(target_os = "android")]
        {
            let spec = shell_exec_spec(command)?;
            let mut argv = [
                spec.argv[0].as_ptr(),
                spec.argv[1].as_ptr(),
                spec.argv[2].as_ptr(),
                std::ptr::null(),
            ];
            let result = unsafe { libc::execv(spec.path.as_ptr(), argv.as_mut_ptr()) };
            if result < 0 {
                return Err(format!(
                    "root shell launch failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            unreachable!("execv only returns on failure");
        }

        #[cfg(not(target_os = "android"))]
        {
            let status = std::process::Command::new("/system/bin/sh")
                .arg("-c")
                .arg(command)
                .status()
                .map_err(|error| format!("root shell launch failed: {error}"))?;

            if status.success() {
                return Ok(());
            }

            let detail = status
                .code()
                .map(|code| format!("exit status {code}"))
                .unwrap_or_else(|| "terminated by signal".to_owned());
            Err(format!("root command failed: {detail}"))
        }
    }
}

pub fn run_root_command<T: KernelTransport>(
    driver: &KernelDriver<T>,
    shell: &mut impl RootShell,
    command: &str,
) -> Result<(), String> {
    if command.trim().is_empty() {
        return Err("root command is empty".to_owned());
    }
    run_root_command_impl(driver, shell, command)
}

#[cfg(not(target_os = "android"))]
fn run_root_command_impl<T: KernelTransport>(
    driver: &KernelDriver<T>,
    shell: &mut impl RootShell,
    command: &str,
) -> Result<(), String> {
    run_root_command_child(driver, shell, command)
}

#[cfg(target_os = "android")]
fn run_root_command_impl<T: KernelTransport>(
    driver: &KernelDriver<T>,
    _shell: &mut impl RootShell,
    command: &str,
) -> Result<(), String> {
    let spec = shell_exec_spec(command)?;
    let pipe_fds = make_cloexec_pipe()?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            let _ = libc::close(pipe_fds[0]);
            let _ = libc::close(pipe_fds[1]);
        }
        return Err(format!(
            "root command fork failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        unsafe {
            let _ = libc::close(pipe_fds[0]);
        }
        if let Err(message) =
            grant_su_raw_and_verify_euid(|| driver.GrantSuRaw(), || unsafe { libc::geteuid() })
        {
            let _ = write_all_fd(pipe_fds[1], message.as_bytes());
            unsafe {
                let _ = libc::close(pipe_fds[1]);
                libc::_exit(1);
            }
        }
        exec_shell_or_write_error(&spec, pipe_fds[1]);
    }

    unsafe {
        let _ = libc::close(pipe_fds[1]);
    }

    let mut status = 0;
    if waitpid_retry(
        |pid, status, options| {
            let result = unsafe { libc::waitpid(pid, status as *mut _, options) };
            if result < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(result)
            }
        },
        pid,
        &mut status,
    )
    .is_err()
    {
        unsafe {
            let _ = libc::close(pipe_fds[0]);
        }
        return Err(format!(
            "root command wait failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let message = read_fd(pipe_fds[0]).unwrap_or_default();
    unsafe {
        let _ = libc::close(pipe_fds[0]);
    }
    let status = std::process::ExitStatus::from_raw(status);
    if status.success() {
        Ok(())
    } else if !message.is_empty() {
        Err(message)
    } else {
        Err(match status.code() {
            Some(code) => format!("root command failed: exit status {code}"),
            None => "root command failed: terminated by signal".to_owned(),
        })
    }
}

#[cfg(target_os = "android")]
fn exec_shell_or_write_error(spec: &ShellExecSpec, error_fd: libc::c_int) -> ! {
    let mut argv = [
        spec.argv[0].as_ptr(),
        spec.argv[1].as_ptr(),
        spec.argv[2].as_ptr(),
        std::ptr::null(),
    ];

    unsafe {
        libc::execv(spec.path.as_ptr(), argv.as_mut_ptr());
        let _ = write_all_fd(error_fd, b"root shell launch failed");
        libc::_exit(127);
    }
}

#[cfg(not(target_os = "android"))]
fn run_root_command_child<T: KernelTransport>(
    driver: &KernelDriver<T>,
    shell: &mut impl RootShell,
    command: &str,
) -> Result<(), String> {
    driver.GrantSu()?;

    #[cfg(target_os = "android")]
    if unsafe { libc::geteuid() } != 0 {
        return Err("kernel grant SU did not elevate the child".to_owned());
    }

    shell.run(command)
}

#[cfg(target_os = "android")]
fn write_all_fd(fd: libc::c_int, mut bytes: &[u8]) -> Result<(), ()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(());
        }
        if written == 0 {
            return Err(());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn read_fd(fd: libc::c_int) -> Result<String, ()> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(());
        }
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "android")]
fn make_cloexec_pipe() -> Result<[libc::c_int; 2], String> {
    let mut pipe_fds = [0; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "root command pipe failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(pipe_fds)
}

#[cfg(any(test, target_os = "android"))]
struct ShellExecSpec {
    path: CString,
    argv: [CString; 3],
}

#[cfg(any(test, target_os = "android"))]
fn shell_exec_spec(command: &str) -> Result<ShellExecSpec, String> {
    Ok(ShellExecSpec {
        path: CString::new("/system/bin/sh")
            .map_err(|error| format!("invalid shell path: {error}"))?,
        argv: [
            CString::new("/system/bin/sh")
                .map_err(|error| format!("invalid shell argv[0]: {error}"))?,
            CString::new("-c").map_err(|error| format!("invalid shell argv[1]: {error}"))?,
            CString::new(command).map_err(|error| format!("invalid shell command: {error}"))?,
        ],
    })
}

#[cfg(any(test, target_os = "android"))]
fn waitpid_retry<F, P>(
    mut waitpid: F,
    pid: P,
    status: &mut libc::c_int,
) -> Result<P, std::io::Error>
where
    P: Copy,
    F: FnMut(P, &mut libc::c_int, libc::c_int) -> Result<P, std::io::Error>,
{
    loop {
        match waitpid(pid, status, 0) {
            Ok(result) => return Ok(result),
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(any(test, target_os = "android"))]
fn grant_su_raw_and_verify_euid<G, E>(mut grant_su_raw: G, geteuid: E) -> Result<(), &'static str>
where
    G: FnMut() -> isize,
    E: FnOnce() -> u32,
{
    if grant_su_raw() != 1 {
        return Err("kernel grant SU failed");
    }
    if geteuid() != 0 {
        return Err("kernel grant SU did not elevate the child");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::abi::CMD_GRANT_SU;
    use std::io;

    struct GrantTransport(isize);

    impl KernelTransport for GrantTransport {
        unsafe fn Invoke(
            &self,
            _scno: i32,
            _option: u64,
            command: usize,
            _args: [usize; 5],
        ) -> isize {
            assert_eq!(command, CMD_GRANT_SU);
            self.0
        }
    }

    #[test]
    fn shell_exec_spec_uses_an_explicit_system_bin_sh_argv() {
        let spec = shell_exec_spec("id -u").unwrap();

        assert_eq!(spec.path.as_c_str(), c"/system/bin/sh");
        assert_eq!(spec.argv[0].as_c_str(), c"/system/bin/sh");
        assert_eq!(spec.argv[1].as_c_str(), c"-c");
        assert_eq!(spec.argv[2].as_c_str(), c"id -u");
    }

    #[test]
    fn waitpid_retry_retries_eintr_before_returning_success() {
        let mut attempts = 0;
        let mut status = 0;

        let pid = waitpid_retry(
            |_, _, _| {
                attempts += 1;
                if attempts == 1 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(313)
                }
            },
            99,
            &mut status,
        )
        .unwrap();

        assert_eq!(pid, 313);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn grant_su_raw_returns_the_driver_result_code() {
        let success_driver = KernelDriver::new(19, 7, 42, GrantTransport(1));
        assert_eq!(success_driver.GrantSuRaw(), 1);

        let failure_driver = KernelDriver::new(19, 7, 42, GrantTransport(-1));
        assert_eq!(failure_driver.GrantSuRaw(), -1);
    }

    #[test]
    fn grant_su_raw_and_verify_euid_rejects_non_root_children() {
        let result = grant_su_raw_and_verify_euid(|| 1, || 1000);
        assert_eq!(result, Err("kernel grant SU did not elevate the child"));
    }

    #[test]
    fn grant_su_raw_and_verify_euid_accepts_root_children() {
        let result = grant_su_raw_and_verify_euid(|| 1, || 0);
        assert_eq!(result, Ok(()));
    }

    #[cfg(target_os = "android")]
    #[test]
    fn cloexec_pipe_marks_both_ends_close_on_exec() {
        let pipe_fds = make_cloexec_pipe().unwrap();
        for fd in pipe_fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_ne!(flags, -1);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
            unsafe {
                let _ = libc::close(fd);
            }
        }
    }
}
