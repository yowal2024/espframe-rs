//! Startup public material for the kernel type-7 proxy.
//!
//! SET arms the proxy before UDP sockets start and returns an owned generation.
//! BIND later supplies the notification token and K0. The kernel selects sockets
//! with is_black_user and learns their peer; neither UID nor endpoint is supplied.

/// Public certificate and trust root copied synchronously by SET.
/// The certificate contains curve public32, ACK public32 and root signature64.
#[derive(Clone, Copy)]
pub struct Type7ProxyConfig<'a> {
    pub certificate: &'a [u8; 128],
    pub root: &'a [u8; 32],
}

pub(super) fn generation(value: u64) -> Result<usize, isize> {
    if value == 0 || value > isize::MAX as u64 {
        Err(-22)
    } else {
        Ok(value as usize)
    }
}

pub(super) fn status(result: isize) -> Result<(), isize> {
    match result {
        0 => Ok(()),
        error if error < 0 => Err(error),
        _ => Err(-71),
    }
}
