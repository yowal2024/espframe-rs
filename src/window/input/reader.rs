//! 沿用 main 的单事件缓冲：read 非零时处理缓冲，错误时复用上一次内容。

use super::{InputEvent, KernelInputParser, KernelInputValue, WindowError};
use std::io;

pub(super) trait InputSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

pub(super) struct KernelInputReader {
    // 对应 main 在 while 外初始化的 kernel_input_value recv{}，不在每轮清空。
    buffer: [u8; 8],
    retries: u64,
}

impl KernelInputReader {
    pub(super) fn new() -> Self {
        Self {
            buffer: [0; 8],
            retries: 0,
        }
    }

    pub(super) fn read(
        &mut self,
        source: &mut impl InputSource,
        parser: &mut KernelInputParser,
        output: &mut Vec<InputEvent>,
    ) -> Result<(), WindowError> {
        match source.read(&mut self.buffer) {
            Ok(0) => return Err(WindowError::Stopped),
            Ok(_) => {}
            Err(error) => {
                // 按用户要求与 main 的 read != 0 一致，-1 也处理缓冲并继续下一轮。
                self.retries = self.retries.saturating_add(1);
                if self.retries.is_power_of_two() {
                    crate::espframe_log!(
                        "window.input.read_retry",
                        "count={} error={}",
                        self.retries,
                        error
                    );
                }
            }
        }
        let value = self.buffer;
        parser.Push(
            KernelInputValue {
                type_: u16::from_ne_bytes([value[0], value[1]]),
                code: u16::from_ne_bytes([value[2], value[3]]),
                value: i32::from_ne_bytes([value[4], value[5], value[6], value[7]]),
            },
            output,
        );
        Ok(())
    }
}

#[cfg(target_os = "android")]
pub(super) struct FdInputSource(pub(super) libc::c_int);

#[cfg(target_os = "android")]
impl InputSource for FdInputSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = unsafe { libc::read(self.0, buffer.as_mut_ptr().cast(), buffer.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}

#[cfg(test)]
mod tests;
