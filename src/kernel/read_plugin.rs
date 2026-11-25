//! Loadable, equal-length file-read rules. The kernel copies every rule at load/config.
//! Target is one TGID identity (not every process with the same UID). No ABI negotiation.
//! Uses the shared CMD_PLUGIN commands; the image descriptor declares PLUGIN_READ.
use super::abi::{CMD_PLUGIN_CONTROL, CMD_PLUGIN_LOAD, CMD_PLUGIN_UNLOAD};
use super::{KernelDriver, KernelTransport};

pub const RP_MAX_CONFIG: usize = 64 * 1024;
pub const RP_MAX_RULES: usize = 4;
pub const RP_MAX_BYTES: usize = 4096;
pub const RP_CONFIG: usize = 1;
pub const RP_STOP: usize = 2;

#[derive(Clone, Copy)]
pub struct ReadReplacePair<'a> {
    pub original: &'a [u8],
    pub replacement: &'a [u8],
}
/// Serialized input for plugins/read_replace.c. Wipes its owned byte pairs on drop.
pub struct ReadReplaceConfig(Vec<u8>);
impl ReadReplaceConfig {
    pub fn new(pairs: &[ReadReplacePair<'_>]) -> Result<Self, isize> {
        if pairs.is_empty() || pairs.len() > RP_MAX_RULES {
            return Err(-22);
        }
        let mut bytes = 4;
        for (i, p) in pairs.iter().enumerate() {
            if p.original.is_empty()
                || p.original.len() > RP_MAX_BYTES
                || p.original.len() != p.replacement.len()
            {
                return Err(-22);
            }
            if pairs[..i].iter().any(|old| old.original == p.original) {
                return Err(-17);
            }
            bytes += 8 + p.original.len() * 2;
        }
        let mut data = Vec::with_capacity(bytes);
        data.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
        for p in pairs {
            data.extend_from_slice(&(p.original.len() as u32).to_le_bytes());
            data.extend_from_slice(&(p.replacement.len() as u32).to_le_bytes());
            data.extend_from_slice(p.original);
            data.extend_from_slice(p.replacement);
        }
        Ok(Self(data))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for ReadReplaceConfig {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
fn ptr(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        0
    } else {
        bytes.as_ptr() as usize
    }
}
fn handle(value: isize) -> Result<u64, isize> {
    if value > 0 {
        Ok(value as u64)
    } else if value < 0 {
        Err(value)
    } else {
        Err(-71)
    }
}
fn status(value: isize) -> Result<(), isize> {
    match value {
        0 => Ok(()),
        n if n < 0 => Err(n),
        _ => Err(-71),
    }
}
impl<T: KernelTransport> KernelDriver<T> {
    /// # Safety
    /// image must contain trusted ARM64 native code implementing plugins/read_sdk.h.
    /// Its callbacks execute in kernel context. Configuration is copied synchronously.
    pub unsafe fn ReadPluginLoad(
        &self,
        image: &[u8],
        config: &[u8],
        target_tgid: i32,
    ) -> Result<u64, isize> {
        if image.is_empty()
            || image.len() > 1024 * 1024
            || config.len() > RP_MAX_CONFIG
            || target_tgid <= 0
        {
            return Err(-22);
        }
        handle(unsafe {
            self.Invoke(
                CMD_PLUGIN_LOAD,
                [
                    ptr(image),
                    image.len(),
                    ptr(config),
                    config.len(),
                    target_tgid as usize,
                ],
            )
        })
    }
    /// Success returns a new handle; the old handle becomes stale. Target is retained.
    /// All prior readers drain before their rule buffers/file bindings are released.
    pub fn ReadPluginConfigure(&self, current: u64, config: &[u8]) -> Result<u64, isize> {
        if config.len() > RP_MAX_CONFIG {
            return Err(-22);
        }
        handle(unsafe {
            self.Invoke(
                CMD_PLUGIN_CONTROL,
                [current as usize, RP_CONFIG, ptr(config), config.len(), 0],
            )
        })
    }
    /// Stop releases bindings and read ownership; CONFIG can resume this image.
    pub fn ReadPluginStop(&self, current: u64) -> Result<(), isize> {
        status(unsafe {
            self.Invoke(
                CMD_PLUGIN_CONTROL,
                [current as usize, RP_STOP, 0, 0, 0],
            )
        })
    }
    pub fn ReadPluginUnload(&self, current: u64) -> Result<(), isize> {
        status(unsafe { self.Invoke(CMD_PLUGIN_UNLOAD, [current as usize, 0, 0, 0, 0]) })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    type Calls = Arc<Mutex<Vec<(usize, [usize; 5])>>>;
    #[derive(Clone, Default)]
    struct Transport(Calls);
    impl KernelTransport for Transport {
        unsafe fn Invoke(&self, _: i32, _: u64, cmd: usize, args: [usize; 5]) -> isize {
            self.0.lock().unwrap().push((cmd, args));
            if cmd == CMD_PLUGIN_LOAD {
                7
            } else if cmd == CMD_PLUGIN_CONTROL && args[1] == RP_CONFIG {
                8
            } else {
                0
            }
        }
    }
    #[test]
    fn equal_length_serialization_and_validation() {
        let pairs = [
            ReadReplacePair {
                original: b"abcd",
                replacement: b"WXYZ",
            },
            ReadReplacePair {
                original: b"ef",
                replacement: b"12",
            },
        ];
        let c = ReadReplaceConfig::new(&pairs).unwrap();
        assert_eq!(
            c.as_bytes(),
            &[
                2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, b'a', b'b', b'c', b'd', b'W', b'X', b'Y', b'Z',
                2, 0, 0, 0, 2, 0, 0, 0, b'e', b'f', b'1', b'2'
            ]
        );
        assert!(matches!(ReadReplaceConfig::new(&[]), Err(-22)));
        assert!(matches!(
            ReadReplaceConfig::new(&[ReadReplacePair {
                original: b"ab",
                replacement: b"x"
            }]),
            Err(-22)
        ));
        assert!(matches!(
            ReadReplaceConfig::new(&[pairs[0], pairs[0]]),
            Err(-17)
        ));
        let bytes = [0u8; RP_MAX_BYTES];
        let max = [ReadReplacePair {
            original: &bytes,
            replacement: &bytes,
        }];
        assert_eq!(
            ReadReplaceConfig::new(&max).unwrap().as_bytes().len(),
            12 + 2 * RP_MAX_BYTES
        );
    }
    #[test]
    fn direct_arguments_and_handle_changes() {
        let t = Transport::default();
        let k = KernelDriver::new(1, 2, 3, t.clone());
        assert_eq!(unsafe { k.ReadPluginLoad(&[1; 64], &[], 0) }, Err(-22));
        assert_eq!(unsafe { k.ReadPluginLoad(&[1; 64], &[], 1234) }, Ok(7));
        assert_eq!(k.ReadPluginConfigure(7, b"config"), Ok(8));
        assert_eq!(k.ReadPluginStop(8), Ok(()));
        assert_eq!(k.ReadPluginUnload(8), Ok(()));
        let c = t.0.lock().unwrap();
        assert_eq!(c.len(), 4);
        assert_eq!(
            (c[0].0, c[0].1[2], c[0].1[3], c[0].1[4]),
            (CMD_PLUGIN_LOAD, 0, 0, 1234)
        );
        assert_eq!(
            (c[1].0, c[1].1[0], c[1].1[1], c[1].1[3], c[1].1[4]),
            (CMD_PLUGIN_CONTROL, 7, RP_CONFIG, 6, 0)
        );
        assert_eq!(c[2], (CMD_PLUGIN_CONTROL, [8, RP_STOP, 0, 0, 0]));
        assert_eq!(c[3], (CMD_PLUGIN_UNLOAD, [8, 0, 0, 0, 0]));
    }
}
