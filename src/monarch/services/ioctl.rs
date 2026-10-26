use crate::monarch::memory::TargetMemory;

use super::{EncodeErrno, GuestServices, KernelServices, ENOTTY};

pub const SYNCSOURCE_CREATE_NUMBER: u8 = 0x40;
pub const SYNCSOURCE_DESTROY_NUMBER: u8 = 0x41;
pub const GPUOBJ_INFO_NUMBER: u8 = 0x47;
pub const GPUOBJ_SET_INFO_NUMBER: u8 = 0x4c;

pub const SYNCSOURCE_CREATE_IOCTL: u32 = 0xc010_0940;
pub const SYNCSOURCE_DESTROY_IOCTL: u32 = 0xc010_0941;
pub const GPUOBJ_INFO_IOCTL: u32 = 0xc030_0947;
pub const GPUOBJ_SET_INFO_IOCTL: u32 = 0x4020_094c;

const IOC_WRITE: u8 = 1;
const IOC_READ: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoctlRequest {
    pub raw: u32,
    pub ioctl_type: u8,
    pub number: u8,
    pub direction: u8,
    pub size: u16,
}

impl IoctlRequest {
    pub fn Decode(raw: u32) -> Self {
        Self {
            raw,
            ioctl_type: ((raw >> 8) & 0xff) as u8,
            number: (raw & 0xff) as u8,
            direction: ((raw >> 30) & 0x3) as u8,
            size: ((raw >> 16) & 0x3fff) as u16,
        }
    }

    pub fn CopyInSize(self, canonical: u32) -> usize {
        let kernel = Self::Decode(canonical);
        if kernel.direction & IOC_WRITE == 0 || self.direction & IOC_WRITE == 0 {
            0
        } else {
            usize::from(kernel.size.min(self.size))
        }
    }

    pub fn CopyOutSize(self, canonical: u32) -> usize {
        let kernel = Self::Decode(canonical);
        if kernel.direction & IOC_READ == 0 || self.direction & IOC_READ == 0 {
            0
        } else {
            usize::from(kernel.size.min(self.size))
        }
    }
}

impl<K: KernelServices> GuestServices<K> {
    pub(super) fn DispatchIoctl<M>(
        &mut self,
        memory: &mut crate::monarch::memory::GuestMemory<M>,
        svc_pc: u64,
        fd: u32,
        raw_request: u32,
        argument: u64,
    ) -> Result<u64, super::ServiceError>
    where
        M: TargetMemory,
    {
        let request = IoctlRequest::Decode(raw_request);
        match request.number {
            SYNCSOURCE_CREATE_NUMBER => {
                self.EmulateSyncsourceCreate(memory, svc_pc, fd, request, argument)
            }
            SYNCSOURCE_DESTROY_NUMBER => {
                self.EmulateSyncsourceDestroy(memory, svc_pc, fd, request, argument)
            }
            GPUOBJ_INFO_NUMBER => self.EmulateGpuobjInfo(memory, svc_pc, fd, request, argument),
            GPUOBJ_SET_INFO_NUMBER => {
                self.EmulateGpuobjSetInfo(memory, svc_pc, fd, request, argument)
            }
            _ => Ok(EncodeErrno(ENOTTY)),
        }
    }
}
