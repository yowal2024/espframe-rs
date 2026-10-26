use crate::monarch::memory::{GuestMemory, TargetMemory};

use super::ioctl::{IoctlRequest, GPUOBJ_INFO_IOCTL, GPUOBJ_SET_INFO_IOCTL};
use super::{
    EncodeErrno, GuestServices, KernelCall, KernelServices, ServiceError, ServiceWriteProvenance,
    EFAULT, EINVAL,
};

const GPUOBJ_INFO_SIZE: usize = 48;
const GPUOBJ_SET_INFO_SIZE: usize = 32;
const GPUOBJ_SET_INFO_METADATA: u64 = 1;
const GPUOBJ_SET_INFO_TYPE: u64 = 2;
const MEMTYPE_MASK: u64 = 0x0000_ff00;
const MEMTYPE_SHIFT: u32 = 8;
const MEMTYPE_MAX: u32 = 0xff;
const METADATA_CAPACITY: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtualKgslObject {
    pub fd: u32,
    pub id: u32,
    pub gpuaddr: u64,
    pub size: u64,
    pub va_len: u64,
    pub va_addr: u64,
    pub memtype_override: Option<u8>,
    pub metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
struct GpuobjInfo {
    gpuaddr: u64,
    flags: u64,
    size: u64,
    va_len: u64,
    va_addr: u64,
    id: u32,
}

impl GpuobjInfo {
    fn Decode(bytes: &[u8; GPUOBJ_INFO_SIZE]) -> Self {
        Self {
            gpuaddr: u64_at(bytes, 0),
            flags: u64_at(bytes, 8),
            size: u64_at(bytes, 16),
            va_len: u64_at(bytes, 24),
            va_addr: u64_at(bytes, 32),
            id: u32_at(bytes, 40),
        }
    }

    fn Encode(self) -> [u8; GPUOBJ_INFO_SIZE] {
        let mut bytes = [0; GPUOBJ_INFO_SIZE];
        put_u64(&mut bytes, 0, self.gpuaddr);
        put_u64(&mut bytes, 8, self.flags);
        put_u64(&mut bytes, 16, self.size);
        put_u64(&mut bytes, 24, self.va_len);
        put_u64(&mut bytes, 32, self.va_addr);
        put_u32(&mut bytes, 40, self.id);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GpuobjSetInfo {
    flags: u64,
    metadata: u64,
    id: u32,
    metadata_len: u32,
    object_type: u32,
}

impl GpuobjSetInfo {
    fn Decode(bytes: &[u8; GPUOBJ_SET_INFO_SIZE]) -> Self {
        Self {
            flags: u64_at(bytes, 0),
            metadata: u64_at(bytes, 8),
            id: u32_at(bytes, 16),
            metadata_len: u32_at(bytes, 20),
            object_type: u32_at(bytes, 24),
        }
    }
}

impl<K: KernelServices> GuestServices<K> {
    pub(super) fn EmulateGpuobjInfo<M: TargetMemory>(
        &mut self,
        memory: &mut GuestMemory<M>,
        svc_pc: u64,
        fd: u32,
        request: IoctlRequest,
        argument: u64,
    ) -> Result<u64, ServiceError> {
        let mut bytes = [0; GPUOBJ_INFO_SIZE];
        let copy_in = request.CopyInSize(GPUOBJ_INFO_IOCTL);
        if copy_in != 0 && ReadMemory(memory, argument, &mut bytes[..copy_in]).is_err() {
            return Ok(EncodeErrno(EFAULT));
        }
        let mut info = GpuobjInfo::Decode(&bytes);
        let result = self.RefreshGpuobjInfo(fd, &mut info)?;
        bytes = info.Encode();
        let copy_out = request.CopyOutSize(GPUOBJ_INFO_IOCTL);
        if copy_out != 0
            && self
                .WriteMemory(
                    memory,
                    argument,
                    &bytes[..copy_out],
                    svc_pc,
                    ServiceWriteProvenance::ServiceCopyOut,
                )
                .is_err()
        {
            return Ok(EncodeErrno(EFAULT));
        }
        Ok(result as u64)
    }

    pub(super) fn EmulateGpuobjSetInfo<M: TargetMemory>(
        &mut self,
        memory: &mut GuestMemory<M>,
        _svc_pc: u64,
        fd: u32,
        request: IoctlRequest,
        argument: u64,
    ) -> Result<u64, ServiceError> {
        let mut bytes = [0; GPUOBJ_SET_INFO_SIZE];
        let copy_in = request.CopyInSize(GPUOBJ_SET_INFO_IOCTL);
        if copy_in != 0 && ReadMemory(memory, argument, &mut bytes[..copy_in]).is_err() {
            return Ok(EncodeErrno(EFAULT));
        }
        let set_info = GpuobjSetInfo::Decode(&bytes);
        let mut live = GpuobjInfo {
            id: set_info.id,
            ..Default::default()
        };
        match self.RefreshGpuobjInfo(fd, &mut live) {
            Ok(_) => {}
            Err(ServiceError::GuestErrno { errno, .. }) => return Ok(EncodeErrno(errno)),
            Err(error) => return Err(error),
        }
        let object = self
            .state
            .objects
            .iter_mut()
            .find(|object| object.fd == fd && object.id == set_info.id)
            .ok_or_else(|| ServiceError::Infrastructure {
                operation: "gpuobj-set-info-shadow".to_owned(),
                errno: 5,
                backend: 0,
            })?;

        if set_info.flags & GPUOBJ_SET_INFO_METADATA != 0 && set_info.metadata_len != 0 {
            object.metadata.clear();
            if set_info.metadata != 0 {
                let size = usize::try_from(set_info.metadata_len)
                    .unwrap_or(usize::MAX)
                    .min(METADATA_CAPACITY - 1);
                if let Ok(mut metadata) = memory.ReadVec(set_info.metadata, size) {
                    for byte in &mut metadata {
                        if *byte == 0 {
                            break;
                        }
                        if !(0x20..=0x7e).contains(byte) {
                            *byte = b'?';
                        }
                    }
                    object.metadata = metadata;
                }
            }
        }

        if set_info.flags & GPUOBJ_SET_INFO_TYPE != 0 {
            if set_info.object_type > MEMTYPE_MAX {
                return Ok(EncodeErrno(EINVAL));
            }
            object.memtype_override = Some(set_info.object_type as u8);
        }
        Ok(0)
    }

    fn RefreshGpuobjInfo(&mut self, fd: u32, info: &mut GpuobjInfo) -> Result<i64, ServiceError> {
        let requested_id = info.id;
        let input = info.Encode();
        let mut output = input;
        let result = self.kernel.GpuobjIoctl(
            self.config.pid,
            fd,
            u64::from(GPUOBJ_INFO_IOCTL),
            &input,
            &mut output,
        );
        self.kernel_calls.push(KernelCall::Gpuobj(
            self.config.pid,
            fd,
            u64::from(GPUOBJ_INFO_IOCTL),
            &input,
            &output,
            &result,
        ));
        let target_result = match result {
            Ok(value) => value,
            Err(ServiceError::GuestErrno { errno, backend }) => {
                return Err(ServiceError::GuestErrno { errno, backend });
            }
            Err(error) => return Err(error),
        };
        *info = GpuobjInfo::Decode(&output);
        if info.id != requested_id {
            return Err(ServiceError::Infrastructure {
                operation: "gpuobj-info-identity".to_owned(),
                errno: 5,
                backend: 0,
            });
        }

        let index = self
            .state
            .objects
            .iter()
            .position(|object| object.fd == fd && object.id == requested_id);
        let (object, inserted) = if let Some(index) = index {
            (&mut self.state.objects[index], false)
        } else {
            self.state.objects.push(VirtualKgslObject {
                fd,
                id: requested_id,
                ..Default::default()
            });
            self.state
                .objects
                .sort_by_key(|object| (object.fd, object.id));
            (
                self.state
                    .objects
                    .iter_mut()
                    .find(|object| object.fd == fd && object.id == requested_id)
                    .expect("inserted KGSL object"),
                true,
            )
        };
        let same_generation = inserted
            || (object.gpuaddr == info.gpuaddr
                && object.size == info.size
                && object.va_len == info.va_len
                && object.va_addr == info.va_addr);
        if !same_generation {
            object.memtype_override = None;
            object.metadata.clear();
        }
        object.gpuaddr = info.gpuaddr;
        object.size = info.size;
        object.va_len = info.va_len;
        object.va_addr = info.va_addr;
        if let Some(memtype) = object.memtype_override {
            info.flags &= !MEMTYPE_MASK;
            info.flags |= (u64::from(memtype) << MEMTYPE_SHIFT) & MEMTYPE_MASK;
        }
        Ok(target_result)
    }
}

fn ReadMemory<M: TargetMemory>(
    memory: &mut GuestMemory<M>,
    address: u64,
    output: &mut [u8],
) -> Result<(), ()> {
    if address == 0 {
        return Err(());
    }
    memory.Read(address, output).map_err(|_| ())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
