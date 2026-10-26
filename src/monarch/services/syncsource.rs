use crate::monarch::memory::{GuestMemory, TargetMemory};
use crate::monarch::syncsource_policy::{
    ErrWithBackend, KgslSyncsourceSelectionKind, SelectVirtualKgslSyncsourceIdWithDiagnostics, EIO,
};

use super::ioctl::{IoctlRequest, SYNCSOURCE_CREATE_IOCTL, SYNCSOURCE_DESTROY_IOCTL};
use super::{
    EncodeErrno, GuestServices, KernelCall, KernelServices, ServiceError, ServiceWriteProvenance,
    EBADF, EFAULT, EINVAL,
};

const SYNCSOURCE_SIZE: usize = 16;
const EPROTO: i32 = 71;

impl<K: KernelServices> GuestServices<K> {
    pub(super) fn EmulateSyncsourceCreate<M: TargetMemory>(
        &mut self,
        memory: &mut GuestMemory<M>,
        svc_pc: u64,
        fd: u32,
        request: IoctlRequest,
        argument: u64,
    ) -> Result<u64, ServiceError> {
        let mut bytes = [0; SYNCSOURCE_SIZE];
        let copy_in = request.CopyInSize(SYNCSOURCE_CREATE_IOCTL);
        if copy_in != 0 && ReadMemory(memory, argument, &mut bytes[..copy_in]).is_err() {
            return Ok(EncodeErrno(EFAULT));
        }
        let id = match self.SelectSyncsourceId(fd) {
            Ok(id) => id,
            Err(ServiceError::GuestErrno { errno, .. }) => return Ok(EncodeErrno(errno)),
            Err(error) => return Err(error),
        };
        self.state.syncsources.push(id);
        self.state.syncsources.sort_unstable();
        bytes[..4].copy_from_slice(&id.to_le_bytes());
        let copy_out = request.CopyOutSize(SYNCSOURCE_CREATE_IOCTL);
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
        Ok(0)
    }

    pub(super) fn EmulateSyncsourceDestroy<M: TargetMemory>(
        &mut self,
        memory: &mut GuestMemory<M>,
        svc_pc: u64,
        fd: u32,
        request: IoctlRequest,
        argument: u64,
    ) -> Result<u64, ServiceError> {
        let mut bytes = [0; SYNCSOURCE_SIZE];
        let copy_in = request.CopyInSize(SYNCSOURCE_DESTROY_IOCTL);
        if copy_in != 0 && ReadMemory(memory, argument, &mut bytes[..copy_in]).is_err() {
            return Ok(EncodeErrno(EFAULT));
        }
        let id = u32::from_le_bytes(bytes[..4].try_into().expect("syncsource id"));
        let validation = self.kernel.ValidateKgslFdChecked(self.config.pid, fd);
        self.kernel_calls.push(KernelCall::ValidationResult(
            self.config.pid,
            fd,
            &validation,
        ));
        match validation {
            Ok(true) => {}
            Ok(false) => return Ok(EncodeErrno(EBADF)),
            Err(ServiceError::GuestErrno { errno, .. }) => return Ok(EncodeErrno(errno)),
            Err(error) => return Err(error),
        }
        if self.RemoveVirtualSyncsource(id).is_err() {
            return Ok(EncodeErrno(EINVAL));
        }
        let copy_out = request.CopyOutSize(SYNCSOURCE_DESTROY_IOCTL);
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
        Ok(0)
    }

    fn SelectSyncsourceId(&mut self, fd: u32) -> Result<u32, ServiceError> {
        let mut infrastructure_error = None;
        let selection =
            SelectVirtualKgslSyncsourceIdWithDiagnostics(&self.state.syncsources, &mut |min_id| {
                let result = self
                    .kernel
                    .PeekKgslSyncsourceIdChecked(self.config.pid, fd, min_id);
                self.kernel_calls
                    .push(KernelCall::Peek(self.config.pid, fd, min_id, &result));
                match result {
                    Ok(peek) => Ok((peek.id, peek.backend)),
                    Err(ServiceError::GuestErrno { errno, backend }) => {
                        Err(ErrWithBackend(-errno, backend))
                    }
                    Err(error) => {
                        let backend = error.Backend();
                        infrastructure_error = Some(error);
                        Err(ErrWithBackend(-EIO, backend))
                    }
                }
            });
        if let Some(error) = infrastructure_error {
            return Err(error);
        }
        match selection.kind {
            KgslSyncsourceSelectionKind::Selected => Ok(selection.id),
            KgslSyncsourceSelectionKind::GuestError => Err(ServiceError::GuestErrno {
                errno: selection.error,
                backend: selection.backend,
            }),
            KgslSyncsourceSelectionKind::InfrastructureError => Err(ServiceError::Infrastructure {
                operation: if selection.error == EPROTO {
                    "peek-syncsource-protocol"
                } else {
                    "peek-syncsource"
                }
                .to_owned(),
                errno: selection.error,
                backend: selection.backend,
            }),
        }
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
