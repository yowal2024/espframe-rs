use super::elf::{find_relocation_with_resolver, TARGET_LIBRARY};
use super::{SensorError, SensorPlatform};

pub(crate) struct SensorHook<P: SensorPlatform> {
    pub(crate) platform: P,
    pub(crate) got_slot: Option<usize>,
    pub(crate) original: Option<usize>,
    pub(crate) original_protection: Option<i32>,
}

impl<P: SensorPlatform> SensorHook<P> {
    pub(crate) fn new(platform: P) -> Self {
        Self {
            platform,
            got_slot: None,
            original: None,
            original_protection: None,
        }
    }
    pub(crate) fn StartWithPublisher<F>(
        &mut self,
        replacement: usize,
        publish: F,
    ) -> Result<(), SensorError>
    where
        F: FnOnce(usize) -> Result<(), SensorError>,
    {
        if self.got_slot.is_some() {
            return Ok(());
        }
        let elf = self.platform.OpenXdl(TARGET_LIBRARY)?;
        let slot = unsafe {
            find_relocation_with_resolver(
                elf.base,
                elf.program_headers,
                elf.program_header_count,
                |base, value| self.platform.ResolveAddress(base, value),
            )
        }?;
        let original = self.platform.ReadPointer(slot)?;
        if original == 0 {
            return Err(SensorError::Platform);
        }
        publish(original)?;
        let page_size = self.platform.PageSize();
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(SensorError::Platform);
        }
        let page = slot & !(page_size - 1);
        let protection = self.platform.ProtectWritable(page, page_size)?;
        self.got_slot = Some(slot);
        self.original = Some(original);
        self.original_protection = Some(protection);
        if let Err(error) = self.platform.WritePointer(slot, replacement) {
            if self
                .platform
                .RestoreProtection(page, page_size, protection)
                .is_err()
            {
                return Err(SensorError::CleanupFailed);
            }
            self.got_slot = None;
            self.original = None;
            self.original_protection = None;
            return Err(error);
        }
        if let Err(error) = self.platform.RestoreProtection(page, page_size, protection) {
            let rollback = self.platform.WritePointer(slot, original);
            let restore = self.platform.RestoreProtection(page, page_size, protection);
            if rollback.is_err() || restore.is_err() {
                return Err(SensorError::CleanupFailed);
            }
            self.got_slot = None;
            self.original = None;
            self.original_protection = None;
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn Stop(&mut self) -> Result<(), SensorError> {
        let (Some(&slot), Some(&original), Some(&protection)) = (
            self.got_slot.as_ref(),
            self.original.as_ref(),
            self.original_protection.as_ref(),
        ) else {
            return Ok(());
        };
        let page_size = self.platform.PageSize();
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(SensorError::Platform);
        }
        let page = slot & !(page_size - 1);
        self.platform.ProtectWritable(page, page_size)?;
        if let Err(error) = self.platform.WritePointer(slot, original) {
            let _ = self.platform.RestoreProtection(page, page_size, protection);
            return Err(error);
        }
        self.platform
            .RestoreProtection(page, page_size, protection)?;
        self.got_slot = None;
        self.original = None;
        self.original_protection = None;
        Ok(())
    }
    pub(crate) fn IsActive(&self) -> bool {
        self.got_slot.is_some()
    }
}
