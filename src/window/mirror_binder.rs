//! Read-only native client for the framework display service (SDK 31-37).
#![allow(unexpected_cfgs)]

use super::binder_display_codec::{read_display_ids, read_display_info, ParcelReader};
use super::mirror::{normalize_displays, DisplaySnapshot};
use super::WindowError;
use binder::binder_impl::{BorrowedParcel, IBinderInternal, Parcel};
use binder::Interface;
use binder_ndk as binder;

const DESCRIPTOR: &str = "android.hardware.display.IDisplayManager";
const GET_DISPLAY_INFO: u32 = binder::binder_impl::FIRST_CALL_TRANSACTION;
const GET_DISPLAY_IDS: u32 = binder::binder_impl::FIRST_CALL_TRANSACTION + 1;

pub(super) fn android_sdk() -> Result<u32, WindowError> {
    let mut buffer = [0 as libc::c_char; 128];
    let length = unsafe {
        libc::__system_property_get(c"ro.build.version.sdk".as_ptr(), buffer.as_mut_ptr())
    };
    if length <= 0 || length as usize >= buffer.len() {
        return Err(WindowError::AbiUnavailable("Android SDK property"));
    }
    let text = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    text.to_str()
        .ok()
        .and_then(|text| text.parse().ok())
        .filter(|sdk| (31..=37).contains(sdk))
        .ok_or(WindowError::AbiUnavailable(
            "DisplayInfo Parcel SDK (31-37)",
        ))
}

pub trait IDisplayManager: Interface {}
binder::declare_binder_interface! {
    IDisplayManager[DESCRIPTOR] {
        native: BnDisplayManager(reject_transaction),
        proxy: BpDisplayManager,
    }
}
impl IDisplayManager for BpDisplayManager {}
impl IDisplayManager for binder::binder_impl::Binder<BnDisplayManager> {}

fn reject_transaction(
    _: &dyn IDisplayManager,
    _: u32,
    _: &BorrowedParcel<'_>,
    _: &mut BorrowedParcel<'_>,
) -> Result<(), binder::StatusCode> {
    Err(binder::StatusCode::UNKNOWN_TRANSACTION)
}

fn failed(error: impl std::fmt::Display) -> WindowError {
    WindowError::Backend(format!("native display Binder: {error}"))
}

#[derive(Default)]
pub(super) struct NativeDisplayClient {
    service: Option<binder::SpIBinder>,
}

impl NativeDisplayClient {
    pub(super) fn is_remote(&mut self) -> Result<bool, WindowError> {
        self.is_remote_with(|| {
            binder::get_service("display").ok_or_else(|| failed("display service not found"))
        })
    }

    pub(super) fn is_remote_with(
        &mut self,
        acquire: impl FnOnce() -> Result<binder::SpIBinder, WindowError>,
    ) -> Result<bool, WindowError> {
        if self.service.is_some() {
            return Ok(true);
        }
        let service = acquire()?;
        // Local Java Binder references must also be released in the caller's JNI scope.
        if !service.is_remote() {
            return Ok(false);
        }
        self.service = Some(
            service
                .into_interface::<dyn IDisplayManager>()
                .map_err(failed)?
                .as_binder(),
        );
        Ok(true)
    }

    pub fn snapshot(&mut self, sdk: u32) -> Result<Vec<DisplaySnapshot>, WindowError> {
        self.snapshot_with(sdk, || {
            binder::get_service("display").ok_or_else(|| failed("display service not found"))
        })
    }

    pub(super) fn snapshot_with(
        &mut self,
        sdk: u32,
        acquire: impl FnOnce() -> Result<binder::SpIBinder, WindowError>,
    ) -> Result<Vec<DisplaySnapshot>, WindowError> {
        if !(31..=37).contains(&sdk) {
            return Err(WindowError::AbiUnavailable("native display Binder SDK"));
        }
        if !self.is_remote_with(acquire)? {
            return Err(WindowError::AbiUnavailable("remote display Binder required"));
        }
        let result = Self::query(self.service.as_ref().unwrap(), sdk);
        if result.is_err() {
            self.service.take();
        }
        result
    }

    fn query(service: &binder::SpIBinder, sdk: u32) -> Result<Vec<DisplaySnapshot>, WindowError> {
        let ids = service
            .transact(GET_DISPLAY_IDS, 0, |mut request| {
                // Android 12/12L has no includeDisabled argument.
                if sdk >= 33 {
                    request.write(&false)?;
                }
                Ok(())
            })
            .map_err(failed)?;
        let ids = read_display_ids(&mut NativeReader::reply(&ids)?)?;
        let mut displays = Vec::with_capacity(ids.len());
        for id in ids {
            let reply = service
                .transact(GET_DISPLAY_INFO, 0, |mut request| request.write(&id))
                .map_err(failed)?;
            let mut reader = NativeReader::reply(&reply)?;
            let start = reader.position();
            if reader.read_i32()? == 0 {
                return Err(failed("display disappeared during enumeration"));
            }
            unsafe { reply.set_data_position(start as i32) }.map_err(failed)?;
            if let Some(display) = read_display_info(&mut reader, sdk, id)? {
                displays.push(display);
            }
        }
        normalize_displays(displays)
    }
}

struct NativeReader<'a>(&'a Parcel);

impl<'a> NativeReader<'a> {
    fn reply(parcel: &'a Parcel) -> Result<Self, WindowError> {
        if !(4..=1024 * 1024).contains(&parcel.get_data_size()) {
            return Err(failed("invalid reply size"));
        }
        let status: binder::Status = parcel.read().map_err(failed)?;
        if !status.is_ok() {
            return Err(failed(status));
        }
        Ok(Self(parcel))
    }

    fn string_bytes(&mut self, wide: bool) -> Result<Option<Vec<u8>>, WindowError> {
        let count = self.read_i32()?;
        if count == -1 {
            return Ok(None);
        }
        let count = usize::try_from(count).map_err(|_| failed("negative string length"))?;
        let unit = if wide { 2 } else { 1 };
        let raw_size = count
            .checked_add(1)
            .and_then(|n| n.checked_mul(unit))
            .filter(|n| *n <= 16 * 1024)
            .ok_or_else(|| failed("oversized string"))?;
        let aligned = (raw_size + 3) & !3;
        if self
            .position()
            .checked_add(aligned)
            .is_none_or(|end| end > self.length())
        {
            return Err(failed("truncated string"));
        }
        let mut bytes = Vec::with_capacity(aligned);
        for _ in 0..aligned / 4 {
            bytes.extend(self.read_i32()?.to_le_bytes());
        }
        if bytes[raw_size - unit..].iter().any(|byte| *byte != 0) {
            return Err(failed("invalid string terminator or padding"));
        }
        bytes.truncate(raw_size - unit);
        Ok(Some(bytes))
    }
}

impl ParcelReader for NativeReader<'_> {
    fn read_i32(&mut self) -> Result<i32, WindowError> {
        self.0.read().map_err(failed)
    }
    fn read_i64(&mut self) -> Result<i64, WindowError> {
        self.0.read().map_err(failed)
    }
    fn read_f32(&mut self) -> Result<f32, WindowError> {
        self.0.read().map_err(failed)
    }
    fn read_string16(&mut self) -> Result<Option<String>, WindowError> {
        self.string_bytes(true)?
            .map(|bytes| {
                let units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                String::from_utf16(&units).map_err(failed)
            })
            .transpose()
    }
    fn skip_string8(&mut self) -> Result<(), WindowError> {
        self.string_bytes(false).map(|_| ())
    }
    fn position(&self) -> usize {
        self.0.get_data_position() as usize
    }
    fn length(&self) -> usize {
        self.0.get_data_size() as usize
    }
    fn skip(&mut self, count: usize) -> Result<(), WindowError> {
        let end = self
            .position()
            .checked_add(count)
            .filter(|end| *end <= self.length())
            .ok_or_else(|| failed("truncated field"))?;
        unsafe {
            self.0
                .set_data_position(i32::try_from(end).map_err(failed)?)
        }
        .map_err(failed)
    }
}
