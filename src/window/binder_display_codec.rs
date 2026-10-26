//! Checked prefix decoder for AOSP IDisplayManager's Java Parcel format.

use super::mirror::DisplaySnapshot;
use super::WindowError;

const MAX_PARCEL_BYTES: usize = 1024 * 1024;
const MAX_STRING_BYTES: usize = 16 * 1024;
const MAX_DISPLAYS: usize = 256;

fn bad(message: &'static str) -> WindowError {
    WindowError::Backend(format!("invalid display Parcel: {message}"))
}

/// String methods must validate the encoded length against the remaining
/// parcel bytes before allocating or advancing, including alignment padding.
pub(super) trait ParcelReader {
    fn read_i32(&mut self) -> Result<i32, WindowError>;
    fn read_i64(&mut self) -> Result<i64, WindowError>;
    fn read_f32(&mut self) -> Result<f32, WindowError>;
    fn read_string16(&mut self) -> Result<Option<String>, WindowError>;
    fn skip_string8(&mut self) -> Result<(), WindowError>;
    fn position(&self) -> usize;
    fn length(&self) -> usize;
    fn skip(&mut self, count: usize) -> Result<(), WindowError>;
}

#[derive(Clone, Copy)]
enum Layout {
    Android12,
    Android13To14,
    Android15To17,
}

impl Layout {
    fn for_sdk(sdk: u32) -> Result<Self, WindowError> {
        match sdk {
            31 | 32 => Ok(Self::Android12),
            33 | 34 => Ok(Self::Android13To14),
            35..=37 => Ok(Self::Android15To17),
            _ => Err(WindowError::AbiUnavailable("DisplayInfo Parcel SDK")),
        }
    }
}

struct Decoder<'a, R> {
    reader: &'a mut R,
    end: usize,
}

impl<'a, R: ParcelReader> Decoder<'a, R> {
    fn new(reader: &'a mut R) -> Result<Self, WindowError> {
        let end = reader.length();
        if end > MAX_PARCEL_BYTES || reader.position() > end || reader.position() % 4 != 0 {
            return Err(bad("invalid total size or position"));
        }
        Ok(Self { reader, end })
    }

    fn ensure(&self, length: usize) -> Result<usize, WindowError> {
        self.reader
            .position()
            .checked_add(length)
            .filter(|end| *end <= self.end)
            .ok_or_else(|| bad("truncated prefix"))
    }

    fn i32(&mut self) -> Result<i32, WindowError> {
        let end = self.ensure(4)?;
        let value = self.reader.read_i32()?;
        if self.reader.position() != end {
            return Err(bad("invalid int32 reader position"));
        }
        Ok(value)
    }

    fn i64(&mut self) -> Result<i64, WindowError> {
        let end = self.ensure(8)?;
        let value = self.reader.read_i64()?;
        if self.reader.position() != end {
            return Err(bad("invalid int64 reader position"));
        }
        Ok(value)
    }

    fn f32(&mut self) -> Result<f32, WindowError> {
        let end = self.ensure(4)?;
        let value = self.reader.read_f32()?;
        if self.reader.position() != end {
            return Err(bad("invalid float reader position"));
        }
        if !value.is_finite() {
            return Err(bad("nonfinite cutout value"));
        }
        Ok(value)
    }

    fn string16(&mut self) -> Result<Option<String>, WindowError> {
        let minimum = self.ensure(4)?;
        let value = self.reader.read_string16()?;
        let end = self.reader.position();
        if end < minimum || end > self.end || end % 4 != 0 || end - minimum > MAX_STRING_BYTES {
            return Err(bad("invalid or oversized UTF-16 string"));
        }
        Ok(value)
    }

    fn string8(&mut self) -> Result<(), WindowError> {
        let minimum = self.ensure(4)?;
        self.reader.skip_string8()?;
        let end = self.reader.position();
        if end < minimum || end > self.end || end % 4 != 0 || end - minimum > MAX_STRING_BYTES {
            return Err(bad("invalid or oversized UTF-8 string"));
        }
        Ok(())
    }

    fn skip(&mut self, length: usize) -> Result<(), WindowError> {
        let end = self.ensure(length)?;
        self.reader.skip(length)?;
        if self.reader.position() != end {
            return Err(bad("invalid skip reader position"));
        }
        Ok(())
    }

    fn present(&mut self) -> Result<bool, WindowError> {
        match self.i32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad("invalid typed-object presence")),
        }
    }

    // DisplayAddress.writeToParcel: Physical contains one long, Network one
    // String16. Java writeParcelable prefixes a nullable String16 class name.
    // https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/core/java/android/view/DisplayAddress.java
    fn address(&mut self) -> Result<(), WindowError> {
        match self.string16()?.as_deref() {
            None => Ok(()),
            Some("android.view.DisplayAddress$Physical") => self.i64().map(|_| ()),
            Some("android.view.DisplayAddress$Network") => self.string16().map(|_| ()),
            _ => Err(bad("unknown DisplayAddress class")),
        }
    }

    fn value_int(&mut self) -> Result<(), WindowError> {
        match self.i32()? {
            -1 => Ok(()),
            1 => self.i32().map(|_| ()),
            _ => Err(bad("unexpected Integer value tag")),
        }
    }

    fn value_string(&mut self) -> Result<(), WindowError> {
        match self.i32()? {
            -1 => Ok(()),
            0 => self.string16().map(|_| ()),
            _ => Err(bad("unexpected String value tag")),
        }
    }

    fn manufacture_date(&mut self, layout: Layout) -> Result<(), WindowError> {
        match self.i32()? {
            -1 => return Ok(()),
            4 => {}
            _ => return Err(bad("unexpected ManufactureDate value tag")),
        }
        let outer_end = self.end;
        // Parcel.writeValue adds a byte length to VAL_PARCELABLE on SDK 33+;
        // direct writeParcelable(address/productInfo) never has this length.
        // https://android.googlesource.com/platform/frameworks/base/+/android-13.0.0_r1/core/java/android/os/Parcel.java
        let nested_end = if matches!(layout, Layout::Android12) {
            None
        } else {
            let length =
                usize::try_from(self.i32()?).map_err(|_| bad("negative Parcelable size"))?;
            if length == 0 || length > MAX_STRING_BYTES || length % 4 != 0 {
                return Err(bad("invalid Parcelable size"));
            }
            let end = self.ensure(length)?;
            self.end = end;
            Some(end)
        };
        if self.string16()?.as_deref()
            != Some("android.hardware.display.DeviceProductInfo$ManufactureDate")
        {
            return Err(bad("unknown ManufactureDate class"));
        }
        self.value_int()?; // Week, nullable Integer.
        self.value_int()?; // Year, nullable Integer.
        if nested_end.is_some_and(|end| self.reader.position() != end) {
            return Err(bad("Parcelable size does not match its body"));
        }
        self.end = outer_end;
        Ok(())
    }

    // This object body is unchanged across SDK 31-37; the nested writeValue
    // representation changes at SDK 33, not the surrounding writeParcelable.
    // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/hardware/display/DeviceProductInfo.java
    fn product(&mut self, layout: Layout) -> Result<(), WindowError> {
        match self.string16()?.as_deref() {
            None => return Ok(()),
            Some("android.hardware.display.DeviceProductInfo") => {}
            _ => return Err(bad("unknown DeviceProductInfo class")),
        }
        self.string16()?; // Name.
        self.string16()?; // Manufacturer PNP ID.
        self.value_string()?; // Product ID.
        self.value_int()?; // Model year.
        self.manufacture_date(layout)?;
        self.i32()?; // Connection-to-sink type.
        Ok(())
    }

    fn typed_rect(&mut self) -> Result<(), WindowError> {
        if self.present()? {
            self.skip(16)?;
        } // Rect and Insets are four i32s.
        Ok(())
    }

    // DisplayCutout.ParcelableWrapper: -1=null, 0=NO_CUTOUT, 1=full body.
    // Physical dimensions/pixel ratio appear in Android 13; sideOverrides in 15.
    // https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/core/java/android/view/DisplayCutout.java
    // https://android.googlesource.com/platform/frameworks/base/+/android-13.0.0_r1/core/java/android/view/DisplayCutout.java
    // https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/core/java/android/view/DisplayCutout.java
    fn cutout(&mut self, layout: Layout) -> Result<(), WindowError> {
        match self.i32()? {
            -1 | 0 => return Ok(()),
            1 => {}
            _ => return Err(bad("unknown cutout variant")),
        }
        self.typed_rect()?; // Safe insets.
        if self.i32()? != 4 {
            return Err(bad("cutout must contain four bounds"));
        }
        for _ in 0..4 {
            self.typed_rect()?;
        }
        self.typed_rect()?; // Waterfall Insets.
        self.i32()?;
        self.i32()?; // Parser display width/height.
        if !matches!(layout, Layout::Android12) {
            self.i32()?;
            self.i32()?;
        }
        self.f32()?; // Density.
        self.string16()?; // Cutout spec, not String8.
        self.i32()?; // Cutout parser rotation, not DisplayInfo.rotation.
        self.f32()?; // Scale.
        if !matches!(layout, Layout::Android12) {
            self.f32()?;
        }
        if matches!(layout, Layout::Android15To17) {
            let count = self.i32()?;
            if count != -1 {
                let count =
                    usize::try_from(count).map_err(|_| bad("negative side override count"))?;
                if count > 256 {
                    return Err(bad("too many side overrides"));
                }
                self.skip(
                    count
                        .checked_mul(4)
                        .ok_or_else(|| bad("side array overflow"))?,
                )?;
            }
        }
        Ok(())
    }
}

/// Status has already been consumed. The next word is the AIDL nullable
/// DisplayInfo marker, not a class name or sized-Parcelable prefix.
// https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/view/DisplayInfo.java
pub(super) fn read_display_info(
    reader: &mut impl ParcelReader,
    sdk: u32,
    requested_id: i32,
) -> Result<Option<DisplaySnapshot>, WindowError> {
    let layout = Layout::for_sdk(sdk)?;
    if requested_id < 0 {
        return Err(bad("invalid requested display id"));
    }
    let mut input = Decoder::new(reader)?;
    if !input.present()? {
        return Ok(None);
    }
    let stack = input.i32()?;
    input.i32()?; // Flags.
    input.i32()?; // Type.
    let id = input.i32()?;
    if id != requested_id {
        return Err(bad("reply display id does not match request"));
    }
    input.i32()?; // Display group ID.
    input.address()?;
    input.product(layout)?;
    input.string8()?; // DisplayInfo.name uniquely uses String8 in this prefix.
    input.skip(6 * 4)?; // appW/H, smallestNominalAppW/H, largestNominalAppW/H.
    let width = input.i32()?;
    let height = input.i32()?;
    input.cutout(layout)?;
    let rotation = input.i32()?;
    if stack == -1 {
        return Ok(None);
    }
    DisplaySnapshot::from_java(id, stack, width, height, rotation).map(Some)
}

/// Java int[] reply, after the Binder status header; null is not a successful
/// empty display list, because the caller uses empty snapshots for teardown.
pub(super) fn read_display_ids(reader: &mut impl ParcelReader) -> Result<Vec<i32>, WindowError> {
    let mut input = Decoder::new(reader)?;
    let count = usize::try_from(input.i32()?).map_err(|_| bad("null or negative display count"))?;
    if count > MAX_DISPLAYS {
        return Err(bad("too many displays"));
    }
    input.ensure(
        count
            .checked_mul(4)
            .ok_or_else(|| bad("display array overflow"))?,
    )?;
    let mut ids = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let id = input.i32()?;
        if id < 0 || !seen.insert(id) {
            return Err(bad("negative or duplicate display id"));
        }
        ids.push(id);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::{Orientation, Size};

    #[derive(Clone, Default)]
    struct Bytes {
        data: Vec<u8>,
        offset: usize,
    }

    impl Bytes {
        fn i32(&mut self, value: i32) {
            self.data.extend(value.to_le_bytes());
        }
        fn i64(&mut self, value: i64) {
            self.data.extend(value.to_le_bytes());
        }
        fn f32(&mut self, value: f32) {
            self.data.extend(value.to_le_bytes());
        }
        fn string16(&mut self, value: Option<&str>) {
            let Some(value) = value else {
                self.i32(-1);
                return;
            };
            let units: Vec<_> = value.encode_utf16().collect();
            self.i32(units.len() as i32);
            for unit in units {
                self.data.extend(unit.to_le_bytes());
            }
            self.data.extend([0, 0]);
            while self.data.len() % 4 != 0 {
                self.data.push(0);
            }
        }
        fn string8(&mut self, value: Option<&str>) {
            let Some(value) = value else {
                self.i32(-1);
                return;
            };
            self.i32(value.len() as i32);
            self.data.extend(value.as_bytes());
            self.data.push(0);
            while self.data.len() % 4 != 0 {
                self.data.push(0);
            }
        }
        fn take<const N: usize>(&mut self) -> Result<[u8; N], WindowError> {
            let end = self.offset.checked_add(N).ok_or(WindowError::Unsupported)?;
            let bytes = self
                .data
                .get(self.offset..end)
                .ok_or(WindowError::Unsupported)?;
            self.offset = end;
            Ok(bytes.try_into().unwrap())
        }
        fn typed_rect(&mut self, present: bool) {
            self.i32(i32::from(present));
            if present {
                for coordinate in [0, 10, 20, 30] {
                    self.i32(coordinate);
                }
            }
        }
        fn tagged_int(&mut self, value: Option<i32>) {
            self.i32(if value.is_some() { 1 } else { -1 });
            if let Some(value) = value {
                self.i32(value);
            }
        }
        fn product(&mut self, sdk: u32, manufacture_date: bool) -> Option<usize> {
            self.string16(Some("android.hardware.display.DeviceProductInfo"));
            self.string16(Some("Panel"));
            self.string16(Some("ABC"));
            self.i32(0);
            self.string16(Some("1234"));
            self.tagged_int(Some(2024));
            if !manufacture_date {
                self.i32(-1);
                self.i32(1);
                return None;
            }
            self.i32(4);
            let length_position = (sdk >= 33).then(|| {
                let index = self.data.len();
                self.i32(0);
                index
            });
            let start = self.data.len();
            self.string16(Some(
                "android.hardware.display.DeviceProductInfo$ManufactureDate",
            ));
            self.tagged_int(None);
            self.tagged_int(Some(2023));
            if let Some(index) = length_position {
                let length = (self.data.len() - start) as i32;
                self.data[index..index + 4].copy_from_slice(&length.to_le_bytes());
            }
            self.i32(1);
            length_position
        }
        fn cutout(&mut self, sdk: u32, variant: i32) {
            self.i32(variant);
            if variant != 1 {
                return;
            }
            self.typed_rect(true);
            self.i32(4);
            for present in [true, false, true, false] {
                self.typed_rect(present);
            }
            self.typed_rect(true); // Insets uses the same four-int body.
            self.i32(1080);
            self.i32(2400);
            if sdk >= 33 {
                self.i32(1080);
                self.i32(2400);
            }
            self.f32(3.0);
            self.string16(Some("M0,0 L20,20"));
            self.i32(2);
            self.f32(1.0);
            if sdk >= 33 {
                self.f32(1.0);
            }
            if sdk >= 35 {
                self.i32(4);
                for side in [0, 1, 2, 3] {
                    self.i32(side);
                }
            }
        }
    }

    impl ParcelReader for Bytes {
        fn read_i32(&mut self) -> Result<i32, WindowError> {
            Ok(i32::from_le_bytes(self.take()?))
        }
        fn read_i64(&mut self) -> Result<i64, WindowError> {
            Ok(i64::from_le_bytes(self.take()?))
        }
        fn read_f32(&mut self) -> Result<f32, WindowError> {
            Ok(f32::from_le_bytes(self.take()?))
        }
        fn read_string16(&mut self) -> Result<Option<String>, WindowError> {
            let length = self.read_i32()?;
            if length == -1 {
                return Ok(None);
            }
            let length = usize::try_from(length).map_err(|_| WindowError::Unsupported)?;
            if length > self.length().saturating_sub(self.offset) / 2 {
                return Err(WindowError::Unsupported);
            }
            let mut units = Vec::new();
            for _ in 0..length {
                units.push(u16::from_le_bytes(self.take()?));
            }
            if self.take::<2>()? != [0, 0] {
                return Err(WindowError::Unsupported);
            }
            self.skip((4 - self.offset % 4) % 4)?;
            String::from_utf16(&units)
                .map(Some)
                .map_err(|_| WindowError::Unsupported)
        }
        fn skip_string8(&mut self) -> Result<(), WindowError> {
            let length = self.read_i32()?;
            if length == -1 {
                return Ok(());
            }
            let length = usize::try_from(length).map_err(|_| WindowError::Unsupported)?;
            self.skip(length)?;
            if self.take::<1>()? != [0] {
                return Err(WindowError::Unsupported);
            }
            self.skip((4 - self.offset % 4) % 4)
        }
        fn position(&self) -> usize {
            self.offset
        }
        fn length(&self) -> usize {
            self.data.len()
        }
        fn skip(&mut self, count: usize) -> Result<(), WindowError> {
            let end = self
                .offset
                .checked_add(count)
                .filter(|end| *end <= self.data.len())
                .ok_or(WindowError::Unsupported)?;
            self.offset = end;
            Ok(())
        }
    }

    fn prefix(sdk: u32, address: u8, product: u8, cutout: i32) -> (Bytes, Option<usize>) {
        let mut bytes = Bytes::default();
        bytes.i32(1); // AIDL nullable return marker, status header already consumed.
        for value in [7, 0, 2, 3, 0] {
            bytes.i32(value);
        }
        match address {
            0 => bytes.string16(None),
            1 => {
                bytes.string16(Some("android.view.DisplayAddress$Physical"));
                bytes.i64(0x123456789abcdef);
            }
            _ => {
                bytes.string16(Some("android.view.DisplayAddress$Network"));
                bytes.string16(Some("aa:bb:cc:dd:ee:ff"));
            }
        }
        let nested_length = if product == 0 {
            bytes.string16(None);
            None
        } else {
            bytes.product(sdk, product == 2)
        };
        bytes.string8(Some("Screen \u{4e2d}\u{6587}"));
        for value in [1900, 1000, 900, 1800, 1900, 1000, 1920, 1080] {
            bytes.i32(value);
        }
        bytes.cutout(sdk, cutout);
        bytes.i32(1); // Actual display rotation, not cutout parser rotation.
        (bytes, nested_length)
    }

    #[test]
    fn decodes_aosp_31_through_36_prefixes_and_ignores_later_fields() {
        for sdk in 31..=37 {
            for address in 0..=2 {
                for product in 0..=2 {
                    for cutout in [-1, 0, 1] {
                        let (mut bytes, _) = prefix(sdk, address, product, cutout);
                        let end = bytes.data.len();
                        bytes.i32(0x12345678);
                        let display = read_display_info(&mut bytes, sdk, 3).unwrap().unwrap();
                        assert_eq!(
                            display,
                            DisplaySnapshot {
                                display_id: 3,
                                layer_stack: 7,
                                orientation: Orientation::Landscape,
                                size: Size::new(1920, 1080)
                            }
                        );
                        assert_eq!(bytes.offset, end, "sdk={sdk}");
                    }
                }
            }
        }
    }

    #[test]
    fn nullable_return_and_disabled_stack_are_not_malformed() {
        let mut null = Bytes::default();
        null.i32(0);
        assert!(read_display_info(&mut null, 31, 3).unwrap().is_none());
        let (mut disabled, _) = prefix(36, 1, 2, 1);
        disabled.data[4..8].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(read_display_info(&mut disabled, 36, 3).unwrap().is_none());
    }

    #[test]
    fn unsupported_versions_invalid_presence_and_conflicting_id_fail() {
        for sdk in [0, 30, 38, u32::MAX] {
            let (mut bytes, _) = prefix(36, 0, 0, 0);
            assert!(read_display_info(&mut bytes, sdk, 3).is_err());
        }
        for marker in [-1i32, 2] {
            let (mut bytes, _) = prefix(36, 0, 0, 0);
            bytes.data[..4].copy_from_slice(&marker.to_le_bytes());
            assert!(read_display_info(&mut bytes, 36, 3).is_err());
        }
        let (mut bytes, _) = prefix(36, 0, 0, 0);
        assert!(read_display_info(&mut bytes, 36, 4).is_err());
    }

    #[test]
    fn every_truncated_prefix_is_rejected() {
        for sdk in [31, 33, 35, 37] {
            let (bytes, _) = prefix(sdk, 1, 2, 1);
            for end in 0..bytes.data.len() {
                let mut truncated = Bytes {
                    data: bytes.data[..end].to_vec(),
                    offset: 0,
                };
                assert!(
                    read_display_info(&mut truncated, sdk, 3).is_err(),
                    "sdk={sdk} end={end}"
                );
            }
        }
    }

    #[test]
    fn nested_parcelable_length_must_match_exact_consumption() {
        for sdk in [33, 34, 35, 36] {
            let (original, index) = prefix(sdk, 1, 2, 1);
            let index = index.unwrap();
            let actual = i32::from_le_bytes(original.data[index..index + 4].try_into().unwrap());
            for length in [-1, 0, actual - 4, actual + 4, i32::MAX] {
                let mut bytes = original.clone();
                bytes.data[index..index + 4].copy_from_slice(&length.to_le_bytes());
                assert!(
                    read_display_info(&mut bytes, sdk, 3).is_err(),
                    "sdk={sdk} length={length}"
                );
            }
        }
    }

    #[test]
    fn display_ids_are_bounded_unique_and_nonnegative() {
        let mut bytes = Bytes::default();
        bytes.i32(3);
        for id in [0, 2, 99] {
            bytes.i32(id);
        }
        assert_eq!(read_display_ids(&mut bytes).unwrap(), [0, 2, 99]);
        for count in [-1, 257, i32::MAX] {
            let mut bytes = Bytes::default();
            bytes.i32(count);
            assert!(read_display_ids(&mut bytes).is_err());
        }
        for ids in [[1, 1], [-1, 2]] {
            let mut bytes = Bytes::default();
            bytes.i32(2);
            for id in ids {
                bytes.i32(id);
            }
            assert!(read_display_ids(&mut bytes).is_err());
        }
        let mut empty = Bytes::default();
        empty.i32(0);
        assert!(read_display_ids(&mut empty).unwrap().is_empty());
    }

    #[test]
    fn unknown_classes_bad_geometry_and_unknown_cutout_variant_fail() {
        let (mut address, _) = prefix(31, 1, 0, 0);
        address.data[28] = b'X'; // First UTF-16 unit of the address class.
        assert!(read_display_info(&mut address, 31, 3).is_err());
        let (mut product, _) = prefix(31, 0, 1, 0);
        product.data[32] = b'X'; // First UTF-16 unit after null address and class length.
        assert!(read_display_info(&mut product, 31, 3).is_err());
        let (original, _) = prefix(36, 0, 0, 0);
        let end = original.data.len();
        for (offset, value) in [
            (4, -2i32),
            (end - 16, 0),
            (end - 12, -1),
            (end - 8, 2),
            (end - 4, 4),
        ] {
            let mut bytes = original.clone();
            bytes.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                read_display_info(&mut bytes, 36, 3).is_err(),
                "offset={offset}"
            );
        }
        let (mut sides, _) = prefix(35, 0, 0, 1);
        let count = sides.data.len() - 24;
        sides.data[count..count + 4].copy_from_slice(&i32::MAX.to_le_bytes());
        assert!(read_display_info(&mut sides, 35, 3).is_err());
    }
}
