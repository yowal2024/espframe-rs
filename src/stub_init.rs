pub const STUB_PAYLOAD_INIT_VERSION: u32 = 1;

#[repr(C)]
pub struct StubPayloadInit {
    pub version: u32,
    pub reserved: u32,
    pub encrypted_blob: *const u8,
    pub encrypted_size: usize,
}
