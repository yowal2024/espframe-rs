#[cfg(feature = "xdl")]
pub mod android;
#[cfg(feature = "soloader")]
pub mod soloader;
pub mod auth;
pub mod debug_log;
pub mod error;
pub mod gyro_aim;
pub mod inject;
#[cfg(feature = "jni")]
pub mod jni;
pub mod kernel;
pub mod mapping;
pub mod math;
pub mod monarch;
pub mod offsets;
pub mod payload;
#[cfg(feature = "xdl")]
pub mod payload_format;
pub mod payload_handoff;
pub mod physics;
pub mod projection;
#[cfg(feature = "xdl")]
pub mod render;
#[cfg(feature = "xdl")]
pub mod sensor;
pub mod stub;
pub mod threading;
mod stub_init;
pub mod ue;
#[cfg(feature = "xdl")]
pub mod window;
#[cfg(feature = "xdl")]
pub mod xdl;

pub use error::EspFrameError;
pub use projection::{
    in_extended_screen, world_to_screen, world_to_screen_matrix, Camera, Viewport,
};
#[cfg(feature = "xdl")]
pub use render::{
    AndroidBackend, EspFrameControl, EspFrameManager, FrameInfo, RenderMode, DEFAULT_IDLE_FPS,
};
pub use stub_init::{StubPayloadInit, STUB_PAYLOAD_INIT_VERSION};

pub struct EspFrame<D> {
    pub driver: D,
    pub offsets: offsets::Offsets,
}

impl<D> EspFrame<D> {
    pub fn new(driver: D, offsets: offsets::Offsets) -> Self {
        Self { driver, offsets }
    }

    pub fn install_offsets(&mut self, offsets: offsets::Offsets) {
        self.offsets = offsets;
    }
}
