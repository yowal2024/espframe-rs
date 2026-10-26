#![allow(non_snake_case)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orientation {
    Portrait = 0,
    Landscape = 1,
    ReversePortrait = 2,
    ReverseLandscape = 3,
}

impl Orientation {
    pub fn IsRotated(self) -> bool {
        matches!(self, Self::Landscape | Self::ReverseLandscape)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }
    pub fn IsValid(self) -> bool {
        self.width != 0 && self.height != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DisplayInfo {
    pub physical_width: u32,
    pub physical_height: u32,
    pub orientation: Orientation,
    pub density: f32,
    pub refresh_rate: f32,
    pub generation: u64,
}

impl DisplayInfo {
    pub const fn new(
        width: u32,
        height: u32,
        orientation: Orientation,
        density: f32,
        refresh_rate: f32,
        generation: u64,
    ) -> Self {
        Self {
            physical_width: width,
            physical_height: height,
            orientation,
            density,
            refresh_rate,
            generation,
        }
    }

    pub fn oriented_size(self) -> Size {
        if self.orientation.IsRotated() {
            Size::new(self.physical_height, self.physical_width)
        } else {
            Size::new(self.physical_width, self.physical_height)
        }
    }

    pub fn with_orientation(self, orientation: Orientation) -> Self {
        if self.orientation == orientation {
            self
        } else {
            Self {
                orientation,
                generation: self.generation.saturating_add(1),
                ..self
            }
        }
    }
}
