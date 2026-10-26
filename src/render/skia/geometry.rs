//! Per-output geometry in the validated ROM's DisplaySettings coordinate space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub physical: [i32; 4],
    pub clip: [i32; 4],
    pub orientation: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct ScreenSize {
    // Logical viewport pixels: use these for UI coordinates, including rotation.
    pub width: u32,
    pub height: u32,
}
impl Geometry {
    pub fn screen_size(self) -> Option<ScreenSize> {
        let (_, _, w, h) = self.dimensions()?;
        Some(ScreenSize {
            width: w as u32,
            height: h as u32,
        })
    }
    pub fn fits_canvas(self, width: u32, height: u32) -> bool {
        self.dimensions().is_some()
            && width > 0
            && height > 0
            && self.physical[0] >= 0
            && self.physical[1] >= 0
            && self.physical[2] as u64 <= width as u64
            && self.physical[3] as u64 <= height as u64
    }
    pub fn dimensions(self) -> Option<(f32, f32, f32, f32)> {
        if !matches!(self.orientation, 0 | 3 | 4 | 7) {
            return None;
        }
        let width = |r: [i32; 4]| r[2].checked_sub(r[0]);
        let height = |r: [i32; 4]| r[3].checked_sub(r[1]);
        let (pw, ph, w, h) = (
            width(self.physical)?,
            height(self.physical)?,
            width(self.clip)?,
            height(self.clip)?,
        );
        if [pw, ph, w, h].iter().any(|&n| !(1..=32768).contains(&n)) {
            return None;
        }
        Some((pw as f32, ph as f32, w as f32, h as f32))
    }
    pub fn degrees(self) -> f32 {
        match self.orientation {
            4 => 90.,
            3 => 180.,
            7 => 270.,
            _ => 0.,
        }
    }
    // Local UI coordinates start at the visible viewport's top-left. Unlike app
    // layer coordinates they do not include clip.left/top (cropped screenshots).
    pub fn projection(self) -> Option<(f32, f32, f32, f32)> {
        let (pw, ph, w, h) = self.dimensions()?;
        let (rw, rh) = if self.orientation & 4 != 0 {
            (h, w)
        } else {
            (w, h)
        };
        Some((pw / rw, ph / rh, rw, rh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_rotations_project_viewport_corners_into_physical_bounds() {
        for rotation in [0, 4, 3, 7] {
            let (w, h) = if rotation & 4 == 0 {
                (1600, 2560)
            } else {
                (2560, 1600)
            };
            let g = Geometry {
                physical: [20, 30, 1620, 2590],
                clip: [11, 17, 11 + w, 17 + h],
                orientation: rotation,
            };
            let (sx, sy, rw, rh) = g.projection().unwrap();
            let rad = g.degrees().to_radians();
            let mut points = Vec::new();
            for (x, y) in [
                (0., 0.),
                (w as f32, 0.),
                (0., h as f32),
                (w as f32, h as f32),
            ] {
                let (x, y) = (x - w as f32 / 2., y - h as f32 / 2.);
                points.push((
                    20. + sx * (rw / 2. + x * rad.cos() - y * rad.sin()),
                    30. + sy * (rh / 2. + x * rad.sin() + y * rad.cos()),
                ));
            }
            for expected in [(20., 30.), (1620., 30.), (20., 2590.), (1620., 2590.)] {
                assert!(points
                    .iter()
                    .any(|p| (p.0 - expected.0).abs() < 0.01 && (p.1 - expected.1).abs() < 0.01));
            }
            assert!(g.fits_canvas(1620, 2590));
            assert!(!g.fits_canvas(100, 100));
        }
    }
}
