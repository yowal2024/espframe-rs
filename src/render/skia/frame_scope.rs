//! RenderEngine-thread composition scopes. Never keep a recording canvas.
use super::geometry::Geometry;

#[derive(Clone, Copy)]
struct Pending {
    engine: usize,
    surface: usize,
    consumed: bool,
    physical: bool,
    geometry: Option<Geometry>,
}
const EMPTY: Pending = Pending {
    engine: 0,
    surface: 0,
    consumed: false,
    physical: false,
    geometry: None,
};
pub struct FrameScope {
    frames: [Pending; 8],
    depth: usize,
}
impl FrameScope {
    pub const fn new() -> Self {
        Self {
            frames: [EMPTY; 8],
            depth: 0,
        }
    }
    pub fn enter(&mut self, engine: usize, physical: bool, geometry: Option<Geometry>) {
        if self.depth < self.frames.len() {
            self.frames[self.depth] = Pending {
                engine,
                physical,
                geometry,
                ..EMPTY
            };
        }
        // Count overflow scopes too: their exit must not pop a parent's frame.
        self.depth += 1;
    }
    pub fn leave(&mut self) {
        if self.depth == 0 {
            return;
        }
        self.depth -= 1;
        if self.depth < self.frames.len() {
            self.frames[self.depth] = EMPTY;
        }
    }
    pub fn current_engine(&self) -> usize {
        if self.depth == 0 || self.depth > self.frames.len() {
            0
        } else {
            self.frames[self.depth - 1].engine
        }
    }
    pub fn capture(&mut self, surface: usize) {
        if self.depth == 0 || self.depth > self.frames.len() {
            return;
        }
        let frame = &mut self.frames[self.depth - 1];
        if !frame.consumed && frame.surface == 0 {
            frame.surface = surface;
        }
    }
    pub fn submit(&mut self, engine: usize, surface: usize) -> Option<(bool, Option<Geometry>)> {
        if self.depth == 0 || self.depth > self.frames.len() || engine == 0 || surface == 0 {
            return None;
        }
        let frame = &mut self.frames[self.depth - 1];
        if frame.consumed
            || frame.engine != engine
            || frame.geometry.is_none()
            || (frame.surface != 0 && frame.surface != surface)
        {
            return None;
        }
        // The inspected 15-17 draw/fade bodies submit their destination once.
        // Other RE tasks (gainmap etc.) have no draw scope and cannot draw here.
        frame.consumed = true;
        frame.surface = surface;
        Some((frame.physical, frame.geometry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const G: Geometry = Geometry {
        physical: [0, 0, 1600, 2560],
        clip: [0, 0, 2560, 1600],
        orientation: 4,
    };
    #[test]
    fn final_surface_is_consumed_once() {
        let mut s = FrameScope::new();
        s.enter(10, true, Some(G));
        s.capture(100);
        assert_eq!(s.submit(10, 200), None);
        assert_eq!(s.submit(20, 100), None);
        assert_eq!(s.submit(10, 100), Some((true, Some(G))));
        assert_eq!(s.submit(10, 100), None);
    }
    #[test]
    fn leaving_aborted_composition_does_not_reuse_metadata() {
        let mut s = FrameScope::new();
        s.enter(10, true, Some(G));
        s.capture(100);
        s.leave();
        s.enter(10, false, None);
        assert_eq!(s.submit(10, 100), None);
        s.leave();
        assert_eq!(s.submit(10, 100), None);
    }
    #[test]
    fn nested_outputs_keep_their_own_geometry() {
        let mut s = FrameScope::new();
        s.enter(10, true, Some(G));
        s.capture(100);
        s.enter(20, false, Some(G));
        s.capture(200);
        assert_eq!(s.submit(10, 100), None);
        assert_eq!(s.submit(20, 200), Some((false, Some(G))));
        s.leave();
        assert_eq!(s.submit(10, 100), Some((true, Some(G))));
    }
    #[test]
    fn overflow_exits_do_not_pop_parent_scopes() {
        let mut s = FrameScope::new();
        for owner in 1..=9 {
            s.enter(owner, true, Some(G));
            s.capture(owner * 100);
        }
        assert_eq!(s.submit(9, 900), None);
        assert_eq!(s.submit(8, 800), None);
        s.leave();
        assert_eq!(s.submit(8, 800), Some((true, Some(G))));
    }
    #[test]
    fn null_surface_or_missing_composition_cannot_draw() {
        let mut s = FrameScope::new();
        s.enter(10, true, Some(G));
        assert_eq!(s.submit(10, 0), None);
        s.leave();
        assert_eq!(s.submit(10, 100), None);
        s.enter(10, true, Some(G));
        assert_eq!(s.submit(10, 100), Some((true, Some(G))));
    }
}
