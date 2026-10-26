use super::{InputEvent, ACTION_DOWN, ACTION_MOVE, ACTION_UP};
use crate::window::Size;
use std::time::{Duration, Instant};

/// Two released taps in the top-left 8% of the logical screen's short edge.
/// Screen changes, dragging and long presses cancel; only pointer zero participates.
#[derive(Default, Debug)]
pub struct TopLeftDoubleTap {
    screen: Option<Size>,
    pressed: Option<([f32; 2], Instant)>,
    last_tap: Option<Instant>,
    contact: bool,
}

impl TopLeftDoubleTap {
    pub fn Observe(&mut self, event: InputEvent, at: Instant, screen: Size) -> bool {
        if self.screen != Some(screen) {
            *self = Self {
                screen: Some(screen),
                ..Self::default()
            };
        }
        let InputEvent::Pointer {
            pointer,
            x,
            y,
            action,
        } = event
        else {
            return false;
        };
        if pointer != 0 {
            return false;
        }
        let was_down = self.contact;
        if action == ACTION_DOWN {
            self.contact = true;
        }
        if action == ACTION_UP {
            self.contact = false;
        }
        let edge = screen.width.min(screen.height) as f32 * 0.08;
        if !screen.IsValid()
            || !x.is_finite()
            || !y.is_finite()
            || x < 0.
            || y < 0.
            || x > edge
            || y > edge
        {
            self.pressed = None;
            self.last_tap = None;
            return false;
        }
        match action {
            ACTION_DOWN if !was_down => {
                // The kernel listener can repeat DOWN across SYN_REPORT records.
                if self.pressed.is_none() {
                    self.pressed = Some(([x, y], at));
                }
            }
            ACTION_DOWN | ACTION_MOVE | ACTION_UP => {
                let Some((start, down_at)) = self.pressed else {
                    return false;
                };
                let slop = edge * 0.25;
                let valid = (x - start[0]).hypot(y - start[1]) <= slop
                    && at
                        .checked_duration_since(down_at)
                        .is_some_and(|d| d <= Duration::from_millis(250));
                if !valid {
                    self.pressed = None;
                    self.last_tap = None;
                } else if action == ACTION_UP {
                    self.pressed = None;
                    let paired = self
                        .last_tap
                        .and_then(|last| at.checked_duration_since(last))
                        .is_some_and(|d| d < Duration::from_millis(500));
                    self.last_tap = if paired { None } else { Some(at) };
                    return paired;
                }
            }
            _ => {
                self.contact = false;
                self.pressed = None;
                self.last_tap = None;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(x: f32, action: u32) -> InputEvent {
        InputEvent::Pointer {
            pointer: 0,
            x,
            y: 10.,
            action,
        }
    }
    #[test]
    fn released_double_tap_toggles_once_and_needs_a_new_pair() {
        let mut gesture = TopLeftDoubleTap::default();
        let start = Instant::now();
        let screen = Size::new(640, 480);
        for (ms, action, expected) in [
            (0, ACTION_DOWN, false),
            (10, ACTION_DOWN, false),
            (20, ACTION_UP, false),
            (200, ACTION_DOWN, false),
            (220, ACTION_UP, true),
            (230, ACTION_UP, false),
            (300, ACTION_DOWN, false),
            (320, ACTION_UP, false),
        ] {
            assert_eq!(
                gesture.Observe(
                    event(10., action),
                    start + Duration::from_millis(ms),
                    screen
                ),
                expected
            );
        }
    }
    #[test]
    fn outside_drag_hold_rotation_and_timeout_cancel_pair() {
        let start = Instant::now();
        let screen = Size::new(640, 480);
        for case in 0..6 {
            let mut gesture = TopLeftDoubleTap::default();
            gesture.Observe(event(10., ACTION_DOWN), start, screen);
            gesture.Observe(
                event(10., ACTION_UP),
                start + Duration::from_millis(20),
                screen,
            );
            let screen2 = if case == 4 {
                Size::new(480, 640)
            } else {
                screen
            };
            let down_ms = if case == 5 { 500 } else { 100 };
            let down_at = start + Duration::from_millis(down_ms);
            if case != 3 {
                gesture.Observe(event(10., ACTION_DOWN), down_at, screen2);
            }
            match case {
                0 => {
                    gesture.Observe(event(200., ACTION_MOVE), down_at, screen2);
                }
                1 => {
                    gesture.Observe(event(30., ACTION_MOVE), down_at, screen2);
                }
                3 => {
                    gesture.Observe(
                        InputEvent::Pointer {
                            pointer: 1,
                            x: 10.,
                            y: 10.,
                            action: ACTION_DOWN,
                        },
                        down_at,
                        screen2,
                    );
                }
                _ => {}
            }
            let up_at = down_at + Duration::from_millis(if case == 2 { 300 } else { 20 });
            assert!(
                !gesture.Observe(event(10., ACTION_UP), up_at, screen2),
                "case {case}"
            );
        }
    }
}
