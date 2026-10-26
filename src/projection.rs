#![allow(dead_code)]

use crate::math::{Mat4, Quat, Vec2, Vec3};

/// Rendering viewport dimensions in pixels.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Viewport {
    pub width: f32,
    pub height: f32,
}

impl Viewport {
    pub const fn new(width: f32, height: f32) -> Self {
        Self { width, height }
    }

    pub fn is_valid(self) -> bool {
        self.width.is_finite() && self.height.is_finite() && self.width > 0.0 && self.height > 0.0
    }

    pub fn is_invalid(self) -> bool {
        !self.is_valid()
    }

    pub fn center(self) -> Vec2 {
        Vec2::new(self.width * 0.5, self.height * 0.5)
    }
}

/// UE camera pose and horizontal field of view.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Camera {
    pub location: Vec3,
    pub rotation: Quat,
    pub fov_degrees: f32,
}

impl Camera {
    pub const fn new(location: Vec3, rotation: Quat, fov_degrees: f32) -> Self {
        Self {
            location,
            rotation,
            fov_degrees,
        }
    }

    pub fn is_valid(self) -> bool {
        self.location.is_finite()
            && self.rotation.is_finite()
            && self.fov_degrees.is_finite()
            && self.fov_degrees > 0.0
            && self.fov_degrees < 180.0
    }
}

/// Projects a world point using UE's X-forward, Y-right, Z-up camera axes.
/// Points behind the one-unit near plane are rejected.
pub fn world_to_screen(world: Vec3, camera: &Camera, viewport: Viewport) -> Option<Vec2> {
    if !world.is_finite() || !camera.is_valid() || !viewport.is_valid() {
        return None;
    }
    let q = camera.rotation.normalized()?;
    let delta = world - camera.location;
    let forward = q.rotate_vec3(Vec3::new(1.0, 0.0, 0.0));
    let right = q.rotate_vec3(Vec3::new(0.0, 1.0, 0.0));
    let up = q.rotate_vec3(Vec3::new(0.0, 0.0, 1.0));
    let depth = delta.dot(forward);
    if !depth.is_finite() || depth < 1.0 {
        return None;
    }
    let focal = viewport.width * 0.5 / (camera.fov_degrees.to_radians() * 0.5).tan();
    if !focal.is_finite() || focal <= 0.0 {
        return None;
    }
    let center = viewport.center();
    let result = Vec2::new(
        center.x + delta.dot(right) * focal / depth,
        center.y - delta.dot(up) * focal / depth,
    );
    result.is_finite().then_some(result)
}

/// Projects a world point with the row-major UE `FMatrix` convention.
pub fn world_to_screen_matrix(world: Vec3, matrix: &Mat4, viewport: Viewport) -> Option<Vec2> {
    if !world.is_finite() || !matrix.is_finite() || !viewport.is_valid() {
        return None;
    }
    let m = &matrix.m;
    let depth = m[0][3] * world.x + m[1][3] * world.y + m[2][3] * world.z + m[3][3];
    if !depth.is_finite() || depth < 0.01 {
        return None;
    }
    let center = viewport.center();
    let x = center.x
        + (m[0][0] * world.x + m[1][0] * world.y + m[2][0] * world.z + m[3][0]) / depth * center.x;
    let y = center.y
        - (m[0][1] * world.x + m[1][1] * world.y + m[2][1] * world.z + m[3][1]) / depth * center.y;
    let result = Vec2::new(x, y);
    result.is_finite().then_some(result)
}

/// Returns whether a projected point lies inside the legacy 2× viewport area.
pub fn in_extended_screen(point: Vec2, viewport: Viewport) -> bool {
    point.is_finite()
        && viewport.is_valid()
        && point.x > 0.0
        && point.x < viewport.width * 2.0
        && point.y > 0.0
        && point.y < viewport.height * 2.0
}
