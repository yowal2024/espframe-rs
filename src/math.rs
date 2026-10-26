#![allow(dead_code)]

use core::ops::{Add, AddAssign, Mul, Sub, SubAssign};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vec2 {
    pub x: f32,
    pub y: f32,
}

impl Vec2 {
    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
    pub const fn zero() -> Self {
        Self::new(0.0, 0.0)
    }
    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite()
    }
    pub fn length(self) -> f32 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}

impl Add for Vec2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::new(self.x + rhs.x, self.y + rhs.y)
    }
}
impl Sub for Vec2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.x - rhs.x, self.y - rhs.y)
    }
}
impl Mul<f32> for Vec2 {
    type Output = Self;
    fn mul(self, rhs: f32) -> Self {
        Self::new(self.x * rhs, self.y * rhs)
    }
}
impl AddAssign for Vec2 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Vec2 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}
impl Vec3 {
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }
    pub const fn zero() -> Self {
        Self::new(0.0, 0.0, 0.0)
    }
    pub const fn one() -> Self {
        Self::new(1.0, 1.0, 1.0)
    }
    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }
    pub fn dot(self, rhs: Self) -> f32 {
        self.x * rhs.x + self.y * rhs.y + self.z * rhs.z
    }
    pub fn cross(self, rhs: Self) -> Self {
        Self::new(
            self.y * rhs.z - self.z * rhs.y,
            self.z * rhs.x - self.x * rhs.z,
            self.x * rhs.y - self.y * rhs.x,
        )
    }
}

/// Unreal's Euler-angle rotation (degrees).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rotator {
    pub pitch: f32,
    pub yaw: f32,
    pub roll: f32,
}

impl Rotator {
    pub const fn new(pitch: f32, yaw: f32, roll: f32) -> Self {
        Self { pitch, yaw, roll }
    }

    pub const fn zero() -> Self {
        Self::new(0.0, 0.0, 0.0)
    }

    pub fn is_finite(self) -> bool {
        self.pitch.is_finite() && self.yaw.is_finite() && self.roll.is_finite()
    }

    pub fn to_quat(self) -> Quat {
        Quat::from_euler_degrees(self.pitch, self.yaw, self.roll)
    }
}

impl From<Rotator> for Quat {
    fn from(value: Rotator) -> Self {
        value.to_quat()
    }
}

impl Add for Vec3 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::new(self.x + rhs.x, self.y + rhs.y, self.z + rhs.z)
    }
}
impl Sub for Vec3 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.x - rhs.x, self.y - rhs.y, self.z - rhs.z)
    }
}
impl Mul<f32> for Vec3 {
    type Output = Self;
    fn mul(self, rhs: f32) -> Self {
        Self::new(self.x * rhs, self.y * rhs, self.z * rhs)
    }
}
impl AddAssign for Vec3 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Vec3 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Quat {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}
impl Quat {
    pub const fn new(x: f32, y: f32, z: f32, w: f32) -> Self {
        Self { x, y, z, w }
    }
    pub const fn identity() -> Self {
        Self::new(0.0, 0.0, 0.0, 1.0)
    }
    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite() && self.w.is_finite()
    }
    pub fn normalized(self) -> Option<Self> {
        if !self.is_finite() {
            return None;
        }
        let n = (self.x * self.x + self.y * self.y + self.z * self.z + self.w * self.w).sqrt();
        if !n.is_finite() || n <= f32::EPSILON {
            None
        } else {
            Some(Self::new(self.x / n, self.y / n, self.z / n, self.w / n))
        }
    }
    /// Unreal FRotator in degrees: positive pitch raises X-forward; positive
    /// roll lowers Y-right. This is not right-handed Euler pitch/roll.
    pub fn from_euler_degrees(pitch: f32, yaw: f32, roll: f32) -> Self {
        let (p, y, r) = (
            pitch.to_radians() * 0.5,
            yaw.to_radians() * 0.5,
            roll.to_radians() * 0.5,
        );
        let (sp, cp) = (p.sin(), p.cos());
        let (sy, cy) = (y.sin(), y.cos());
        let (sr, cr) = (r.sin(), r.cos());
        Self::new(
            cr * sp * sy - sr * cp * cy,
            -cr * sp * cy - sr * cp * sy,
            cr * cp * sy - sr * sp * cy,
            cr * cp * cy + sr * sp * sy,
        )
    }
    pub fn conjugate(self) -> Self {
        Self::new(-self.x, -self.y, -self.z, self.w)
    }
    pub fn rotate_vec3(self, v: Vec3) -> Vec3 {
        let q = self.normalized().unwrap_or(self);
        let t = q.xyz().cross(v) * 2.0;
        v + t * q.w + q.xyz().cross(t)
    }
    fn xyz(self) -> Vec3 {
        Vec3::new(self.x, self.y, self.z)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mat4 {
    pub m: [[f32; 4]; 4],
}
impl Default for Mat4 {
    fn default() -> Self {
        Self::identity()
    }
}
impl Mat4 {
    pub const fn identity() -> Self {
        Self {
            m: [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [0.0, 0.0, 0.0, 1.0],
            ],
        }
    }
    pub const fn from_rows(m: [[f32; 4]; 4]) -> Self {
        Self { m }
    }
    pub fn is_finite(self) -> bool {
        self.m.iter().flatten().all(|v| v.is_finite())
    }
    pub fn from_quat_translation(rotation: Quat, translation: Vec3) -> Self {
        let q = rotation.normalized().unwrap_or(Quat::identity());
        let (x, y, z, w) = (q.x, q.y, q.z, q.w);
        Self::from_rows([
            [
                1.0 - 2.0 * (y * y + z * z),
                2.0 * (x * y + z * w),
                2.0 * (x * z - y * w),
                0.0,
            ],
            [
                2.0 * (x * y - z * w),
                1.0 - 2.0 * (x * x + z * z),
                2.0 * (y * z + x * w),
                0.0,
            ],
            [
                2.0 * (x * z + y * w),
                2.0 * (y * z - x * w),
                1.0 - 2.0 * (x * x + y * y),
                0.0,
            ],
            [translation.x, translation.y, translation.z, 1.0],
        ])
    }
    pub fn transform_point(self, point: Vec3) -> Vec3 {
        Vec3::new(
            self.m[0][0] * point.x + self.m[1][0] * point.y + self.m[2][0] * point.z + self.m[3][0],
            self.m[0][1] * point.x + self.m[1][1] * point.y + self.m[2][1] * point.z + self.m[3][1],
            self.m[0][2] * point.x + self.m[1][2] * point.y + self.m[2][2] * point.z + self.m[3][2],
        )
    }
}

/// A mathematical value, not a fixed process-memory layout. Memory decoding
/// uses the host-selected [`crate::ue::TransformLayout`].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Transform {
    pub rotation: Quat,
    pub translation: Vec3,
    pub scale3d: Vec3,
}

impl Default for Transform {
    fn default() -> Self {
        Self::identity()
    }
}
impl Transform {
    pub const fn identity() -> Self {
        Self {
            rotation: Quat::identity(),
            translation: Vec3::zero(),
            scale3d: Vec3::one(),
        }
    }
    pub const fn new(rotation: Quat, translation: Vec3, scale3d: Vec3) -> Self {
        Self {
            rotation,
            translation,
            scale3d,
        }
    }
    pub fn is_finite(self) -> bool {
        self.rotation.is_finite() && self.translation.is_finite() && self.scale3d.is_finite()
    }
    pub fn matrix(self) -> Mat4 {
        let q = self.rotation.normalized().unwrap_or(Quat::identity());
        let mut m = Mat4::from_quat_translation(q, self.translation);
        m.m[0][0] *= self.scale3d.x;
        m.m[0][1] *= self.scale3d.x;
        m.m[0][2] *= self.scale3d.x;
        m.m[1][0] *= self.scale3d.y;
        m.m[1][1] *= self.scale3d.y;
        m.m[1][2] *= self.scale3d.y;
        m.m[2][0] *= self.scale3d.z;
        m.m[2][1] *= self.scale3d.z;
        m.m[2][2] *= self.scale3d.z;
        m
    }
    pub fn transform_point(self, point: Vec3) -> Vec3 {
        self.matrix().transform_point(point)
    }
}

#[cfg(test)]
mod unreal_rotation_tests {
    use super::*;

    fn assert_vector(actual: Vec3, expected: Vec3) {
        let delta = actual - expected;
        assert!(
            delta.dot(delta) < 0.000001,
            "actual={actual:?} expected={expected:?}"
        );
    }

    #[test]
    fn positive_unreal_pitch_raises_forward_and_positive_roll_lowers_right() {
        let (s, c) = 30.0_f32.to_radians().sin_cos();
        assert_vector(
            Quat::from_euler_degrees(30.0, 0.0, 0.0).rotate_vec3(Vec3::new(1.0, 0.0, 0.0)),
            Vec3::new(c, 0.0, s),
        );
        assert_vector(
            Quat::from_euler_degrees(0.0, 0.0, 30.0).rotate_vec3(Vec3::new(0.0, 1.0, 0.0)),
            Vec3::new(0.0, c, -s),
        );
        assert_vector(
            Quat::from_euler_degrees(0.0, 90.0, 0.0).rotate_vec3(Vec3::new(1.0, 0.0, 0.0)),
            Vec3::new(0.0, 1.0, 0.0),
        );
    }

    #[test]
    fn quaternion_and_matrix_axes_match_main_rotator_matrix() {
        for (pitch, yaw, roll) in [
            (20.0_f32, 37.0_f32, -11.0_f32),
            (-47.0, 123.0, 31.0),
            (89.9, 235.0, 67.0),
            (-89.9, 359.9, 0.0),
        ] {
            let (sp, cp) = pitch.to_radians().sin_cos();
            let (sy, cy) = yaw.to_radians().sin_cos();
            let (sr, cr) = roll.to_radians().sin_cos();
            // Independent oracle from main::FMatrix(FRotator), not quaternion output.
            let axes = [
                Vec3::new(cp * cy, cp * sy, sp),
                Vec3::new(sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp),
                Vec3::new(-(cr * sp * cy + sr * sy), cy * sr - cr * sp * sy, cr * cp),
            ];
            let rotation = Rotator::new(pitch, yaw, roll).to_quat();
            let matrix = Mat4::from_quat_translation(rotation, Vec3::zero());
            for (index, local) in [
                Vec3::new(1.0, 0.0, 0.0),
                Vec3::new(0.0, 1.0, 0.0),
                Vec3::new(0.0, 0.0, 1.0),
            ]
            .into_iter()
            .enumerate()
            {
                assert_vector(rotation.rotate_vec3(local), axes[index]);
                assert_vector(matrix.transform_point(local), axes[index]);
            }
        }
    }
}
