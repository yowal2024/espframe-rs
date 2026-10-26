#![allow(non_snake_case)]

//! Physics-facing validation and reusable DFCOL types.

pub mod dfcol;

use std::sync::Arc;

use crate::math::Vec3;

/// Owns the active DFCOL registry while leaving map choice and archive
/// acquisition to the host application.
pub struct PhysicsRuntime {
    registry: Arc<dfcol::DfcolRegistry>,
}

impl PhysicsRuntime {
    pub fn New() -> Self {
        Self {
            registry: Arc::new(dfcol::DfcolRegistry::New()),
        }
    }

    pub fn WithRegistry(registry: Arc<dfcol::DfcolRegistry>) -> Self {
        Self { registry }
    }

    pub fn Registry(&self) -> Arc<dfcol::DfcolRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn RequestMap(&self, map_name: &str) {
        self.registry.RequestMap(map_name);
    }

    pub fn ClearActiveScene(&self) {
        self.registry.ClearActiveScene();
    }

    pub fn LinecastLocal(&self, from: Vec3, to: Vec3, world_origin: Vec3) -> bool {
        self.registry.LinecastLocal(from, to, world_origin)
    }

    pub fn LinecastLocalBatch(
        &self,
        from: Vec3,
        targets: &[Vec3],
        world_origin: Vec3,
        blocked: &mut [bool],
    ) {
        self.registry
            .LinecastLocalBatch(from, targets, world_origin, blocked);
    }

    pub fn BeginPack(&self, generation: u64) -> bool {
        self.registry.BeginPack(generation)
    }

    pub fn CommitPack(&self, generation: u64, expected_count: u32) -> bool {
        self.registry.CommitPack(generation, expected_count)
    }

    pub fn AbortPack(&self, generation: u64) {
        self.registry.AbortPack(generation);
    }

    pub fn PackStatus(&self) -> dfcol::PackStatus {
        self.registry.GetPackStatus()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PhysicsVec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

pub fn linecast_input_valid(from: PhysicsVec3, to: PhysicsVec3, origin: PhysicsVec3) -> bool {
    if !from.x.is_finite()
        || !from.y.is_finite()
        || !from.z.is_finite()
        || !to.x.is_finite()
        || !to.y.is_finite()
        || !to.z.is_finite()
        || !origin.x.is_finite()
        || !origin.y.is_finite()
        || !origin.z.is_finite()
    {
        return false;
    }
    let dx = to.x - from.x;
    let dy = to.y - from.y;
    let dz = to.z - from.z;
    dx.is_finite() && dy.is_finite() && dz.is_finite() && dx * dx + dy * dy + dz * dz >= 1.0e-6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_finite_and_zero_length_queries() {
        let origin = PhysicsVec3::default();
        assert!(!linecast_input_valid(
            PhysicsVec3 {
                x: f32::NAN,
                ..origin
            },
            origin,
            origin
        ));
        assert!(!linecast_input_valid(origin, origin, origin));
    }

    #[test]
    fn accepts_finite_nonzero_queries() {
        assert!(linecast_input_valid(
            PhysicsVec3::default(),
            PhysicsVec3 {
                x: 1.0,
                ..Default::default()
            },
            PhysicsVec3::default()
        ));
    }
}
