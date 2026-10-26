use std::sync::Arc;

use crate::math::{Quat, Vec3};

use super::bvh::{segment_triangle, Aabb, Segment, Triangle, TriangleBvh};
use super::convex::Triangulate;
use super::format::DfcolHeader;
use super::DfcolError;

const HEADER_SIZE: usize = 64;
const ACTOR_SIZE: usize = 92;
const MAX_VERTICES_PER_MESH: u32 = 4_000_000;
const MAX_TRIANGLES_PER_MESH: u32 = 4_000_000;
const MAX_HEIGHT_SAMPLES: u64 = 16_000_000;
const MAX_SOURCE_VERTICES: u64 = 24_000_000;
const MAX_SOURCE_TRIANGLES: u64 = 24_000_000;
const MAX_INSTANCE_TRIANGLES: u64 = 128_000_000;
const HOLE_MATERIAL: u8 = 127;
const TRAVERSAL_STACK_SIZE: usize = 128;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SceneStats {
    pub triangle_meshes: u32,
    pub height_fields: u32,
    pub boxes: u32,
    pub convex_meshes: u32,
    pub actors: u32,
    pub source_triangles: u64,
    pub mesh_bvh_nodes: u64,
    pub scene_bvh_nodes: u64,
    pub payload_bytes: u64,
    pub file_bytes: u64,
    pub payload_crc32: u32,
    pub header_crc32: u32,
}

pub struct Scene {
    name: String,
    stats: SceneStats,
    geometry: GeometryPools,
}

struct GeometryPools {
    triangles: Vec<TriangleBvh>,
    height_fields: Vec<HeightField>,
    boxes: Vec<Vec3>,
    convexes: Vec<TriangleBvh>,
    instances: Vec<Instance>,
    scene_nodes: Vec<SceneNode>,
    scene_bounds: Aabb,
}

#[derive(Clone, Copy)]
struct SceneNode {
    bounds: Aabb,
    first: u32,
    count: u32,
}

impl SceneNode {
    fn leaf(self) -> bool {
        self.count & 0x8000_0000 != 0
    }

    fn primitive_count(self) -> usize {
        (self.count & 0x7fff_ffff) as usize
    }
}

struct Instance {
    geometry: GeometryRef,
    world_to_local: Affine,
    bounds: Aabb,
}

#[derive(Clone, Copy)]
enum GeometryRef {
    Triangles(usize),
    HeightField(usize),
    Box(usize),
    Convex(usize),
}

#[derive(Clone)]
struct HeightField {
    rows: u32,
    columns: u32,
    height_scale: f32,
    row_scale: f32,
    column_scale: f32,
    samples: Vec<HeightSample>,
    bounds: Aabb,
    triangle_count: u64,
}

#[derive(Clone, Copy)]
struct HeightSample {
    height: i16,
    material0: u8,
    material1: u8,
}

#[derive(Clone, Copy)]
struct Mat3 {
    c0: Vec3,
    c1: Vec3,
    c2: Vec3,
}

impl Mat3 {
    fn identity() -> Self {
        Self {
            c0: Vec3::new(1.0, 0.0, 0.0),
            c1: Vec3::new(0.0, 1.0, 0.0),
            c2: Vec3::new(0.0, 0.0, 1.0),
        }
    }

    fn apply(self, value: Vec3) -> Vec3 {
        self.c0 * value.x + self.c1 * value.y + self.c2 * value.z
    }

    fn multiply(self, rhs: Self) -> Self {
        Self {
            c0: self.apply(rhs.c0),
            c1: self.apply(rhs.c1),
            c2: self.apply(rhs.c2),
        }
    }

    fn transpose(self) -> Self {
        Self {
            c0: Vec3::new(self.c0.x, self.c1.x, self.c2.x),
            c1: Vec3::new(self.c0.y, self.c1.y, self.c2.y),
            c2: Vec3::new(self.c0.z, self.c1.z, self.c2.z),
        }
    }

    fn inverse(self) -> Option<Self> {
        let r0 = self.c1.cross(self.c2);
        let determinant = self.c0.dot(r0);
        if !determinant.is_finite() || determinant.abs() < 1.0e-12 {
            return None;
        }
        let reciprocal = 1.0 / determinant;
        let r1 = self.c2.cross(self.c0);
        let r2 = self.c0.cross(self.c1);
        let value = Self {
            c0: Vec3::new(r0.x, r1.x, r2.x) * reciprocal,
            c1: Vec3::new(r0.y, r1.y, r2.y) * reciprocal,
            c2: Vec3::new(r0.z, r1.z, r2.z) * reciprocal,
        };
        if value.c0.is_finite() && value.c1.is_finite() && value.c2.is_finite() {
            Some(value)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
struct Affine {
    linear: Mat3,
    translation: Vec3,
}

impl Affine {
    fn apply(self, point: Vec3) -> Vec3 {
        self.linear.apply(point) + self.translation
    }

    fn inverse(self) -> Option<Self> {
        let linear = self.linear.inverse()?;
        let translation = linear.apply(self.translation) * -1.0;
        translation.is_finite().then_some(Self {
            linear,
            translation,
        })
    }
}

fn rotation_matrix(q: Quat) -> Mat3 {
    let x2 = q.x + q.x;
    let y2 = q.y + q.y;
    let z2 = q.z + q.z;
    let xx = x2 * q.x;
    let yy = y2 * q.y;
    let zz = z2 * q.z;
    let xy = x2 * q.y;
    let xz = x2 * q.z;
    let xw = x2 * q.w;
    let yz = y2 * q.z;
    let yw = y2 * q.w;
    let zw = z2 * q.w;
    Mat3 {
        c0: Vec3::new(1.0 - yy - zz, xy + zw, xz - yw),
        c1: Vec3::new(xy - zw, 1.0 - xx - zz, yz + xw),
        c2: Vec3::new(xz + yw, yz - xw, 1.0 - xx - yy),
    }
}

fn mesh_scale_matrix(scale: Vec3, rotation: Quat) -> Mat3 {
    let rotation_matrix = rotation_matrix(rotation);
    let scaled = Mat3 {
        c0: Vec3::new(
            rotation_matrix.c0.x * scale.x,
            rotation_matrix.c0.y * scale.y,
            rotation_matrix.c0.z * scale.z,
        ),
        c1: Vec3::new(
            rotation_matrix.c1.x * scale.x,
            rotation_matrix.c1.y * scale.y,
            rotation_matrix.c1.z * scale.z,
        ),
        c2: Vec3::new(
            rotation_matrix.c2.x * scale.x,
            rotation_matrix.c2.y * scale.y,
            rotation_matrix.c2.z * scale.z,
        ),
    };
    rotation_matrix.transpose().multiply(scaled)
}

fn transform_bounds(bounds: Aabb, transform: Affine) -> Aabb {
    let center = bounds.center();
    let extents = (bounds.upper - bounds.lower) * 0.5;
    let world_center = transform.apply(center);
    let world_extents = Vec3::new(
        transform.linear.c0.x.abs() * extents.x
            + transform.linear.c1.x.abs() * extents.y
            + transform.linear.c2.x.abs() * extents.z,
        transform.linear.c0.y.abs() * extents.x
            + transform.linear.c1.y.abs() * extents.y
            + transform.linear.c2.y.abs() * extents.z,
        transform.linear.c0.z.abs() * extents.x
            + transform.linear.c1.z.abs() * extents.y
            + transform.linear.c2.z.abs() * extents.z,
    );
    let lower = world_center - world_extents;
    let upper = world_center + world_extents;
    let largest = lower
        .x
        .abs()
        .max(lower.y.abs())
        .max(lower.z.abs())
        .max(upper.x.abs())
        .max(upper.y.abs())
        .max(upper.z.abs());
    let padding = 1.0e-3 + largest * 2.0e-7;
    Aabb {
        lower: lower - Vec3::new(padding, padding, padding),
        upper: upper + Vec3::new(padding, padding, padding),
    }
}

impl Scene {
    #[allow(non_snake_case)]
    pub fn Load(bytes: &[u8], name: &str) -> Result<Arc<Self>, DfcolError> {
        let header = DfcolHeader::Parse(bytes)?;
        let mut reader = Reader::new(bytes);
        reader.cursor = HEADER_SIZE;
        let mut triangles = Vec::new();
        let mut height_fields = Vec::new();
        let mut boxes = Vec::new();
        let mut convexes = Vec::new();
        let mut source_vertices = 0u64;
        let mut source_triangles = 0u64;
        let mut mesh_bvh_nodes = 0u64;

        for _ in 0..header.triangle_meshes {
            let record = reader.cursor;
            let vertex_count = reader.u32("triangle vertex count")?;
            let triangle_count = reader.u32("triangle count")?;
            let flags = reader.u32("triangle flags")?;
            if !(3..=MAX_VERTICES_PER_MESH).contains(&vertex_count)
                || !(1..=MAX_TRIANGLES_PER_MESH).contains(&triangle_count)
                || flags & !0x06 != 0
                || (flags & 0x02 != 0 && vertex_count > 65_536)
            {
                return Err(DfcolError::new(format!(
                    "offset {record}: invalid triangle record"
                )));
            }
            let index_size = if flags & 0x02 != 0 { 2 } else { 4 };
            let vertex_bytes = usize::try_from(vertex_count)
                .ok()
                .and_then(|value| value.checked_mul(12))
                .ok_or_else(|| "triangle record size overflow".to_string())?;
            let index_bytes = usize::try_from(triangle_count)
                .ok()
                .and_then(|value| value.checked_mul(3 * index_size))
                .ok_or_else(|| "triangle record size overflow".to_string())?;
            let vertex_start = reader.cursor;
            reader.require(vertex_bytes + index_bytes, "triangle payload")?;
            let mut vertices = Vec::with_capacity(vertex_count as usize);
            for index in 0..vertex_count as usize {
                vertices.push(reader.vec3_at(vertex_start + index * 12, "triangle vertex")?);
            }
            let indices_start = vertex_start + vertex_bytes;
            let mut mesh_triangles = Vec::with_capacity(triangle_count as usize);
            for index in 0..triangle_count as usize {
                let offset = indices_start + index * 3 * index_size;
                let triangle = if index_size == 2 {
                    [
                        reader.u16_at(offset) as u32,
                        reader.u16_at(offset + 2) as u32,
                        reader.u16_at(offset + 4) as u32,
                    ]
                } else {
                    [
                        reader.u32_at(offset),
                        reader.u32_at(offset + 4),
                        reader.u32_at(offset + 8),
                    ]
                };
                if triangle.iter().any(|&item| item >= vertex_count) {
                    return Err(DfcolError::new(format!(
                        "offset {offset}: triangle index out of range"
                    )));
                }
                let points = [
                    vertices[triangle[0] as usize],
                    vertices[triangle[1] as usize],
                    vertices[triangle[2] as usize],
                ];
                if !nondegenerate_triangle(points) {
                    return Err(DfcolError::new(format!(
                        "offset {offset}: degenerate triangle"
                    )));
                }
                let cross = (points[1] - points[0]).cross(points[2] - points[0]);
                if f64::from(cross.dot(cross)) >= 1.0e-6 {
                    mesh_triangles.push(Triangle { points });
                }
            }
            source_vertices = add_limit(
                source_vertices,
                u64::from(vertex_count),
                MAX_SOURCE_VERTICES,
                record,
            )?;
            source_triangles = add_limit(
                source_triangles,
                u64::from(triangle_count),
                MAX_SOURCE_TRIANGLES,
                record,
            )?;
            reader.cursor = indices_start + index_bytes;
            let bvh = TriangleBvh::build(mesh_triangles)?;
            mesh_bvh_nodes += bvh.node_count() as u64;
            triangles.push(bvh);
        }

        for _ in 0..header.height_fields {
            let record = reader.cursor;
            let rows = reader.u32("height-field rows")?;
            let columns = reader.u32("height-field columns")?;
            let height_scale = reader.f32("height scale")?;
            let row_scale = reader.f32("row scale")?;
            let column_scale = reader.f32("column scale")?;
            let flags = reader.u8("height-field flags")?;
            reader.require(3, "height-field reserved bytes")?;
            reader.cursor += 3;
            if rows < 2
                || columns < 2
                || !height_scale.is_finite()
                || !row_scale.is_finite()
                || !column_scale.is_finite()
                || height_scale <= 0.0
                || row_scale <= 0.0
                || column_scale <= 0.0
                || flags & !0x02 != 0
            {
                return Err(DfcolError::new(format!(
                    "offset {record}: invalid height-field record"
                )));
            }
            let sample_count = u64::from(rows)
                .checked_mul(u64::from(columns))
                .ok_or_else(|| "height-field size overflow".to_string())?;
            if sample_count > MAX_HEIGHT_SAMPLES {
                return Err(DfcolError::new(format!(
                    "offset {record}: height-field sample count exceeds resource limit"
                )));
            }
            let sample_bytes = usize::try_from(sample_count)
                .ok()
                .and_then(|value| value.checked_mul(4))
                .ok_or_else(|| "height-field size overflow".to_string())?;
            reader.require(sample_bytes, "height-field samples")?;
            let mut samples = Vec::with_capacity(sample_count as usize);
            for _ in 0..sample_count {
                samples.push(HeightSample {
                    height: reader.i16_at(reader.cursor),
                    material0: reader.bytes[reader.cursor + 2],
                    material1: reader.bytes[reader.cursor + 3],
                });
                reader.cursor += 4;
            }
            let mut min_height = i16::MAX;
            let mut max_height = i16::MIN;
            for sample in &samples {
                min_height = min_height.min(sample.height);
                max_height = max_height.max(sample.height);
            }
            let mut holes = 0u64;
            for row in 0..rows - 1 {
                for column in 0..columns - 1 {
                    let sample = samples[row as usize * columns as usize + column as usize];
                    holes += u64::from((sample.material0 & 0x7f) == HOLE_MATERIAL);
                    holes += u64::from((sample.material1 & 0x7f) == HOLE_MATERIAL);
                }
            }
            let triangle_count = u64::from(rows - 1) * u64::from(columns - 1) * 2 - holes;
            if triangle_count == 0 {
                return Err(DfcolError::new(format!(
                    "offset {record}: height field contains no collision triangles"
                )));
            }
            source_vertices =
                add_limit(source_vertices, sample_count, MAX_SOURCE_VERTICES, record)?;
            source_triangles = add_limit(
                source_triangles,
                triangle_count,
                MAX_SOURCE_TRIANGLES,
                record,
            )?;
            let field = HeightField {
                rows,
                columns,
                height_scale,
                row_scale,
                column_scale,
                samples,
                bounds: Aabb {
                    lower: Vec3::new(0.0, f32::from(min_height) * height_scale, 0.0),
                    upper: Vec3::new(
                        (rows - 1) as f32 * row_scale,
                        f32::from(max_height) * height_scale,
                        (columns - 1) as f32 * column_scale,
                    ),
                },
                triangle_count,
            };
            if !field.bounds.valid() {
                return Err(DfcolError::new(format!(
                    "offset {record}: non-finite height-field bounds"
                )));
            }
            height_fields.push(field);
        }

        for _ in 0..header.boxes {
            let record = reader.cursor;
            let extents = reader.vec3("box half extents")?;
            if extents.x <= 0.0 || extents.y <= 0.0 || extents.z <= 0.0 {
                return Err(DfcolError::new(format!(
                    "offset {record}: invalid box half extents"
                )));
            }
            source_vertices = add_limit(source_vertices, 8, MAX_SOURCE_VERTICES, record)?;
            source_triangles = add_limit(source_triangles, 12, MAX_SOURCE_TRIANGLES, record)?;
            boxes.push(extents);
        }

        for _ in 0..header.convexes {
            let record = reader.cursor;
            let vertex_count = reader.u32("convex vertex count")?;
            let flat_count = reader.u32("convex flat-index count")?;
            let polygon_count = reader.u32("convex polygon count")?;
            if !(4..=256).contains(&vertex_count)
                || !(4..=255).contains(&polygon_count)
                || flat_count < polygon_count * 3
                || flat_count > 4096
            {
                return Err(DfcolError::new(format!(
                    "offset {record}: invalid convex record"
                )));
            }
            let vertex_start = reader.cursor;
            let vertex_bytes = vertex_count as usize * 12;
            reader.require(vertex_bytes + flat_count as usize, "convex payload")?;
            let mut vertices = Vec::with_capacity(vertex_count as usize);
            for index in 0..vertex_count as usize {
                vertices.push(reader.vec3_at(vertex_start + index * 12, "convex vertex")?);
            }
            let indices_start = vertex_start + vertex_bytes;
            let indices = &reader.bytes[indices_start..indices_start + flat_count as usize];
            let triangulation =
                Triangulate(&vertices, indices, polygon_count).map_err(DfcolError::new)?;
            source_vertices = add_limit(
                source_vertices,
                u64::from(vertex_count),
                MAX_SOURCE_VERTICES,
                record,
            )?;
            source_triangles = add_limit(
                source_triangles,
                triangulation.triangles.len() as u64,
                MAX_SOURCE_TRIANGLES,
                record,
            )?;
            let mut convex_triangles = Vec::with_capacity(triangulation.triangles.len());
            for triangle in triangulation.triangles {
                let points = [
                    vertices[triangle[0] as usize],
                    vertices[triangle[1] as usize],
                    vertices[triangle[2] as usize],
                ];
                if f64::from(
                    (points[1] - points[0])
                        .cross(points[2] - points[0])
                        .dot((points[1] - points[0]).cross(points[2] - points[0])),
                ) >= 1.0e-6
                {
                    convex_triangles.push(Triangle { points });
                }
            }
            let bvh = TriangleBvh::build(convex_triangles)?;
            mesh_bvh_nodes += bvh.node_count() as u64;
            convexes.push(bvh);
            reader.cursor = indices_start + flat_count as usize;
        }

        let actor_bytes = usize::try_from(header.actor_count)
            .ok()
            .and_then(|count| count.checked_mul(ACTOR_SIZE))
            .ok_or_else(|| "actor section size overflow".to_string())?;
        if reader.cursor > bytes.len() || actor_bytes != bytes.len() - reader.cursor {
            return Err(DfcolError::new(format!(
                "offset {}: actor section does not end at exact EOF",
                reader.cursor
            )));
        }
        let geometry_limits = [
            triangles.len(),
            height_fields.len(),
            boxes.len(),
            convexes.len(),
        ];
        let mut instances = Vec::with_capacity(header.actor_count as usize);
        let actors_begin = reader.cursor;
        let mut instance_triangles = 0u64;
        for actor_index in 0..header.actor_count as usize {
            let record = actors_begin + actor_index * ACTOR_SIZE;
            let actor_rotation = reader.quat_at(record, "actor rotation")?;
            let actor_position = reader.vec3_at(record + 16, "actor position")?;
            let raw_type = reader.bytes[record + 28];
            if raw_type > 3 {
                return Err(DfcolError::new(format!(
                    "offset {}: invalid actor geometry type",
                    record + 28
                )));
            }
            let geometry_scale = reader.vec3_at(record + 32, "actor geometry scale")?;
            let scale_rotation = reader.quat_at(record + 44, "scale rotation")?;
            let local_rotation = reader.quat_at(record + 60, "local-pose rotation")?;
            let local_position = reader.vec3_at(record + 76, "local-pose position")?;
            let geometry_id = reader.u32_at(record + 88) as usize;
            if geometry_id >= geometry_limits[raw_type as usize] {
                return Err(DfcolError::new(format!(
                    "offset {}: actor geometry id out of range",
                    record + 88
                )));
            }
            let triangle_count = match raw_type {
                0 => triangles[geometry_id].triangle_count() as u64,
                1 => height_fields[geometry_id].triangle_count,
                2 => 12,
                _ => convexes[geometry_id].triangle_count() as u64,
            };
            instance_triangles = add_limit(
                instance_triangles,
                triangle_count,
                MAX_INSTANCE_TRIANGLES,
                record,
            )?;
            let geometry = match raw_type {
                0 => GeometryRef::Triangles(geometry_id),
                1 => GeometryRef::HeightField(geometry_id),
                2 => GeometryRef::Box(geometry_id),
                _ => GeometryRef::Convex(geometry_id),
            };
            let (geometry_bounds, geometry_transform) = match geometry {
                GeometryRef::Triangles(id) | GeometryRef::Convex(id) => {
                    let mesh = if raw_type == 0 {
                        &triangles[id]
                    } else {
                        &convexes[id]
                    };
                    let scale = geometry_scale;
                    if [scale.x, scale.y, scale.z]
                        .iter()
                        .any(|value| value.abs() < 1.0e-6 || value.abs() > 1.0e6)
                        || (raw_type == 3
                            && [scale.x, scale.y, scale.z]
                                .iter()
                                .any(|value| *value <= 0.0))
                    {
                        return Err(DfcolError::new(format!(
                            "offset {}: invalid mesh scale",
                            record + 32
                        )));
                    }
                    (mesh.bounds(), mesh_scale_matrix(scale, scale_rotation))
                }
                GeometryRef::HeightField(id) => {
                    let field = &height_fields[id];
                    if geometry_scale.x < 1.0e-8
                        || geometry_scale.z < 1.0e-8
                        || geometry_scale.y < 0.0001 / 65535.0
                        || !nearly_equal(geometry_scale.x, field.column_scale)
                        || !nearly_equal(geometry_scale.y, field.height_scale)
                        || !nearly_equal(geometry_scale.z, field.row_scale)
                        || !identity_rotation(scale_rotation)
                    {
                        return Err(DfcolError::new(format!(
                            "offset {}: height-field scale integrity mismatch",
                            record + 32
                        )));
                    }
                    (field.bounds, Mat3::identity())
                }
                GeometryRef::Box(id) => {
                    let extents = boxes[id];
                    if !nearly_equal(geometry_scale.x, extents.x)
                        || !nearly_equal(geometry_scale.y, extents.y)
                        || !nearly_equal(geometry_scale.z, extents.z)
                        || !identity_rotation(scale_rotation)
                    {
                        return Err(DfcolError::new(format!(
                            "offset {}: box extent integrity mismatch",
                            record + 32
                        )));
                    }
                    let mut bounds = Aabb::empty();
                    bounds.include(extents * -1.0);
                    bounds.include(extents);
                    (bounds, Mat3::identity())
                }
            };
            let actor_matrix = rotation_matrix(actor_rotation);
            let local_matrix = rotation_matrix(local_rotation);
            let local_to_world = Affine {
                linear: actor_matrix
                    .multiply(local_matrix)
                    .multiply(geometry_transform),
                translation: actor_matrix.apply(local_position) + actor_position,
            };
            let world_to_local = local_to_world.inverse().ok_or_else(|| {
                DfcolError::new(format!("offset {record}: singular actor affine transform"))
            })?;
            let bounds = transform_bounds(geometry_bounds, local_to_world);
            if !bounds.valid() {
                return Err(DfcolError::new(format!(
                    "offset {record}: invalid actor world bounds"
                )));
            }
            instances.push(Instance {
                geometry,
                world_to_local,
                bounds,
            });
        }
        if instances.is_empty() {
            return Err(DfcolError::new("DFCOL contains no actors"));
        }
        let mut scene_bounds = Aabb::empty();
        for instance in &instances {
            scene_bounds.include_bounds(instance.bounds);
        }
        let instance_count = instances.len();
        let mut scene_nodes = Vec::new();
        build_scene_node(&mut instances, &mut scene_nodes, 0, instance_count, 0);
        let scene_bvh_nodes = scene_nodes.len() as u64;
        let stats = SceneStats {
            triangle_meshes: header.triangle_meshes,
            height_fields: header.height_fields,
            boxes: header.boxes,
            convex_meshes: header.convexes,
            actors: header.actor_count,
            source_triangles,
            mesh_bvh_nodes,
            scene_bvh_nodes,
            payload_bytes: header.payload_bytes,
            file_bytes: bytes.len() as u64,
            payload_crc32: header.payload_crc32,
            header_crc32: header.header_crc32,
        };
        Ok(Arc::new(Self {
            name: name.to_string(),
            stats,
            geometry: GeometryPools {
                triangles,
                height_fields,
                boxes,
                convexes,
                instances,
                scene_nodes,
                scene_bounds,
            },
        }))
    }

    #[allow(non_snake_case)]
    pub fn Linecast(&self, from: Vec3, to: Vec3) -> bool {
        if !from.is_finite() || !to.is_finite() || !self.geometry.scene_bounds.valid() {
            return false;
        }
        let query = Segment::new(from, to);
        if !segment_aabb(query, self.geometry.scene_bounds) {
            return false;
        }
        let mut stack = [0usize; TRAVERSAL_STACK_SIZE];
        let mut stack_len = 1;
        stack[0] = 0;
        while stack_len != 0 {
            stack_len -= 1;
            let index = stack[stack_len];
            let node = self.geometry.scene_nodes[index];
            if node.leaf() {
                for instance in &self.geometry.instances
                    [node.first as usize..node.first as usize + node.primitive_count()]
                {
                    if !segment_aabb(query, instance.bounds) {
                        continue;
                    }
                    let local_from = instance.world_to_local.apply(from);
                    let local_to = instance.world_to_local.apply(to);
                    let hit = match instance.geometry {
                        GeometryRef::Triangles(id) => {
                            self.geometry.triangles[id].linecast(local_from, local_to)
                        }
                        GeometryRef::HeightField(id) => {
                            self.geometry.height_fields[id].linecast(local_from, local_to)
                        }
                        GeometryRef::Box(id) => {
                            linecast_box(self.geometry.boxes[id], local_from, local_to)
                        }
                        GeometryRef::Convex(id) => {
                            self.geometry.convexes[id].linecast(local_from, local_to)
                        }
                    };
                    if hit {
                        return true;
                    }
                }
                continue;
            }
            let left = node.first as usize;
            let right = node.count as usize;
            let mut left_entry = 0.0;
            let mut right_entry = 0.0;
            let hit_left = segment_aabb_with_entry(
                query,
                self.geometry.scene_nodes[left].bounds,
                Some(&mut left_entry),
            );
            let hit_right = segment_aabb_with_entry(
                query,
                self.geometry.scene_nodes[right].bounds,
                Some(&mut right_entry),
            );
            let added = usize::from(hit_left) + usize::from(hit_right);
            if stack_len + added > TRAVERSAL_STACK_SIZE {
                return false;
            }
            if hit_left && hit_right {
                if left_entry <= right_entry {
                    stack[stack_len] = right;
                    stack_len += 1;
                    stack[stack_len] = left;
                    stack_len += 1;
                } else {
                    stack[stack_len] = left;
                    stack_len += 1;
                    stack[stack_len] = right;
                    stack_len += 1;
                }
            } else if hit_left {
                stack[stack_len] = left;
                stack_len += 1;
            } else if hit_right {
                stack[stack_len] = right;
                stack_len += 1;
            }
        }
        false
    }

    #[allow(non_snake_case)]
    pub fn Name(&self) -> &str {
        &self.name
    }

    #[allow(non_snake_case)]
    pub fn Stats(&self) -> &SceneStats {
        &self.stats
    }
}

fn linecast_box(extents: Vec3, from: Vec3, to: Vec3) -> bool {
    let query = Segment::new(from, to);
    let vertices = [
        Vec3::new(-extents.x, -extents.y, -extents.z),
        Vec3::new(extents.x, -extents.y, -extents.z),
        Vec3::new(extents.x, extents.y, -extents.z),
        Vec3::new(-extents.x, extents.y, -extents.z),
        Vec3::new(-extents.x, -extents.y, extents.z),
        Vec3::new(extents.x, -extents.y, extents.z),
        Vec3::new(extents.x, extents.y, extents.z),
        Vec3::new(-extents.x, extents.y, extents.z),
    ];
    const TRIANGLES: [[usize; 3]; 12] = [
        [0, 2, 1],
        [0, 3, 2],
        [4, 5, 6],
        [4, 6, 7],
        [0, 1, 5],
        [0, 5, 4],
        [3, 7, 6],
        [3, 6, 2],
        [0, 4, 7],
        [0, 7, 3],
        [1, 2, 6],
        [1, 6, 5],
    ];
    TRIANGLES.iter().any(|triangle| {
        segment_triangle(
            query,
            [
                vertices[triangle[0]],
                vertices[triangle[1]],
                vertices[triangle[2]],
            ],
        )
    })
}

impl HeightField {
    fn vertex(&self, row: u32, column: u32) -> Vec3 {
        let sample = self.samples[row as usize * self.columns as usize + column as usize];
        Vec3::new(
            row as f32 * self.row_scale,
            f32::from(sample.height) * self.height_scale,
            column as f32 * self.column_scale,
        )
    }

    fn linecast(&self, from: Vec3, to: Vec3) -> bool {
        let query = Segment::new(from, to);
        if !segment_aabb(query, self.bounds) {
            return false;
        }
        let dx = query.delta[0];
        let dz = query.delta[2];
        let max_x = f64::from(self.rows - 1) * f64::from(self.row_scale);
        let max_z = f64::from(self.columns - 1) * f64::from(self.column_scale);
        let mut entry = 0.0;
        let mut exit = 1.0;
        if !clip_projected_axis(f64::from(from.x), dx, 0.0, max_x, &mut entry, &mut exit)
            || !clip_projected_axis(f64::from(from.z), dz, 0.0, max_z, &mut entry, &mut exit)
        {
            return false;
        }
        entry = entry.max(0.0);
        exit = exit.min(1.0);
        if entry > exit {
            return false;
        }
        let step_x = if dx > 1.0e-20 {
            1
        } else if dx < -1.0e-20 {
            -1
        } else {
            0
        };
        let step_z = if dz > 1.0e-20 {
            1
        } else if dz < -1.0e-20 {
            -1
        } else {
            0
        };
        let start_x = f64::from(from.x) + dx * entry;
        let start_z = f64::from(from.z) + dz * entry;
        let mut row = initial_cell(start_x, f64::from(self.row_scale), self.rows - 1, step_x);
        let mut column = initial_cell(
            start_z,
            f64::from(self.column_scale),
            self.columns - 1,
            step_z,
        );
        let infinity = f64::INFINITY;
        let delta_x = if step_x != 0 {
            f64::from(self.row_scale) / dx.abs()
        } else {
            infinity
        };
        let delta_z = if step_z != 0 {
            f64::from(self.column_scale) / dz.abs()
        } else {
            infinity
        };
        let mut next_x = if step_x != 0 {
            let boundary = if step_x > 0 { row + 1 } else { row } as f64;
            (boundary * f64::from(self.row_scale) - f64::from(from.x)) / dx
        } else {
            infinity
        };
        let mut next_z = if step_z != 0 {
            let boundary = if step_z > 0 { column + 1 } else { column } as f64;
            (boundary * f64::from(self.column_scale) - f64::from(from.z)) / dz
        } else {
            infinity
        };
        let row_boundary = step_x == 0
            && ((start_x / f64::from(self.row_scale)).round()
                - start_x / f64::from(self.row_scale))
            .abs()
                < 1.0e-9;
        let column_boundary = step_z == 0
            && ((start_z / f64::from(self.column_scale)).round()
                - start_z / f64::from(self.column_scale))
            .abs()
                < 1.0e-9;
        let maximum_steps = u64::from(self.rows) + u64::from(self.columns) + 8;
        for _ in 0..maximum_steps {
            if self.linecast_cell(row, column, query) {
                return true;
            }
            if row_boundary && self.linecast_cell(row - 1, column, query) {
                return true;
            }
            if column_boundary && self.linecast_cell(row, column - 1, query) {
                return true;
            }
            if row_boundary && column_boundary && self.linecast_cell(row - 1, column - 1, query) {
                return true;
            }
            let next = next_x.min(next_z);
            if next > exit + 1.0e-10 || !next.is_finite() {
                break;
            }
            let advance_x = next_x <= next_z + 1.0e-12;
            let advance_z = next_z <= next_x + 1.0e-12;
            if advance_x
                && advance_z
                && (self.linecast_cell(row + step_x, column, query)
                    || self.linecast_cell(row, column + step_z, query))
            {
                return true;
            }
            if advance_x {
                row += step_x;
                next_x += delta_x;
            }
            if advance_z {
                column += step_z;
                next_z += delta_z;
            }
            if row < 0
                || column < 0
                || row >= self.rows as i32 - 1
                || column >= self.columns as i32 - 1
            {
                break;
            }
        }
        false
    }

    fn linecast_cell(&self, row: i32, column: i32, query: Segment) -> bool {
        if row < 0 || column < 0 || row >= self.rows as i32 - 1 || column >= self.columns as i32 - 1
        {
            return false;
        }
        let row = row as u32;
        let column = column as u32;
        let cell = self.samples[row as usize * self.columns as usize + column as usize];
        let hole0 = cell.material0 & 0x7f == HOLE_MATERIAL;
        let hole1 = cell.material1 & 0x7f == HOLE_MATERIAL;
        if hole0 && hole1 {
            return false;
        }
        let v00 = self.vertex(row, column);
        let v01 = self.vertex(row, column + 1);
        let v10 = self.vertex(row + 1, column);
        let v11 = self.vertex(row + 1, column + 1);
        if cell.material0 & 0x80 != 0 {
            (!hole0 && segment_triangle(query, [v10, v00, v11]))
                || (!hole1 && segment_triangle(query, [v01, v11, v00]))
        } else {
            (!hole0 && segment_triangle(query, [v00, v01, v10]))
                || (!hole1 && segment_triangle(query, [v11, v10, v01]))
        }
    }
}

fn clip_projected_axis(
    start: f64,
    delta: f64,
    low: f64,
    high: f64,
    entry: &mut f64,
    exit: &mut f64,
) -> bool {
    if delta.abs() < 1.0e-20 {
        return start >= low && start <= high;
    }
    let mut first = (low - start) / delta;
    let mut second = (high - start) / delta;
    if first > second {
        std::mem::swap(&mut first, &mut second);
    }
    *entry = (*entry).max(first);
    *exit = (*exit).min(second);
    *entry <= *exit
}

fn initial_cell(coordinate: f64, scale: f64, cell_count: u32, step: i32) -> i32 {
    let grid = coordinate / scale;
    let mut cell = grid.floor() as i32;
    let nearest = grid.round();
    if step < 0 && (grid - nearest).abs() < 1.0e-9 {
        cell -= 1;
    }
    cell.clamp(0, cell_count as i32 - 1)
}

fn segment_aabb(query: Segment, bounds: Aabb) -> bool {
    segment_aabb_with_entry(query, bounds, None)
}

fn segment_aabb_with_entry(query: Segment, bounds: Aabb, entry: Option<&mut f64>) -> bool {
    let start = [
        f64::from(query.from.x),
        f64::from(query.from.y),
        f64::from(query.from.z),
    ];
    let low = [
        f64::from(bounds.lower.x),
        f64::from(bounds.lower.y),
        f64::from(bounds.lower.z),
    ];
    let high = [
        f64::from(bounds.upper.x),
        f64::from(bounds.upper.y),
        f64::from(bounds.upper.z),
    ];
    let mut minimum: f64 = 0.0;
    let mut maximum: f64 = 1.0;
    for axis in 0..3 {
        if query.parallel_mask & (1 << axis) != 0 {
            if start[axis] < low[axis] || start[axis] > high[axis] {
                return false;
            }
            continue;
        }
        // Retain direct division: reciprocal multiplication can round slab boundaries differently.
        let mut first = (low[axis] - start[axis]) / query.delta[axis];
        let mut second = (high[axis] - start[axis]) / query.delta[axis];
        if first > second {
            std::mem::swap(&mut first, &mut second);
        }
        minimum = minimum.max(first);
        maximum = maximum.min(second);
        if minimum > maximum {
            return false;
        }
    }
    if let Some(entry) = entry {
        *entry = minimum;
    }
    true
}

fn build_scene_node(
    instances: &mut [Instance],
    nodes: &mut Vec<SceneNode>,
    first: usize,
    count: usize,
    depth: usize,
) -> usize {
    let index = nodes.len();
    let mut bounds = Aabb::empty();
    for instance in &instances[first..first + count] {
        bounds.include_bounds(instance.bounds);
    }
    nodes.push(SceneNode {
        bounds,
        first: 0,
        count: 0,
    });
    if count <= 8 {
        nodes[index].first = first as u32;
        nodes[index].count = 0x8000_0000 | count as u32;
        return index;
    }
    let middle = first
        + super::sah::partition(
            &mut instances[first..first + count],
            depth,
            |instance| instance.bounds,
            |instance| super::sah::bounds_center(instance.bounds),
        );
    let left = build_scene_node(instances, nodes, first, middle - first, depth + 1);
    let right = build_scene_node(instances, nodes, middle, first + count - middle, depth + 1);
    nodes[index].first = left as u32;
    nodes[index].count = right as u32;
    index
}

fn nondegenerate_triangle([a, b, c]: [Vec3; 3]) -> bool {
    let ab = [
        f64::from(b.x) - f64::from(a.x),
        f64::from(b.y) - f64::from(a.y),
        f64::from(b.z) - f64::from(a.z),
    ];
    let ac = [
        f64::from(c.x) - f64::from(a.x),
        f64::from(c.y) - f64::from(a.y),
        f64::from(c.z) - f64::from(a.z),
    ];
    let area = cross(ab, ac);
    let area_squared = dot(area, area);
    area_squared.is_finite() && area_squared > 0.0
}

fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

fn nearly_equal(left: f32, right: f32) -> bool {
    let tolerance = 1.0e-6f32.max(left.abs().max(right.abs()) * 1.0e-5);
    (left - right).abs() <= tolerance
}

fn identity_rotation(rotation: Quat) -> bool {
    rotation.x.abs() <= 1.0e-5
        && rotation.y.abs() <= 1.0e-5
        && rotation.z.abs() <= 1.0e-5
        && (rotation.w.abs() - 1.0).abs() <= 1.0e-5
}

fn add_limit(value: u64, added: u64, limit: u64, offset: usize) -> Result<u64, DfcolError> {
    if added > limit || value > limit - added {
        Err(DfcolError::new(format!(
            "offset {offset}: resource limit exceeded"
        )))
    } else {
        Ok(value + added)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn require(&self, length: usize, description: &str) -> Result<(), DfcolError> {
        if self.cursor > self.bytes.len() || length > self.bytes.len() - self.cursor {
            Err(DfcolError::new(format!(
                "offset {}: truncated {description}",
                self.cursor
            )))
        } else {
            Ok(())
        }
    }

    fn u8(&mut self, description: &str) -> Result<u8, DfcolError> {
        self.require(1, description)?;
        let value = self.bytes[self.cursor];
        self.cursor += 1;
        Ok(value)
    }

    fn u32(&mut self, description: &str) -> Result<u32, DfcolError> {
        self.require(4, description)?;
        let value =
            u32::from_le_bytes(self.bytes[self.cursor..self.cursor + 4].try_into().unwrap());
        self.cursor += 4;
        Ok(value)
    }

    fn f32(&mut self, description: &str) -> Result<f32, DfcolError> {
        Ok(f32::from_bits(self.u32(description)?))
    }

    fn vec3(&mut self, description: &str) -> Result<Vec3, DfcolError> {
        let value = Vec3::new(
            self.f32(description)?,
            self.f32(description)?,
            self.f32(description)?,
        );
        if value.is_finite() {
            Ok(value)
        } else {
            Err(DfcolError::new(format!(
                "offset {}: non-finite {description}",
                self.cursor - 12
            )))
        }
    }

    fn i16_at(&self, offset: usize) -> i16 {
        i16::from_le_bytes(self.bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u16_at(&self, offset: usize) -> u16 {
        u16::from_le_bytes(self.bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }

    fn vec3_at(&self, offset: usize, description: &str) -> Result<Vec3, DfcolError> {
        let value = Vec3::new(
            f32::from_bits(self.u32_at(offset)),
            f32::from_bits(self.u32_at(offset + 4)),
            f32::from_bits(self.u32_at(offset + 8)),
        );
        value
            .is_finite()
            .then_some(value)
            .ok_or_else(|| DfcolError::new(format!("offset {offset}: non-finite {description}")))
    }

    fn quat_at(&self, offset: usize, description: &str) -> Result<Quat, DfcolError> {
        let value = Quat::new(
            f32::from_bits(self.u32_at(offset)),
            f32::from_bits(self.u32_at(offset + 4)),
            f32::from_bits(self.u32_at(offset + 8)),
            f32::from_bits(self.u32_at(offset + 12)),
        );
        let norm = value.x * value.x + value.y * value.y + value.z * value.z + value.w * value.w;
        if !value.is_finite() || !norm.is_finite() || (norm - 1.0).abs() > 1.0e-2 || norm < 1.0e-20
        {
            return Err(DfcolError::new(format!(
                "offset {offset}: invalid {description}"
            )));
        }
        let reciprocal = 1.0 / norm.sqrt();
        Ok(Quat::new(
            value.x * reciprocal,
            value.y * reciprocal,
            value.z * reciprocal,
            value.w * reciprocal,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{segment_triangle, Segment};
    use crate::math::Vec3;

    #[test]
    fn segment_triangle_rejects_non_finite_barycentric_inputs() {
        let triangle = [
            Vec3::new(0.0, 0.0, 0.0),
            Vec3::new(1.0, 0.0, 0.0),
            Vec3::new(0.0, 1.0, 0.0),
        ];
        assert!(!segment_triangle(
            Segment::new(Vec3::new(f32::NAN, 0.0, -1.0), Vec3::new(0.0, 0.0, 1.0)),
            triangle,
        ));
    }
}

#[cfg(test)]
mod sah_scene_tests {
    use super::*;

    #[test]
    fn clustered_scene_covers_each_instance_once_and_matches_direct_box_scan() {
        let mut instances: Vec<_> = (0..1024)
            .map(|i| {
                let center = Vec3::new(
                    if i < 768 {
                        (i % 32) as f32 * 3.0
                    } else {
                        100.0 + (i % 16) as f32 * 10.0
                    },
                    (i / 32) as f32 * 3.0,
                    0.0,
                );
                let extents = if i % 31 == 0 {
                    Vec3::new(20.0, 0.3, 0.5)
                } else {
                    Vec3::one()
                };
                Instance {
                    geometry: GeometryRef::Box(i),
                    world_to_local: Affine {
                        linear: Mat3::identity(),
                        translation: center * -1.0,
                    },
                    bounds: Aabb {
                        lower: center - extents,
                        upper: center + extents,
                    },
                }
            })
            .collect();
        let mut nodes = Vec::new();
        build_scene_node(&mut instances, &mut nodes, 0, 1024, 0);
        fn check(
            nodes: &[SceneNode],
            instances: &[Instance],
            index: usize,
            depth: usize,
            seen: &mut [bool],
        ) {
            assert!(depth <= super::super::sah::MAX_DEPTH);
            let node = nodes[index];
            if node.leaf() {
                assert!(node.primitive_count() <= 8);
                for instance in
                    &instances[node.first as usize..node.first as usize + node.primitive_count()]
                {
                    let GeometryRef::Box(id) = instance.geometry else {
                        panic!("expected box")
                    };
                    assert!(!seen[id]);
                    seen[id] = true;
                    assert!(
                        instance.bounds.lower.x >= node.bounds.lower.x
                            && instance.bounds.upper.x <= node.bounds.upper.x
                    );
                    assert!(
                        instance.bounds.lower.y >= node.bounds.lower.y
                            && instance.bounds.upper.y <= node.bounds.upper.y
                    );
                    assert!(
                        instance.bounds.lower.z >= node.bounds.lower.z
                            && instance.bounds.upper.z <= node.bounds.upper.z
                    );
                }
            } else {
                check(nodes, instances, node.first as usize, depth + 1, seen);
                check(nodes, instances, node.count as usize, depth + 1, seen);
            }
        }
        let mut seen = vec![false; 1024];
        check(&nodes, &instances, 0, 0, &mut seen);
        assert!(seen.iter().all(|v| *v));
        let boxes: Vec<_> = (0..1024)
            .map(|i| {
                if i % 31 == 0 {
                    Vec3::new(20.0, 0.3, 0.5)
                } else {
                    Vec3::one()
                }
            })
            .collect();
        let scene = Scene {
            name: "sah_test".into(),
            stats: SceneStats::default(),
            geometry: GeometryPools {
                triangles: Vec::new(),
                height_fields: Vec::new(),
                boxes,
                convexes: Vec::new(),
                scene_bounds: nodes[0].bounds,
                instances,
                scene_nodes: nodes,
            },
        };
        for i in 0..10000 {
            let from = Vec3::new(
                ((i * 31) % 2600) as f32 * 0.1 - 5.0,
                ((i * 43) % 1050) as f32 * 0.1 - 5.0,
                -3.0,
            );
            let to = Vec3::new(from.x + (i % 5) as f32 - 2.0, from.y + 0.5, 3.0);
            let want = scene.geometry.instances.iter().any(|instance| {
                let GeometryRef::Box(id) = instance.geometry else {
                    panic!("expected box")
                };
                linecast_box(
                    scene.geometry.boxes[id],
                    instance.world_to_local.apply(from),
                    instance.world_to_local.apply(to),
                )
            });
            assert_eq!(scene.Linecast(from, to), want, "ray {i}");
        }
    }
}
