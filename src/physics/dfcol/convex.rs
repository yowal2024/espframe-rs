use std::collections::{HashMap, HashSet};

use crate::math::Vec3;

#[derive(Clone, Copy, Debug, Default)]
struct DVec3 {
    x: f64,
    y: f64,
    z: f64,
}

impl DVec3 {
    fn from_vec3(value: Vec3) -> Self {
        Self {
            x: f64::from(value.x),
            y: f64::from(value.y),
            z: f64::from(value.z),
        }
    }

    fn add(self, rhs: Self) -> Self {
        Self {
            x: self.x + rhs.x,
            y: self.y + rhs.y,
            z: self.z + rhs.z,
        }
    }

    fn sub(self, rhs: Self) -> Self {
        Self {
            x: self.x - rhs.x,
            y: self.y - rhs.y,
            z: self.z - rhs.z,
        }
    }

    fn scale(self, scalar: f64) -> Self {
        Self {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }

    fn dot(self, rhs: Self) -> f64 {
        self.x * rhs.x + self.y * rhs.y + self.z * rhs.z
    }

    fn cross(self, rhs: Self) -> Self {
        Self {
            x: self.y * rhs.z - self.z * rhs.y,
            y: self.z * rhs.x - self.x * rhs.z,
            z: self.x * rhs.y - self.y * rhs.x,
        }
    }

    fn length(self) -> f64 {
        self.dot(self).sqrt()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Triangulation {
    pub triangles: Vec<[u32; 3]>,
    pub was_ambiguous: bool,
}

/// Recover polygon boundaries from PhysX's flattened convex index stream.
///
/// The stream has no face delimiters.  We therefore search the bounded set of
/// partitions whose undirected edges form a closed oriented manifold, then
/// select the lowest-residual valid convex solution.
#[allow(non_snake_case)] // PascalCase preserves the native DFCOL compatibility API.
pub fn Triangulate(
    vertices: &[Vec3],
    flat_indices: &[u8],
    expected_polygons: u32,
) -> Result<Triangulation, String> {
    if !(4..=256).contains(&vertices.len()) {
        return Err("convex vertex count is outside [4, 256]".into());
    }
    if !(4..=255).contains(&expected_polygons) {
        return Err("convex polygon count is outside [4, 255]".into());
    }
    if flat_indices.len() > 4096
        || flat_indices.len() < expected_polygons as usize * 3
        || !flat_indices.len().is_multiple_of(2)
    {
        return Err("convex flat-index count is invalid".into());
    }
    if expected_polygons as isize != 2 - vertices.len() as isize + (flat_indices.len() / 2) as isize
    {
        return Err("convex counts fail the Euler manifold check".into());
    }
    if vertices.iter().any(|point| !point.is_finite()) {
        return Err("convex contains a non-finite vertex".into());
    }
    let extent = vertices.iter().fold(
        (
            DVec3 {
                x: f64::INFINITY,
                y: f64::INFINITY,
                z: f64::INFINITY,
            },
            DVec3 {
                x: f64::NEG_INFINITY,
                y: f64::NEG_INFINITY,
                z: f64::NEG_INFINITY,
            },
        ),
        |(mut low, mut high), point| {
            let point = DVec3::from_vec3(*point);
            low.x = low.x.min(point.x);
            low.y = low.y.min(point.y);
            low.z = low.z.min(point.z);
            high.x = high.x.max(point.x);
            high.y = high.y.max(point.y);
            high.z = high.z.max(point.z);
            (low, high)
        },
    );
    let extent_len = extent.1.sub(extent.0).length();
    if !extent_len.is_finite() || extent_len <= 0.0 {
        return Err("convex has zero or invalid extent".into());
    }
    let duplicate_distance = (extent_len * 1.0e-12).max(1.0e-9).powi(2) * 0.01;
    for left in 0..vertices.len() {
        for right in left + 1..vertices.len() {
            let delta = DVec3::from_vec3(vertices[left]).sub(DVec3::from_vec3(vertices[right]));
            if delta.dot(delta) <= duplicate_distance {
                return Err("convex contains duplicate vertices".into());
            }
        }
    }
    let mut used = vec![false; vertices.len()];
    for &index in flat_indices {
        let index = index as usize;
        if index >= vertices.len() {
            return Err("convex flat index is out of range".into());
        }
        used[index] = true;
    }
    if used.iter().any(|used| !used) {
        return Err("convex flat indices omit a vertex".into());
    }

    let mut search = Search {
        vertices,
        indices: flat_indices,
        expected_faces: expected_polygons as usize,
        edge_state: HashMap::new(),
        open_edges: HashSet::new(),
        last_possible: build_future_edge_index(vertices.len(), flat_indices),
        tolerance: Tolerance::new(extent_len),
        faces: Vec::new(),
        best: None,
        solutions: 0,
        valid_solutions: 0,
        work: 0,
    };
    search.Run(0, 0);
    if search.work > 2_000_000 {
        return Err("convex topology recovery exceeded its work limit".into());
    }
    if search.solutions > 64 {
        return Err("convex topology has excessive boundary ambiguity".into());
    }
    if search.solutions == 0 {
        return Err("flat indices cannot form a closed oriented manifold".into());
    }
    let (triangles, score) = search
        .best
        .take()
        .ok_or_else(|| "recovered convex topology has invalid geometry".to_string())?;
    let _ = score;
    Ok(Triangulation {
        triangles,
        was_ambiguous: search.valid_solutions > 1,
    })
}

struct Search<'a> {
    vertices: &'a [Vec3],
    indices: &'a [u8],
    expected_faces: usize,
    edge_state: HashMap<u16, i8>,
    open_edges: HashSet<u16>,
    last_possible: HashMap<u16, usize>,
    tolerance: Tolerance,
    faces: Vec<(usize, usize)>,
    best: Option<(Vec<[u32; 3]>, f64)>,
    solutions: usize,
    valid_solutions: usize,
    work: usize,
}

#[derive(Clone, Copy)]
struct Tolerance {
    extent: f64,
    area: f64,
    volume: f64,
}

impl Tolerance {
    fn new(extent: f64) -> Self {
        Self {
            extent,
            area: (extent * extent * 1.0e-18).max(1.0e-18),
            volume: (extent * extent * extent * 1.0e-24).max(1.0e-27),
        }
    }
}

impl<'a> Search<'a> {
    #[allow(non_snake_case)]
    fn Run(&mut self, position: usize, unique_edges: usize) {
        self.work += 1;
        if self.work > 2_000_000 || self.solutions > 64 {
            return;
        }
        let face_index = self.faces.len();
        if face_index == self.expected_faces {
            if position == self.indices.len()
                && self.edge_state.values().all(|state| *state == 2)
                && unique_edges == self.indices.len() / 2
            {
                self.solutions += 1;
                if let Some((triangles, score)) = self.evaluate() {
                    self.valid_solutions += 1;
                    if self
                        .best
                        .as_ref()
                        .is_none_or(|(_, best_score)| score < *best_score)
                    {
                        self.best = Some((triangles, score));
                    }
                }
            }
            return;
        }
        if position >= self.indices.len() {
            return;
        }
        let remaining_faces = self.expected_faces - face_index - 1;
        let minimum_future = remaining_faces * 3;
        if self.indices.len() - position < minimum_future + 3 {
            return;
        }
        let max_length = self
            .vertices
            .len()
            .min(self.indices.len() - position - minimum_future);
        let mut seen = [false; 256];
        for length in 1..=max_length {
            self.work += 1;
            if self.work > 2_000_000 || self.solutions > 64 {
                return;
            }
            let index = self.indices[position + length - 1] as usize;
            if seen[index] {
                break;
            }
            seen[index] = true;
            if length < 3 {
                continue;
            }
            let end = position + length;
            let remaining_indices = self.indices.len() - end;
            if remaining_faces != 0 && remaining_indices > remaining_faces * self.vertices.len() {
                continue;
            }
            let mut changes = Vec::new();
            let mut next_unique = unique_edges;
            let mut valid = true;
            for offset in position..end {
                let from = self.indices[offset];
                let to = self.indices[if offset + 1 == end {
                    position
                } else {
                    offset + 1
                }];
                if !self.add_edge(from, to, &mut changes, &mut next_unique) {
                    valid = false;
                    break;
                }
            }
            if valid {
                let future_slots = self.indices.len() - end;
                let open_count = self.open_edges.len();
                valid = next_unique <= self.indices.len() / 2
                    && open_count <= future_slots
                    && (future_slots - open_count).is_multiple_of(2)
                    && self.open_edges_have_future_matches(end);
            }
            if valid {
                self.faces.push((position, end));
                self.Run(end, next_unique);
                self.faces.pop();
            }
            for (key, previous) in changes.into_iter().rev() {
                if previous == 0 {
                    self.edge_state.remove(&key);
                    self.open_edges.remove(&key);
                } else {
                    self.edge_state.insert(key, previous);
                    self.open_edges.insert(key);
                }
            }
            if self.work > 2_000_000 || self.solutions > 64 {
                return;
            }
        }
    }

    fn add_edge(
        &mut self,
        from: u8,
        to: u8,
        changes: &mut Vec<(u16, i8)>,
        unique_edges: &mut usize,
    ) -> bool {
        if from == to {
            return false;
        }
        let (low, high) = if from < to { (from, to) } else { (to, from) };
        let key = u16::from(low) << 8 | u16::from(high);
        let direction = if from < to { 1 } else { -1 };
        let previous = *self.edge_state.get(&key).unwrap_or(&0);
        if previous == 2 || previous == direction {
            return false;
        }
        changes.push((key, previous));
        if previous == 0 {
            self.edge_state.insert(key, direction);
            self.open_edges.insert(key);
            *unique_edges += 1;
        } else {
            self.edge_state.insert(key, 2);
            self.open_edges.remove(&key);
        }
        true
    }

    fn open_edges_have_future_matches(&self, future_begin: usize) -> bool {
        self.open_edges.iter().all(|key| {
            let low = (*key >> 8) as u8;
            let high = *key as u8;
            let direction = self.edge_state[key];
            let reverse = if direction == 1 {
                u16::from(high) << 8 | u16::from(low)
            } else {
                u16::from(low) << 8 | u16::from(high)
            };
            self.last_possible
                .get(&reverse)
                .copied()
                .is_some_and(|last| last >= future_begin)
        })
    }

    fn evaluate(&self) -> Option<(Vec<[u32; 3]>, f64)> {
        let mut triangles = Vec::with_capacity(self.indices.len() - self.faces.len() * 2);
        let mut volume = 0.0f64;
        let mut score = 0.0f64;
        for &(begin, end) in &self.faces {
            let first = self.indices[begin] as usize;
            let mut center = DVec3::default();
            for &index in &self.indices[begin..end] {
                center = center.add(DVec3::from_vec3(self.vertices[index as usize]));
            }
            center = center.scale(1.0 / (end - begin) as f64);
            let mut normal = DVec3::default();
            for offset in begin..end {
                let next = if offset + 1 == end { begin } else { offset + 1 };
                normal = normal.add(
                    DVec3::from_vec3(self.vertices[self.indices[offset] as usize])
                        .sub(center)
                        .cross(
                            DVec3::from_vec3(self.vertices[self.indices[next] as usize])
                                .sub(center),
                        ),
                );
            }
            let normal_len = normal.length();
            if !normal_len.is_finite() || normal_len <= self.tolerance.area {
                return None;
            }
            let normalized = normal.scale(1.0 / normal_len);
            let mut face_residual = 0.0f64;
            for &index in &self.indices[begin..end] {
                let distance =
                    normalized.dot(DVec3::from_vec3(self.vertices[index as usize]).sub(center));
                face_residual = face_residual.max(distance.abs());
            }
            let mut minimum_distance = f64::INFINITY;
            let mut maximum_distance = f64::NEG_INFINITY;
            for vertex in self.vertices {
                let distance = normalized.dot(DVec3::from_vec3(*vertex).sub(center));
                minimum_distance = minimum_distance.min(distance);
                maximum_distance = maximum_distance.max(distance);
            }
            let supporting_violation = maximum_distance.max(0.0).min((-minimum_distance).max(0.0));
            score += (face_residual + supporting_violation) / self.tolerance.extent;
            for offset in begin + 1..end - 1 {
                let second = self.indices[offset] as usize;
                let third = self.indices[offset + 1] as usize;
                let a = DVec3::from_vec3(self.vertices[first]);
                let b = DVec3::from_vec3(self.vertices[second]);
                let c = DVec3::from_vec3(self.vertices[third]);
                let cross = b.sub(a).cross(c.sub(a));
                if !cross.dot(cross).is_finite() || cross.dot(cross) <= 0.0 {
                    return None;
                }
                triangles.push([self.indices[begin] as u32, second as u32, third as u32]);
                volume += a.dot(b.cross(c));
            }
        }
        let expected_triangles = self.indices.len() - self.faces.len() * 2;
        if triangles.len() != expected_triangles
            || !volume.is_finite()
            || volume.abs() <= self.tolerance.volume * 6.0
            || !score.is_finite()
        {
            return None;
        }
        Some((triangles, score))
    }
}

fn build_future_edge_index(vertex_count: usize, indices: &[u8]) -> HashMap<u16, usize> {
    let mut last_possible: HashMap<u16, usize> = HashMap::new();
    for offset in 0..indices.len().saturating_sub(1) {
        let directed = u16::from(indices[offset]) << 8 | u16::from(indices[offset + 1]);
        last_possible
            .entry(directed)
            .and_modify(|last| *last = (*last).max(offset))
            .or_insert(offset);
    }
    for begin in 0..indices.len() {
        let mut seen = vec![false; vertex_count];
        let maximum_end = indices.len().min(begin + vertex_count);
        for end in begin..maximum_end {
            let index = indices[end] as usize;
            if seen[index] {
                break;
            }
            seen[index] = true;
            if end - begin + 1 < 3 {
                continue;
            }
            let directed = u16::from(indices[end]) << 8 | u16::from(indices[begin]);
            last_possible
                .entry(directed)
                .and_modify(|last| *last = (*last).max(begin))
                .or_insert(begin);
        }
    }
    last_possible
}
