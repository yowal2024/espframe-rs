use crate::math::Vec3;

pub(crate) const LEAF_SIZE: usize = 8;
const TRAVERSAL_STACK_SIZE: usize = 128;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Aabb {
    pub lower: Vec3,
    pub upper: Vec3,
}

impl Aabb {
    pub fn empty() -> Self {
        Self {
            lower: Vec3::new(f32::INFINITY, f32::INFINITY, f32::INFINITY),
            upper: Vec3::new(f32::NEG_INFINITY, f32::NEG_INFINITY, f32::NEG_INFINITY),
        }
    }

    pub fn include(&mut self, point: Vec3) {
        self.lower.x = self.lower.x.min(point.x);
        self.lower.y = self.lower.y.min(point.y);
        self.lower.z = self.lower.z.min(point.z);
        self.upper.x = self.upper.x.max(point.x);
        self.upper.y = self.upper.y.max(point.y);
        self.upper.z = self.upper.z.max(point.z);
    }

    pub fn include_bounds(&mut self, other: Self) {
        self.include(other.lower);
        self.include(other.upper);
    }

    pub fn center(self) -> Vec3 {
        (self.lower + self.upper) * 0.5
    }

    pub fn valid(self) -> bool {
        self.lower.is_finite()
            && self.upper.is_finite()
            && self.lower.x <= self.upper.x
            && self.lower.y <= self.upper.y
            && self.lower.z <= self.upper.z
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Triangle {
    pub points: [Vec3; 3],
}

impl Triangle {
    fn bounds(self) -> Aabb {
        let mut bounds = Aabb::empty();
        for point in self.points {
            bounds.include(point);
        }
        bounds
    }
}

#[derive(Clone, Copy, Debug)]
struct Node {
    bounds: Aabb,
    first: u32,
    count: u32,
}

impl Node {
    fn leaf(self) -> bool {
        self.count & 0x8000_0000 != 0
    }

    fn primitive_count(self) -> usize {
        (self.count & 0x7fff_ffff) as usize
    }
}

#[derive(Clone)]
pub(crate) struct TriangleBvh {
    triangles: Vec<Triangle>,
    nodes: Vec<Node>,
}

impl TriangleBvh {
    pub fn build(mut triangles: Vec<Triangle>) -> Result<Self, String> {
        if triangles.is_empty() {
            return Err("triangle BVH has no triangles".into());
        }
        let mut nodes = Vec::new();
        let triangle_count = triangles.len();
        build_node(&mut triangles, &mut nodes, 0, triangle_count, 0);
        Ok(Self { triangles, nodes })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn bounds(&self) -> Aabb {
        self.nodes[0].bounds
    }

    pub fn triangle_count(&self) -> usize {
        self.triangles.len()
    }

    pub fn linecast(&self, from: Vec3, to: Vec3) -> bool {
        if !from.is_finite() || !to.is_finite() || self.nodes.is_empty() {
            return false;
        }
        let query = Segment::new(from, to);
        if !segment_aabb(query, self.nodes[0].bounds, None) {
            return false;
        }
        let mut stack = [0usize; TRAVERSAL_STACK_SIZE];
        let mut stack_len = 1;
        stack[0] = 0;
        while stack_len != 0 {
            stack_len -= 1;
            let index = stack[stack_len];
            let node = self.nodes[index];
            if node.leaf() {
                let begin = node.first as usize;
                for triangle in &self.triangles[begin..begin + node.primitive_count()] {
                    if segment_triangle(query, triangle.points) {
                        return true;
                    }
                }
                continue;
            }
            let left = node.first as usize;
            let right = node.count as usize;
            let mut left_entry = 0.0;
            let mut right_entry = 0.0;
            let hit_left = segment_aabb(query, self.nodes[left].bounds, Some(&mut left_entry));
            let hit_right = segment_aabb(query, self.nodes[right].bounds, Some(&mut right_entry));
            match (hit_left, hit_right) {
                (true, true) if left_entry <= right_entry => {
                    if stack_len + 2 > TRAVERSAL_STACK_SIZE {
                        return false;
                    }
                    stack[stack_len] = right;
                    stack_len += 1;
                    stack[stack_len] = left;
                    stack_len += 1;
                }
                (true, true) => {
                    if stack_len + 2 > TRAVERSAL_STACK_SIZE {
                        return false;
                    }
                    stack[stack_len] = left;
                    stack_len += 1;
                    stack[stack_len] = right;
                    stack_len += 1;
                }
                (true, false) => {
                    if stack_len == TRAVERSAL_STACK_SIZE {
                        return false;
                    }
                    stack[stack_len] = left;
                    stack_len += 1;
                }
                (false, true) => {
                    if stack_len == TRAVERSAL_STACK_SIZE {
                        return false;
                    }
                    stack[stack_len] = right;
                    stack_len += 1;
                }
                (false, false) => {}
            }
        }
        false
    }
}

fn build_node(
    triangles: &mut [Triangle],
    nodes: &mut Vec<Node>,
    first: usize,
    count: usize,
    depth: usize,
) -> usize {
    let node_index = nodes.len();
    let mut bounds = Aabb::empty();
    for triangle in &triangles[first..first + count] {
        bounds.include_bounds(triangle.bounds());
    }
    nodes.push(Node {
        bounds,
        first: 0,
        count: 0,
    });
    if count <= LEAF_SIZE {
        nodes[node_index].first = first as u32;
        nodes[node_index].count = 0x8000_0000 | count as u32;
        return node_index;
    }
    let middle = first
        + super::sah::partition(
            &mut triangles[first..first + count],
            depth,
            |triangle| triangle.bounds(),
            |triangle| {
                let [a, b, c] = triangle.points;
                [
                    (a.x as f64 + b.x as f64 + c.x as f64) / 3.0,
                    (a.y as f64 + b.y as f64 + c.y as f64) / 3.0,
                    (a.z as f64 + b.z as f64 + c.z as f64) / 3.0,
                ]
            },
        );
    let left = build_node(triangles, nodes, first, middle - first, depth + 1);
    let right = build_node(triangles, nodes, middle, first + count - middle, depth + 1);
    nodes[node_index].first = left as u32;
    nodes[node_index].count = right as u32;
    node_index
}

#[derive(Clone, Copy)]
pub(super) struct Segment {
    pub(super) from: Vec3,
    pub(super) delta: [f64; 3],
    inverse: [f64; 3],
    length_squared: f64,
    pub(super) parallel_mask: u8,
}

impl Segment {
    pub(super) fn new(from: Vec3, to: Vec3) -> Self {
        let delta = [
            f64::from(to.x) - f64::from(from.x),
            f64::from(to.y) - f64::from(from.y),
            f64::from(to.z) - f64::from(from.z),
        ];
        let mut inverse = [0.0; 3];
        let mut parallel_mask = 0;
        for axis in 0..3 {
            if delta[axis].abs() < 1.0e-20 {
                parallel_mask |= 1 << axis;
            } else {
                inverse[axis] = 1.0 / delta[axis];
            }
        }
        Self {
            from,
            delta,
            inverse,
            length_squared: dot(delta, delta),
            parallel_mask,
        }
    }
}

fn segment_aabb(query: Segment, bounds: Aabb, entry: Option<&mut f64>) -> bool {
    let start = [
        query.from.x as f64,
        query.from.y as f64,
        query.from.z as f64,
    ];
    let low = [
        bounds.lower.x as f64,
        bounds.lower.y as f64,
        bounds.lower.z as f64,
    ];
    let high = [
        bounds.upper.x as f64,
        bounds.upper.y as f64,
        bounds.upper.z as f64,
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
        let mut first = (low[axis] - start[axis]) * query.inverse[axis];
        let mut second = (high[axis] - start[axis]) * query.inverse[axis];
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

pub(super) fn segment_triangle(query: Segment, points: [Vec3; 3]) -> bool {
    let [a, b, c] = points;
    let e1 = [
        f64::from(b.x) - f64::from(a.x),
        f64::from(b.y) - f64::from(a.y),
        f64::from(b.z) - f64::from(a.z),
    ];
    let e2 = [
        f64::from(c.x) - f64::from(a.x),
        f64::from(c.y) - f64::from(a.y),
        f64::from(c.z) - f64::from(a.z),
    ];
    let p = cross(query.delta, e2);
    let determinant = dot(e1, p);
    let scale_squared = query.length_squared * dot(e1, e1) * dot(e2, e2);
    if determinant * determinant <= (scale_squared * 1.0e-24).max(1.0e-36) {
        return false;
    }
    let inverse_det = 1.0 / determinant;
    let t = [
        f64::from(query.from.x) - f64::from(a.x),
        f64::from(query.from.y) - f64::from(a.y),
        f64::from(query.from.z) - f64::from(a.z),
    ];
    let u = dot(t, p) * inverse_det;
    if !(-1.0e-8..=1.0 + 1.0e-8).contains(&u) {
        return false;
    }
    let q = cross(t, e1);
    let v = dot(query.delta, q) * inverse_det;
    if v < -1.0e-8 || u + v > 1.0 + 1.0e-8 {
        return false;
    }
    let parameter = dot(e2, q) * inverse_det;
    (-1.0e-8..=1.0 + 1.0e-8).contains(&parameter)
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

#[cfg(test)]
mod sah_build_tests {
    use super::*;

    fn depth_and_leaf_cap(bvh: &TriangleBvh, index: usize) -> usize {
        let node = bvh.nodes[index];
        if node.leaf() {
            assert!(node.primitive_count() <= LEAF_SIZE);
            assert!(node.first as usize + node.primitive_count() <= bvh.triangles.len());
            return 0;
        }
        1 + depth_and_leaf_cap(bvh, node.first as usize)
            .max(depth_and_leaf_cap(bvh, node.count as usize))
    }

    #[test]
    fn finite_extreme_centers_and_skewed_distributions_stay_stack_safe() {
        let triangles: Vec<_> = (-125..=125)
            .flat_map(|power| {
                let x = 2.0f32.powi(power);
                (0..16).map(move |i| Triangle {
                    points: [
                        Vec3::new(x, i as f32, 0.0),
                        Vec3::new(x, i as f32 + 0.25, 0.0),
                        Vec3::new(x, i as f32, 0.25),
                    ],
                })
            })
            .collect();
        let bvh = TriangleBvh::build(triangles).unwrap();
        assert!(depth_and_leaf_cap(&bvh, 0) <= super::super::sah::MAX_DEPTH);
        let huge = Triangle {
            points: [
                Vec3::new(f32::MAX * 0.9, 0.0, 0.0),
                Vec3::new(f32::MAX * 0.9, 1.0, 0.0),
                Vec3::new(f32::MAX * 0.9, 0.0, 1.0),
            ],
        };
        let bvh = TriangleBvh::build(vec![huge; 4096]).unwrap();
        assert!(bvh.bounds().valid());
        assert!(depth_and_leaf_cap(&bvh, 0) <= super::super::sah::MAX_DEPTH);
    }

    #[test]
    fn triangle_tree_matches_direct_primitive_scan_across_unequal_clusters() {
        let triangles: Vec<_> = (0..1024)
            .map(|i| {
                let x = if i < 768 {
                    (i % 32) as f32
                } else {
                    100.0 + (i % 16) as f32 * 3.0
                };
                let y = (i / 32) as f32;
                let width = if i % 31 == 0 { 12.0 } else { 0.75 };
                Triangle {
                    points: [
                        Vec3::new(x, y, 0.0),
                        Vec3::new(x + width, y, 0.0),
                        Vec3::new(x, y + 0.75, 0.0),
                    ],
                }
            })
            .collect();
        let bvh = TriangleBvh::build(triangles.clone()).unwrap();
        for i in 0..20000 {
            let from = Vec3::new(
                ((i * 31) % 1600) as f32 * 0.1 + 0.025,
                ((i * 43) % 400) as f32 * 0.1 + 0.025,
                -2.0,
            );
            let to = Vec3::new(from.x + ((i % 5) as f32 - 2.0) * 0.25, from.y, 2.0);
            let want = triangles
                .iter()
                .any(|t| segment_triangle(Segment::new(from, to), t.points));
            assert_eq!(bvh.linecast(from, to), want, "ray {i}");
        }
    }
}
