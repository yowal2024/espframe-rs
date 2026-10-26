use super::bvh::Aabb;

pub(super) const MAX_DEPTH: usize = 48;
const BINS: usize = 16;

#[derive(Clone, Copy)]
struct Bin {
    bounds: Aabb,
    count: usize,
}

fn area(bounds: Aabb) -> f64 {
    if !bounds.valid() {
        return 0.0;
    }
    let x = bounds.upper.x as f64 - bounds.lower.x as f64;
    let y = bounds.upper.y as f64 - bounds.lower.y as f64;
    let z = bounds.upper.z as f64 - bounds.lower.z as f64;
    2.0 * (x * y + y * z + z * x)
}

pub(super) fn bounds_center(bounds: Aabb) -> [f64; 3] {
    [
        (bounds.lower.x as f64 + bounds.upper.x as f64) * 0.5,
        (bounds.lower.y as f64 + bounds.upper.y as f64) * 0.5,
        (bounds.lower.z as f64 + bounds.upper.z as f64) * 0.5,
    ]
}

fn bin(value: f64, low: f64, scale: f64) -> usize {
    (((value - low) * scale) as usize).min(BINS - 1)
}

pub(super) fn partition<T>(
    items: &mut [T],
    depth: usize,
    bounds: impl Fn(&T) -> Aabb,
    center: impl Fn(&T) -> [f64; 3],
) -> usize {
    let mut low = [f64::INFINITY; 3];
    let mut high = [f64::NEG_INFINITY; 3];
    let mut finite = true;
    for item in items.iter() {
        let c = center(item);
        for axis in 0..3 {
            finite &= c[axis].is_finite();
            low[axis] = low[axis].min(c[axis]);
            high[axis] = high[axis].max(c[axis]);
        }
    }
    let spread = [high[0] - low[0], high[1] - low[1], high[2] - low[2]];
    let fallback_axis = if spread[1] > spread[0] && spread[1] >= spread[2] {
        1
    } else if spread[2] > spread[0] {
        2
    } else {
        0
    };
    // Preserve the median partition (including within-leaf order) unless SAH
    // offers a meaningful surface-cost improvement. Uniform grids otherwise
    // pay for different any-hit primitive ordering without better bounds.
    let middle = items.len() / 2;
    items.select_nth_unstable_by(middle, |a, b| {
        center(a)[fallback_axis].total_cmp(&center(b)[fallback_axis])
    });
    let mut left_bounds = Aabb::empty();
    let mut right_bounds = Aabb::empty();
    for item in &items[..middle] {
        left_bounds.include_bounds(bounds(item));
    }
    for item in &items[middle..] {
        right_bounds.include_bounds(bounds(item));
    }
    let median_cost =
        area(left_bounds) * middle as f64 + area(right_bounds) * (items.len() - middle) as f64;
    // Each child must still fit leaves of eight at depth MAX_DEPTH. This
    // bounds even deliberately skewed SAH trees without oversized leaves.
    let capacity = 8u128 << MAX_DEPTH.saturating_sub(depth + 1);
    let mut best = None;
    let mut best_cost = f64::INFINITY;
    if finite {
        for axis in 0..3 {
            if !spread[axis].is_finite() || spread[axis] <= 0.0 {
                continue;
            }
            let scale = BINS as f64 / spread[axis];
            let empty = Bin {
                bounds: Aabb::empty(),
                count: 0,
            };
            let mut bins = [empty; BINS];
            for item in items.iter() {
                let index = bin(center(item)[axis], low[axis], scale);
                bins[index].count += 1;
                bins[index].bounds.include_bounds(bounds(item));
            }
            let mut suffix = [empty; BINS];
            let mut acc = empty;
            for i in (0..BINS).rev() {
                if bins[i].count != 0 {
                    acc.bounds.include_bounds(bins[i].bounds);
                }
                acc.count += bins[i].count;
                suffix[i] = acc;
            }
            let mut left = empty;
            for i in 0..BINS - 1 {
                if bins[i].count != 0 {
                    left.bounds.include_bounds(bins[i].bounds);
                }
                left.count += bins[i].count;
                let right = suffix[i + 1];
                if left.count == 0
                    || right.count == 0
                    || left.count as u128 > capacity
                    || right.count as u128 > capacity
                {
                    continue;
                }
                let cost =
                    area(left.bounds) * left.count as f64 + area(right.bounds) * right.count as f64;
                if cost < best_cost {
                    best_cost = cost;
                    best = Some((axis, i, scale));
                }
            }
        }
    }
    if best_cost >= median_cost * 0.98 {
        return middle;
    }
    if let Some((axis, split_bin, scale)) = best {
        let mut left = 0;
        let mut right = items.len();
        while left < right {
            if bin(center(&items[left])[axis], low[axis], scale) <= split_bin {
                left += 1;
            } else {
                right -= 1;
                items.swap(left, right);
            }
        }
        if left != 0 && left != items.len() {
            return left;
        }
    }
    middle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::Vec3;

    fn box_at(x: f32, y: f32) -> Aabb {
        Aabb {
            lower: Vec3::new(x, y, 0.0),
            upper: Vec3::new(x + 1.0, y + 1.0, 1.0),
        }
    }
    fn center(b: &Aabb) -> [f64; 3] {
        [
            ((b.lower.x as f64) + b.upper.x as f64) * 0.5,
            ((b.lower.y as f64) + b.upper.y as f64) * 0.5,
            ((b.lower.z as f64) + b.upper.z as f64) * 0.5,
        ]
    }

    #[test]
    fn separates_unequal_clusters_instead_of_overlapping_them() {
        let mut boxes: Vec<_> = (0..12)
            .map(|i| box_at(i as f32 * 0.1, 0.0))
            .chain((0..4).map(|i| box_at(100.0 + i as f32 * 0.1, 0.0)))
            .collect();
        let split = partition(&mut boxes, 0, |b| *b, center);
        assert!(boxes[..split].iter().all(|b| b.upper.x < 10.0));
        assert!(boxes[split..].iter().all(|b| b.lower.x > 90.0));
    }

    #[test]
    fn last_level_keeps_both_children_within_leaf_capacity() {
        let mut boxes: Vec<_> = (0..12)
            .map(|i| box_at(i as f32 * 0.1, 0.0))
            .chain((0..4).map(|i| box_at(100.0 + i as f32 * 0.1, 0.0)))
            .collect();
        let split = partition(&mut boxes, MAX_DEPTH - 1, |b| *b, center);
        assert!(split <= 8 && boxes.len() - split <= 8);
    }

    #[test]
    fn identical_and_nonfinite_centers_always_make_progress() {
        for center_value in [[0.0; 3], [f64::INFINITY; 3], [f64::NAN; 3]] {
            let mut boxes = vec![box_at(0.0, 0.0); 257];
            let split = partition(&mut boxes, 0, |b| *b, |_| center_value);
            assert!(split > 0 && split < boxes.len());
            assert!(boxes.iter().all(|b| b.valid()));
        }
    }

    #[test]
    fn skewed_subtree_fits_remaining_depth_without_oversized_leaves() {
        fn walk(items: &mut [Aabb], depth: usize) {
            assert!(depth <= MAX_DEPTH);
            if items.len() <= 8 {
                return;
            }
            let split = partition(items, depth, |b| *b, center);
            let (left, right) = items.split_at_mut(split);
            walk(left, depth + 1);
            walk(right, depth + 1);
        }
        let mut boxes: Vec<_> = (0..1024)
            .map(|i| box_at(2.0f32.powi((i / 8) - 64), 0.0))
            .collect();
        // Only seven levels remain: an unrestricted SAH split would isolate
        // distant boxes and exhaust the depth budget with primitives left.
        walk(&mut boxes, MAX_DEPTH - 7);
    }
}
