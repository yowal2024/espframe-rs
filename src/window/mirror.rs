//! Typed display snapshots and layout in compositor logical coordinates.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use super::{Orientation, Size, WindowError};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DisplayQueryMode {
    #[default]
    Auto,
    Jni,
    Binder,
}

impl DisplayQueryMode {
    pub(super) fn query(
        self,
        is_remote: impl FnOnce() -> Result<bool, WindowError>,
        jni: Option<impl FnOnce() -> Result<Vec<DisplaySnapshot>, WindowError>>,
        binder: Option<impl FnOnce() -> Result<Vec<DisplaySnapshot>, WindowError>>,
    ) -> Result<Vec<DisplaySnapshot>, WindowError> {
        match self {
            Self::Jni => jni.ok_or(WindowError::AbiUnavailable("JNI display backend"))?(),
            Self::Binder => binder.ok_or(WindowError::AbiUnavailable("Binder display backend"))?(),
            Self::Auto => match (jni, binder) {
                (jni, Some(binder)) => {
                    let remote = is_remote()?;
                    crate::espframe_log!(
                        "surface.mirror.auto_backend",
                        "remote={} selected={}",
                        remote,
                        if remote { "Binder" } else { "JNI" }
                    );
                    if remote {
                        binder()
                    } else {
                        jni.ok_or(WindowError::AbiUnavailable("JNI display backend"))?()
                    }
                }
                (Some(jni), None) => jni(),
                (None, None) => Err(WindowError::AbiUnavailable("display enumeration backend")),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplaySnapshot {
    pub display_id: i32,
    pub layer_stack: u32,
    pub orientation: Orientation,
    pub size: Size,
}

impl DisplaySnapshot {
    pub fn from_java(
        display_id: i32,
        layer_stack: i32,
        width: i32,
        height: i32,
        rotation: i32,
    ) -> Result<Self, WindowError> {
        if display_id < 0 || layer_stack < 0 || width <= 0 || height <= 0 {
            return Err(WindowError::Backend(
                "invalid JNI display information".into(),
            ));
        }
        let orientation = match rotation {
            0 => Orientation::Portrait,
            1 => Orientation::Landscape,
            2 => Orientation::ReversePortrait,
            3 => Orientation::ReverseLandscape,
            _ => return Err(WindowError::Backend("invalid JNI display rotation".into())),
        };
        Ok(Self {
            display_id,
            layer_stack: layer_stack as u32,
            orientation,
            size: Size::new(width as u32, height as u32),
        })
    }
}

pub(super) fn normalize_displays(
    mut displays: Vec<DisplaySnapshot>,
) -> Result<Vec<DisplaySnapshot>, WindowError> {
    displays.sort_by_key(|display| display.display_id);
    let mut result: Vec<DisplaySnapshot> = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for display in displays {
        if !ids.insert(display.display_id) {
            return Err(WindowError::Backend(
                "duplicate JNI display identity".into(),
            ));
        }
        if let Some(previous) = result
            .iter()
            .find(|previous| previous.layer_stack == display.layer_stack)
        {
            if previous.size != display.size || previous.orientation != display.orientation {
                return Err(WindowError::Backend(
                    "conflicting shared display layer stack".into(),
                ));
            }
            continue;
        }
        result.push(display);
    }
    Ok(result)
}

pub(super) fn snapshot_changed(
    before: &[DisplaySnapshot],
    after: &[DisplaySnapshot],
    previous_source: Option<u32>,
    source: u32,
) -> bool {
    before != after || previous_source != Some(source)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct MirrorTransform {
    pub scale: f32,
    pub x: f32,
    pub y: f32,
}

pub(super) fn mirror_layout(
    source: Size,
    target: &DisplaySnapshot,
) -> Result<MirrorTransform, WindowError> {
    if !source.IsValid() || !target.size.IsValid() {
        return Err(WindowError::InvalidSize);
    }
    let scale = (f64::from(target.size.width) / f64::from(source.width))
        .min(f64::from(target.size.height) / f64::from(source.height));
    Ok(MirrorTransform {
        scale: scale as f32,
        x: ((f64::from(target.size.width) - f64::from(source.width) * scale) * 0.5) as f32,
        y: ((f64::from(target.size.height) - f64::from(source.height) * scale) * 0.5) as f32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(id: i32, stack: i32, width: i32, height: i32, rotation: i32) -> DisplaySnapshot {
        DisplaySnapshot::from_java(id, stack, width, height, rotation).unwrap()
    }

    #[test]
    fn rejects_invalid_jni_fields_without_unsigned_wrapping() {
        for (id, stack, w, h, rotation) in [
            (-1, 1, 100, 200, 0),
            (1, -1, 100, 200, 0),
            (1, 1, 0, 200, 0),
            (1, 1, 100, -1, 0),
            (1, 1, 100, 200, 4),
        ] {
            assert!(DisplaySnapshot::from_java(id, stack, w, h, rotation).is_err());
        }
    }

    #[test]
    fn logical_size_fit_does_not_repeat_display_rotation() {
        for rotation in 0..4 {
            let target = display(1, 2, 1920, 1080, rotation);
            let transform = mirror_layout(Size::new(2400, 1080), &target).unwrap();
            assert!((transform.scale - 0.8).abs() < 0.0001);
            assert_eq!(transform.x, 0.0);
            assert_eq!(transform.y, 108.0);
        }
    }

    #[test]
    fn snapshot_changes_recompute_size_and_validate_shared_stacks() {
        let one = display(0, 0, 1080, 2400, 0);
        let same = display(1, 0, 1080, 2400, 0);
        assert_eq!(
            normalize_displays(vec![same, one.clone()]).unwrap(),
            vec![one.clone()]
        );
        assert!(normalize_displays(vec![one, display(1, 0, 1920, 1080, 1)]).is_err());
        assert_ne!(
            mirror_layout(Size::new(2400, 1080), &display(1, 1, 1920, 1080, 1)).unwrap(),
            mirror_layout(Size::new(2400, 1080), &display(1, 1, 1280, 720, 1)).unwrap()
        );
    }

    #[test]
    fn duplicate_identity_is_rejected_even_after_shared_stack_deduplication() {
        let a = display(0, 0, 1080, 2400, 0);
        let b = display(1, 0, 1080, 2400, 0);
        let duplicate = display(1, 2, 1920, 1080, 0);
        assert!(normalize_displays(vec![a, b, duplicate]).is_err());
    }

    #[test]
    fn changing_primary_stack_invalidates_unchanged_mirror_snapshot() {
        let displays = vec![display(0, 0, 1080, 2400, 0), display(1, 1, 1920, 1080, 1)];
        assert!(!snapshot_changed(&displays, &displays, Some(0), 0));
        assert!(snapshot_changed(&displays, &displays, Some(0), 1));
    }

    type Query = fn() -> Result<Vec<DisplaySnapshot>, WindowError>;

    #[test]
    fn forced_display_modes_never_call_the_other_backend() {
        let expected = vec![display(1, 2, 1920, 1080, 1)];
        assert_eq!(
            DisplayQueryMode::Jni
                .query(
                    || panic!("forced JNI must not probe"),
                    Some(|| Ok(expected.clone())),
                    Some(|| panic!("Binder called in JNI mode")),
                )
                .unwrap(),
            expected
        );
        assert_eq!(
            DisplayQueryMode::Binder
                .query(
                    || panic!("forced Binder must not probe"),
                    Some(|| panic!("JNI called in Binder mode")),
                    Some(|| Ok(expected.clone())),
                )
                .unwrap(),
            expected
        );
        assert_eq!(
            DisplayQueryMode::Jni.query(
                || panic!("forced JNI must not probe"),
                Some(|| Err(WindowError::Stopped)),
                Some(|| panic!("forced JNI must not fall back")),
            ),
            Err(WindowError::Stopped)
        );
        assert_eq!(
            DisplayQueryMode::Binder.query(
                || panic!("forced Binder must not probe"),
                Some(|| panic!("forced Binder must not fall back")),
                Some(|| Err(WindowError::InvalidSize)),
            ),
            Err(WindowError::InvalidSize)
        );
        assert_eq!(
            DisplayQueryMode::Jni.query(
                || panic!("missing forced JNI must not probe"),
                None::<Query>,
                Some(|| panic!("missing JNI must not fall back"))
            ),
            Err(WindowError::AbiUnavailable("JNI display backend"))
        );
        assert_eq!(
            DisplayQueryMode::Binder.query(
                || panic!("missing forced Binder must not probe"),
                Some(|| panic!("missing Binder must not fall back")),
                None::<Query>
            ),
            Err(WindowError::AbiUnavailable("Binder display backend"))
        );
    }

    #[test]
    fn auto_remote_selects_only_binder_after_probe() {
        let calls = std::cell::RefCell::new(Vec::new());
        let expected = vec![display(1, 2, 1920, 1080, 1)];
        assert_eq!(
            DisplayQueryMode::Auto
                .query(
                    || { calls.borrow_mut().push("probe"); Ok(true) },
                    Some(|| panic!("remote Auto must not query JNI")),
                    Some(|| {
                        calls.borrow_mut().push("Binder");
                        Ok(expected.clone())
                    }),
                )
                .unwrap(),
            expected
        );
        assert_eq!(*calls.borrow(), ["probe", "Binder"]);
        assert!(DisplayQueryMode::Auto
            .query(
                || Ok(true),
                Some(|| panic!("remote empty result must not query JNI")),
                Some(|| Ok(Vec::new()))
            )
            .unwrap()
            .is_empty());
        assert_eq!(
            DisplayQueryMode::Auto.query(
                || Ok(true),
                Some(|| panic!("remote Binder error must not query JNI")),
                Some(|| Err(WindowError::InvalidSize))
            ),
            Err(WindowError::InvalidSize)
        );
    }

    #[test]
    fn auto_local_selects_only_jni_and_never_falls_back_on_empty_or_error() {
        let calls = std::cell::RefCell::new(Vec::new());
        assert!(DisplayQueryMode::Auto.query(
            || { calls.borrow_mut().push("probe"); Ok(false) },
            Some(|| { calls.borrow_mut().push("JNI"); Ok(Vec::new()) }),
            Some(|| panic!("local Binder must not run")),
        ).unwrap().is_empty());
        assert_eq!(*calls.borrow(), ["probe", "JNI"]);
        assert_eq!(DisplayQueryMode::Auto.query(
            || Ok(false), Some(|| Err(WindowError::Stopped)),
            Some(|| panic!("JNI failure must not fall back to local Binder")),
        ), Err(WindowError::Stopped));
        assert_eq!(DisplayQueryMode::Auto.query(
            || Ok(false), None::<Query>,
            Some(|| panic!("missing JNI must not fall back to local Binder")),
        ), Err(WindowError::AbiUnavailable("JNI display backend")));
    }

    #[test]
    fn auto_probe_error_never_guesses_a_backend() {
        assert_eq!(DisplayQueryMode::Auto.query(
            || Err(WindowError::Stopped),
            Some(|| panic!("failed probe must not query JNI")),
            Some(|| panic!("failed probe must not query Binder")),
        ), Err(WindowError::Stopped));
    }

    #[test]
    fn auto_uses_the_available_backend_and_reports_no_backend() {
        assert_eq!(DisplayQueryMode::default(), DisplayQueryMode::Auto);
        let expected = vec![display(1, 2, 1920, 1080, 1)];
        assert_eq!(
            DisplayQueryMode::Auto
                .query(|| panic!("JNI-only build must not probe"), Some(|| Ok(expected.clone())), None::<Query>)
                .unwrap(),
            expected
        );
        assert_eq!(
            DisplayQueryMode::Auto
                .query(|| Ok(true), None::<Query>, Some(|| Ok(expected.clone())))
                .unwrap(),
            expected
        );
        assert_eq!(
            DisplayQueryMode::Auto.query(|| panic!("JNI-only build must not probe"), Some(|| Err(WindowError::Stopped)), None::<Query>),
            Err(WindowError::Stopped)
        );
        assert_eq!(
            DisplayQueryMode::Auto.query(|| Ok(true), None::<Query>, Some(|| Err(WindowError::InvalidSize))),
            Err(WindowError::InvalidSize)
        );
        assert_eq!(
            DisplayQueryMode::Auto.query(|| panic!("no backends must not probe"), None::<Query>, None::<Query>),
            Err(WindowError::AbiUnavailable("display enumeration backend"))
        );
    }
}
