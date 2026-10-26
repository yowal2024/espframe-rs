use super::*;

fn push(parser: &mut KernelInputParser, kind: u16, code: u16, value: i32) {
    let mut output = Vec::new();
    parser.Push(
        KernelInputValue {
            type_: kind,
            code,
            value,
        },
        &mut output,
    );
    assert!(output.is_empty(), "只有 SYN_REPORT 才交付槽位状态");
}

fn frame(parser: &mut KernelInputParser) -> Vec<InputEvent> {
    let mut output = Vec::new();
    parser.Push(
        KernelInputValue {
            type_: EV_SYN,
            code: SYN_REPORT,
            value: 0,
        },
        &mut output,
    );
    output.sort_by_key(|event| match event {
        InputEvent::Pointer { pointer, .. } => *pointer,
        InputEvent::Key { .. } => panic!("main 触摸通路忽略 EV_KEY"),
    });
    output
}

fn pointer(slot: i32, x: i32, y: i32, action: u32) -> InputEvent {
    InputEvent::Pointer {
        pointer: slot as u32,
        x: x as f32,
        y: y as f32,
        action,
    }
}

#[test]
fn new_and_default_begin_with_only_slot_zero_moving() {
    for mut parser in [KernelInputParser::new(), KernelInputParser::default()] {
        assert_eq!(frame(&mut parser), [pointer(0, 0, 0, ACTION_MOVE)]);
        assert_eq!(frame(&mut parser), [pointer(0, 0, 0, ACTION_MOVE)]);
    }
    // 对应 main 的单槽默认构造：坐标归零、动作 UP；初始化槽 0 时才改为 MOVE。
    let slot = SlotState::default();
    assert_eq!((slot.x, slot.y, slot.action), (0, 0, ACTION_UP));
}

#[test]
fn coordinates_update_independently_without_a_tracking_id() {
    let mut parser = KernelInputParser::new();
    push(&mut parser, EV_ABS, ABS_MT_POSITION_X, -120);
    assert_eq!(frame(&mut parser), [pointer(0, -120, 0, ACTION_MOVE)]);
    push(&mut parser, EV_ABS, ABS_MT_POSITION_Y, 240);
    assert_eq!(frame(&mut parser), [pointer(0, -120, 240, ACTION_MOVE)]);
    push(&mut parser, EV_ABS, ABS_MT_POSITION_X, 360);
    assert_eq!(frame(&mut parser), [pointer(0, 360, 240, ACTION_MOVE)]);
}

#[test]
fn down_persists_until_selecting_the_slot_again_sets_move() {
    let mut parser = KernelInputParser::new();
    push(&mut parser, EV_ABS, ABS_MT_TRACKING_ID, 42);
    push(&mut parser, EV_ABS, ABS_MT_POSITION_X, 100);
    for _ in 0..2 {
        assert_eq!(frame(&mut parser), [pointer(0, 100, 0, ACTION_DOWN)]);
    }
    push(&mut parser, EV_ABS, ABS_MT_POSITION_Y, 200);
    assert_eq!(frame(&mut parser), [pointer(0, 100, 200, ACTION_DOWN)]);
    // 即使仍选中同一槽，ABS_MT_SLOT 也会把 DOWN 改为 MOVE。
    push(&mut parser, EV_ABS, ABS_MT_SLOT, 0);
    assert_eq!(frame(&mut parser), [pointer(0, 100, 200, ACTION_MOVE)]);
}

#[test]
fn up_and_coordinates_remain_in_every_syn_until_the_next_slot_selection() {
    let mut parser = KernelInputParser::new();
    push(&mut parser, EV_ABS, ABS_MT_SLOT, 3);
    push(&mut parser, EV_ABS, ABS_MT_POSITION_X, 100);
    push(&mut parser, EV_ABS, ABS_MT_POSITION_Y, 200);
    push(&mut parser, EV_ABS, ABS_MT_TRACKING_ID, -1);
    let released = [
        pointer(0, 0, 0, ACTION_MOVE),
        pointer(3, 100, 200, ACTION_UP),
    ];
    for _ in 0..3 {
        assert_eq!(frame(&mut parser), released);
    }
    push(&mut parser, EV_ABS, ABS_MT_SLOT, 3);
    assert_eq!(
        frame(&mut parser),
        [
            pointer(0, 0, 0, ACTION_MOVE),
            pointer(3, 100, 200, ACTION_MOVE)
        ]
    );
}

#[test]
fn only_minus_one_tracking_id_means_up() {
    let mut parser = KernelInputParser::new();
    for (tracking, action) in [
        (i32::MIN, ACTION_DOWN),
        (-2, ACTION_DOWN),
        (-1, ACTION_UP),
        (0, ACTION_DOWN),
        (i32::MAX, ACTION_DOWN),
    ] {
        push(&mut parser, EV_ABS, ABS_MT_TRACKING_ID, tracking);
        assert_eq!(frame(&mut parser), [pointer(0, 0, 0, action)]);
    }
}

#[test]
fn negative_and_sparse_slots_keep_independent_state_without_dense_allocation() {
    let mut parser = KernelInputParser::new();
    for (slot, x) in [(i32::MIN, 10), (-1, 20), (i32::MAX, 30)] {
        push(&mut parser, EV_ABS, ABS_MT_SLOT, slot);
        push(&mut parser, EV_ABS, ABS_MT_POSITION_X, x);
    }
    push(&mut parser, EV_ABS, ABS_MT_SLOT, -1);
    push(&mut parser, EV_ABS, ABS_MT_POSITION_Y, 40);
    push(&mut parser, EV_ABS, ABS_MT_TRACKING_ID, -1);
    assert_eq!(
        frame(&mut parser),
        [
            pointer(0, 0, 0, ACTION_MOVE),
            pointer(i32::MAX, 30, 0, ACTION_MOVE),
            pointer(i32::MIN, 10, 0, ACTION_MOVE),
            pointer(-1, 20, 40, ACTION_UP),
        ]
    );
}

#[test]
fn keys_unknown_records_and_other_syn_codes_do_not_change_touch_state() {
    let mut parser = KernelInputParser::new();
    push(&mut parser, EV_ABS, ABS_MT_POSITION_X, 72);
    let baseline = frame(&mut parser);
    for (kind, code, value) in [
        (EV_KEY, KEY_VOLUMEUP, 1),
        (EV_KEY, KEY_VOLUMEDOWN, 0),
        (EV_KEY, KEY_VOLUMEDOWN, 2),
        (EV_KEY, KEY_VOLUMEDOWN, -1),
        (EV_ABS, u16::MAX, 400),
        (EV_SYN, 1, 1),
        (u16::MAX, 0, 800),
    ] {
        push(&mut parser, kind, code, value);
        assert_eq!(frame(&mut parser), baseline);
    }
}
