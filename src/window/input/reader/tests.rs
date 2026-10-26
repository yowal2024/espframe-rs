use super::super::{
    InputEvent, KernelInputParser, WindowError, ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_SLOT,
    ABS_MT_TRACKING_ID, ACTION_DOWN, ACTION_MOVE, ACTION_UP, EV_ABS, EV_KEY, EV_SYN, SYN_REPORT,
};
use super::{InputSource, KernelInputReader};
use std::collections::VecDeque;
use std::io::{self, ErrorKind};

enum Step {
    Bytes(Vec<u8>),
    Error(ErrorKind),
}

struct ScriptedSource {
    steps: VecDeque<Step>,
    buffers_before_read: Vec<Vec<u8>>,
}

impl ScriptedSource {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            buffers_before_read: Vec::new(),
        }
    }

    fn assert_finished(&self) {
        assert!(self.steps.is_empty(), "仍有预期的读取尚未执行");
    }
}

impl InputSource for ScriptedSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert_eq!(
            buffer.len(),
            8,
            "每次读取一个完整的 kernel_input_value 缓冲"
        );
        self.buffers_before_read.push(buffer.to_vec());
        match self.steps.pop_front().expect("发生了额外的读取") {
            Step::Bytes(bytes) => {
                assert!(bytes.len() <= buffer.len());
                // 模拟 read 只覆盖实际收到的前缀，未覆盖的字节保持原值。
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Step::Error(kind) => Err(io::Error::new(kind, "scripted read error")),
        }
    }
}

// 按字段编码，避免依赖结构体填充、指针对齐或 Unix 系统调用。
fn encode(kind: u16, code: u16, value: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&code.to_ne_bytes());
    bytes.extend_from_slice(&value.to_ne_bytes());
    bytes
}

fn value(kind: u16, code: u16, value: i32) -> Step {
    Step::Bytes(encode(kind, code, value))
}

fn pointer(slot: u32, x: f32, y: f32, action: u32) -> InputEvent {
    InputEvent::Pointer {
        pointer: slot,
        x,
        y,
        action,
    }
}

fn sort_pointers(output: &mut [InputEvent]) {
    output.sort_by_key(|event| match event {
        InputEvent::Pointer { pointer, .. } => *pointer,
        InputEvent::Key { .. } => panic!("main 触摸解析器不输出 EV_KEY"),
    });
}

#[test]
fn successive_reads_preserve_multitouch_and_repeat_up_at_each_syn() {
    let values = [
        (EV_ABS, ABS_MT_SLOT, 1),
        (EV_ABS, ABS_MT_TRACKING_ID, 17),
        (EV_ABS, ABS_MT_POSITION_X, 300),
        (EV_ABS, ABS_MT_POSITION_Y, 400),
        (EV_ABS, ABS_MT_SLOT, 0),
        (EV_ABS, ABS_MT_TRACKING_ID, 21),
        (EV_ABS, ABS_MT_POSITION_X, 100),
        (EV_ABS, ABS_MT_POSITION_Y, 200),
        (EV_SYN, SYN_REPORT, 0),
        (EV_ABS, ABS_MT_SLOT, 1),
        (EV_ABS, ABS_MT_POSITION_X, 310),
        (EV_ABS, ABS_MT_POSITION_Y, 410),
        (EV_ABS, ABS_MT_SLOT, 0),
        (EV_ABS, ABS_MT_POSITION_X, 110),
        (EV_ABS, ABS_MT_POSITION_Y, 210),
        (EV_SYN, SYN_REPORT, 0),
        (EV_ABS, ABS_MT_SLOT, 1),
        (EV_ABS, ABS_MT_TRACKING_ID, -1),
        (EV_ABS, ABS_MT_SLOT, 0),
        (EV_ABS, ABS_MT_TRACKING_ID, -1),
        (EV_SYN, SYN_REPORT, 0),
        (EV_SYN, SYN_REPORT, 0),
    ];
    let expected = [
        [
            pointer(0, 100.0, 200.0, ACTION_DOWN),
            pointer(1, 300.0, 400.0, ACTION_DOWN),
        ],
        [
            pointer(0, 110.0, 210.0, ACTION_MOVE),
            pointer(1, 310.0, 410.0, ACTION_MOVE),
        ],
        [
            pointer(0, 110.0, 210.0, ACTION_UP),
            pointer(1, 310.0, 410.0, ACTION_UP),
        ],
        [
            pointer(0, 110.0, 210.0, ACTION_UP),
            pointer(1, 310.0, 410.0, ACTION_UP),
        ],
    ];
    let mut source = ScriptedSource::new(
        values
            .iter()
            .map(|&(kind, code, data)| value(kind, code, data)),
    );
    let mut reader = KernelInputReader::new();
    let mut parser = KernelInputParser::new();
    let mut output = Vec::new();
    let mut frame = 0;

    for (index, &(kind, code, _)) in values.iter().enumerate() {
        output.clear();
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        if (kind, code) == (EV_SYN, SYN_REPORT) {
            sort_pointers(&mut output);
            assert_eq!(output, expected[frame]);
            frame += 1;
        } else {
            assert!(output.is_empty());
        }
        assert_eq!(source.buffers_before_read.len(), index + 1);
    }
    assert_eq!(frame, expected.len());
    source.assert_finished();
}

#[test]
fn every_read_error_replays_syn_without_changing_down_or_clearing_up() {
    let errors = [
        ErrorKind::Interrupted,
        ErrorKind::WouldBlock,
        ErrorKind::PermissionDenied,
        ErrorKind::BrokenPipe,
        ErrorKind::Other,
    ];
    let mut steps = vec![
        value(EV_ABS, ABS_MT_TRACKING_ID, 42),
        value(EV_ABS, ABS_MT_POSITION_X, 120),
        value(EV_ABS, ABS_MT_POSITION_Y, 240),
        value(EV_SYN, SYN_REPORT, 0),
    ];
    steps.extend(errors.into_iter().map(Step::Error));
    steps.extend([
        value(EV_ABS, ABS_MT_TRACKING_ID, -1),
        value(EV_SYN, SYN_REPORT, 0),
        Step::Error(ErrorKind::Interrupted),
    ]);
    let mut source = ScriptedSource::new(steps);
    let mut reader = KernelInputReader::new();
    let mut parser = KernelInputParser::new();
    let mut output = Vec::new();
    for _ in 0..4 {
        reader.read(&mut source, &mut parser, &mut output).unwrap();
    }
    assert_eq!(output, [pointer(0, 120.0, 240.0, ACTION_DOWN)]);

    for _ in errors {
        output.clear();
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        assert_eq!(output, [pointer(0, 120.0, 240.0, ACTION_DOWN)]);
    }
    output.clear();
    reader.read(&mut source, &mut parser, &mut output).unwrap();
    assert!(output.is_empty());
    for _ in 0..2 {
        output.clear();
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        assert_eq!(output, [pointer(0, 120.0, 240.0, ACTION_UP)]);
    }
    source.assert_finished();
}

#[test]
fn replayed_key_records_are_ignored_and_later_syn_still_works() {
    let errors = [
        ErrorKind::Interrupted,
        ErrorKind::WouldBlock,
        ErrorKind::PermissionDenied,
    ];
    let key_bytes = encode(EV_KEY, 114, 1);
    let mut steps = vec![Step::Bytes(key_bytes.clone())];
    steps.extend(errors.into_iter().map(Step::Error));
    steps.push(value(EV_SYN, SYN_REPORT, 0));
    let mut source = ScriptedSource::new(steps);
    let mut reader = KernelInputReader::new();
    let mut parser = KernelInputParser::new();
    let mut output = Vec::new();

    for _ in 0..=errors.len() {
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        assert!(output.is_empty());
    }
    reader.read(&mut source, &mut parser, &mut output).unwrap();
    assert_eq!(output, [pointer(0, 0.0, 0.0, ACTION_MOVE)]);
    assert!(source.buffers_before_read[1..]
        .iter()
        .all(|bytes| bytes == &key_bytes));
    source.assert_finished();
}

#[test]
fn first_read_error_uses_zero_syn_and_reports_the_initial_slot_zero_move() {
    let mut source = ScriptedSource::new([
        Step::Error(ErrorKind::Interrupted),
        Step::Error(ErrorKind::PermissionDenied),
        value(EV_KEY, 115, 1),
    ]);
    let mut reader = KernelInputReader::new();
    let mut parser = KernelInputParser::new();
    let mut output = Vec::new();

    for _ in 0..2 {
        output.clear();
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        assert_eq!(output, [pointer(0, 0.0, 0.0, ACTION_MOVE)]);
    }
    output.clear();
    reader.read(&mut source, &mut parser, &mut output).unwrap();
    assert!(output.is_empty());
    assert!(source
        .buffers_before_read
        .iter()
        .all(|bytes| bytes == &[0; 8]));
    source.assert_finished();
}

#[test]
fn short_read_overwrites_prefix_and_immediately_updates_using_the_old_tail() {
    let first = encode(EV_ABS, ABS_MT_POSITION_X, 120);
    let next = encode(EV_ABS, ABS_MT_POSITION_Y, 240);
    let merged = encode(EV_ABS, ABS_MT_POSITION_Y, 120);
    let mut source = ScriptedSource::new([
        Step::Bytes(first.clone()),
        Step::Bytes(next[..4].to_vec()),
        Step::Error(ErrorKind::Interrupted),
        value(EV_SYN, SYN_REPORT, 0),
        Step::Bytes(next),
        value(EV_SYN, SYN_REPORT, 0),
    ]);
    let mut reader = KernelInputReader::new();
    let mut parser = KernelInputParser::new();
    let mut output = Vec::new();

    // 前四字节把 POSITION_X 改为 POSITION_Y，value 仍是旧值 120；不拼接短读。
    for _ in 0..3 {
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        assert!(output.is_empty());
    }
    reader.read(&mut source, &mut parser, &mut output).unwrap();
    assert_eq!(output, [pointer(0, 120.0, 120.0, ACTION_MOVE)]);
    assert_eq!(source.buffers_before_read[1], first);
    assert_eq!(source.buffers_before_read[2], merged);
    assert_eq!(source.buffers_before_read[3], merged);
    output.clear();
    reader.read(&mut source, &mut parser, &mut output).unwrap();
    assert!(output.is_empty());
    reader.read(&mut source, &mut parser, &mut output).unwrap();
    assert_eq!(output, [pointer(0, 120.0, 240.0, ACTION_MOVE)]);
    source.assert_finished();
}

#[test]
fn every_short_prefix_preserves_the_unwritten_suffix_for_the_next_read() {
    let first = encode(EV_ABS, ABS_MT_POSITION_X, 120);
    let next = encode(EV_ABS, ABS_MT_POSITION_Y, 240);
    for length in 1..8 {
        let mut expected = first.clone();
        expected[..length].copy_from_slice(&next[..length]);
        let mut source = ScriptedSource::new([
            Step::Bytes(first.clone()),
            Step::Bytes(next[..length].to_vec()),
            Step::Error(ErrorKind::Interrupted),
        ]);
        let mut reader = KernelInputReader::new();
        let mut parser = KernelInputParser::new();
        let mut output = Vec::new();

        for _ in 0..3 {
            reader.read(&mut source, &mut parser, &mut output).unwrap();
        }
        assert!(output.is_empty());
        assert_eq!(source.buffers_before_read[2], expected);
        source.assert_finished();
    }
}

#[test]
fn eof_stops_without_replaying_a_complete_or_partially_overwritten_syn() {
    for short_prefix in [false, true] {
        let mut steps = vec![value(EV_SYN, SYN_REPORT, 0)];
        if short_prefix {
            steps.push(Step::Bytes(encode(EV_SYN, SYN_REPORT, 0)[..4].to_vec()));
        }
        steps.push(Step::Bytes(Vec::new()));
        let mut source = ScriptedSource::new(steps);
        let mut reader = KernelInputReader::new();
        let mut parser = KernelInputParser::new();
        let mut output = Vec::new();
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        assert_eq!(output, [pointer(0, 0.0, 0.0, ACTION_MOVE)]);
        if short_prefix {
            output.clear();
            reader.read(&mut source, &mut parser, &mut output).unwrap();
            assert_eq!(output, [pointer(0, 0.0, 0.0, ACTION_MOVE)]);
        }
        output.clear();
        assert!(matches!(
            reader.read(&mut source, &mut parser, &mut output),
            Err(WindowError::Stopped)
        ));
        assert!(output.is_empty());
        source.assert_finished();
    }
}

#[test]
fn each_iteration_reads_exactly_one_eight_byte_buffer_even_after_error() {
    let mut source = ScriptedSource::new([
        value(EV_SYN, SYN_REPORT, 0),
        Step::Error(ErrorKind::Interrupted),
        value(EV_KEY, 115, 0),
    ]);
    let mut reader = KernelInputReader::new();
    let mut parser = KernelInputParser::new();
    let mut output = Vec::new();
    for index in 0..3 {
        output.clear();
        reader.read(&mut source, &mut parser, &mut output).unwrap();
        if index < 2 {
            assert_eq!(output, [pointer(0, 0.0, 0.0, ACTION_MOVE)]);
        } else {
            assert!(output.is_empty());
        }
        assert_eq!(source.buffers_before_read.len(), index + 1);
        assert_eq!(source.steps.len(), 2 - index);
    }
    source.assert_finished();
}
