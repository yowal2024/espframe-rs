use super::*;
use crate::window::input::{InputEvent, ACTION_DOWN, EV_ABS, EV_SYN, SYN_REPORT};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

struct ControlledSource {
    bytes: Receiver<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    entered: Sender<()>,
    dropped: Sender<()>,
}

impl InputSource for ControlledSource {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        assert_eq!(output.len(), 8);
        self.reads.fetch_add(1, Ordering::Relaxed);
        let _ = self.entered.send(());
        // 测试输入等待与真正的阻塞 read 一样，完全由写端唤醒。
        let bytes = self.bytes.recv().unwrap_or_default();
        output[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

impl Drop for ControlledSource {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}

struct SourceControl {
    bytes: Sender<Vec<u8>>,
    entered: Receiver<()>,
    dropped: Receiver<()>,
    reads: Arc<AtomicUsize>,
}

fn source() -> (ControlledSource, SourceControl) {
    let (bytes, receiver) = mpsc::channel();
    let (entered_tx, entered) = mpsc::channel();
    let (dropped_tx, dropped) = mpsc::channel();
    let reads = Arc::new(AtomicUsize::new(0));
    (
        ControlledSource {
            bytes: receiver,
            reads: Arc::clone(&reads),
            entered: entered_tx,
            dropped: dropped_tx,
        },
        SourceControl {
            bytes,
            entered,
            dropped,
            reads,
        },
    )
}

fn callbacks() -> (InputCallbackSlot, Receiver<InputEvent>) {
    let (sender, receiver) = mpsc::channel();
    (
        Arc::new(Mutex::new(Some(Arc::new(move |event| {
            let _ = sender.send(event);
        })))),
        receiver,
    )
}

fn value(type_: u16, code: u16, value: i32) -> Vec<u8> {
    [
        type_.to_ne_bytes().as_slice(),
        code.to_ne_bytes().as_slice(),
        value.to_ne_bytes().as_slice(),
    ]
    .concat()
}

#[test]
fn process_listener_reuses_the_first_positive_fd_without_recreating_it() {
    let listener = ProcessTouchListener::default();
    assert!(listener.open(|| Ok(0)).is_err());
    assert_eq!(listener.open(|| Ok(42)).unwrap(), 42);
    assert_eq!(listener.open(|| panic!("listener recreated")).unwrap(), 42);
}

#[test]
fn callback_handoff_reuses_the_blocked_reader_and_keeps_touch_state() {
    let listener = ProcessTouchListener::default();
    listener.open(|| Ok(42)).unwrap();
    let (first_source, first) = source();
    let (first_slot, first_events) = callbacks();
    listener.start(first_source, first_slot).unwrap();
    first.entered.recv_timeout(TIMEOUT).unwrap();
    first.bytes.send(value(EV_ABS, 57, 7)).unwrap();
    first.bytes.send(value(EV_ABS, 53, 120)).unwrap();
    first.bytes.send(value(EV_ABS, 54, 240)).unwrap();
    first.bytes.send(value(EV_SYN, SYN_REPORT, 0)).unwrap();
    let pressed = InputEvent::Pointer {
        pointer: 0,
        x: 120.0,
        y: 240.0,
        action: ACTION_DOWN,
    };
    assert_eq!(first_events.recv_timeout(TIMEOUT).unwrap(), pressed);

    let (unused_source, unused) = source();
    let (second_slot, second_events) = callbacks();
    listener.start(unused_source, second_slot).unwrap();
    unused.dropped.recv_timeout(TIMEOUT).unwrap();
    assert_eq!(unused.reads.load(Ordering::Relaxed), 0);
    // 切换界面后继续由原读端处理 SYN，槽位、坐标和 DOWN 都未被重置。
    first.bytes.send(value(EV_SYN, SYN_REPORT, 0)).unwrap();
    assert_eq!(second_events.recv_timeout(TIMEOUT).unwrap(), pressed);
    assert!(first_events.try_recv().is_err());
    assert_eq!(listener.open(|| panic!("listener recreated")).unwrap(), 42);

    first.bytes.send(Vec::new()).unwrap();
    first.dropped.recv_timeout(TIMEOUT).unwrap();
}

#[test]
fn callback_slot_changes_are_visible_without_restarting_the_reader() {
    let listener = ProcessTouchListener::default();
    listener.open(|| Ok(42)).unwrap();
    let (source, control) = source();
    let (slot, old_events) = callbacks();
    listener.start(source, Arc::clone(&slot)).unwrap();
    control.entered.recv_timeout(TIMEOUT).unwrap();
    let (new_slot, new_events) = callbacks();
    *slot.lock().unwrap() = new_slot.lock().unwrap().take();
    control.bytes.send(value(EV_SYN, SYN_REPORT, 0)).unwrap();
    assert_eq!(
        new_events.recv_timeout(TIMEOUT).unwrap(),
        InputEvent::new(0, 0, 0)
    );
    assert!(old_events.try_recv().is_err());
    control.bytes.send(Vec::new()).unwrap();
    control.dropped.recv_timeout(TIMEOUT).unwrap();
}

#[test]
fn eof_keeps_the_global_fd_and_does_not_automatically_start_a_new_reader() {
    let listener = ProcessTouchListener::default();
    listener.open(|| Ok(42)).unwrap();
    let (first_source, first) = source();
    let (slot, events) = callbacks();
    listener.start(first_source, slot).unwrap();
    first.bytes.send(Vec::new()).unwrap();
    first.dropped.recv_timeout(TIMEOUT).unwrap();
    assert!(events.try_recv().is_err());

    assert_eq!(listener.open(|| panic!("listener recreated")).unwrap(), 42);
    let (unused_source, unused) = source();
    let (slot, _) = callbacks();
    listener.start(unused_source, slot).unwrap();
    unused.dropped.recv_timeout(TIMEOUT).unwrap();
    assert_eq!(unused.reads.load(Ordering::Relaxed), 0);
}
