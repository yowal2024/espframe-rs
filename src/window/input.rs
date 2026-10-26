#![allow(non_snake_case)]

use super::{Orientation, WindowError};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub use super::input_hook::{
    android_volume_key_event, ANDROID_KEYCODE_VOLUME_DOWN, ANDROID_KEYCODE_VOLUME_UP,
    LINUX_KEYCODE_VOLUME_DOWN, LINUX_KEYCODE_VOLUME_UP,
};

#[cfg(target_os = "android")]
use crate::kernel::{KernelDriver, KernelTransport};

#[cfg(any(target_os = "android", test))]
mod reader;

#[cfg(any(target_os = "android", test))]
mod listener;

mod top_left;
pub use top_left::TopLeftDoubleTap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InputEvent {
    Pointer {
        pointer: u32,
        x: f32,
        y: f32,
        action: u32,
    },
    Key {
        code: u16,
        down: bool,
    },
}

pub const ACTION_MOVE: u32 = 2;
pub const ACTION_DOWN: u32 = 0;
pub const ACTION_UP: u32 = 1;

impl InputEvent {
    pub const fn new(pointer: u32, x: i32, y: i32) -> Self {
        Self::Pointer {
            pointer,
            x: x as f32,
            y: y as f32,
            action: ACTION_MOVE,
        }
    }
    pub fn IsFinite(self) -> bool {
        match self {
            Self::Pointer { x, y, .. } => x.is_finite() && y.is_finite(),
            Self::Key { .. } => true,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelInputValue {
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

pub const EV_ABS: u16 = 3;
pub const EV_KEY: u16 = 1;
pub const EV_SYN: u16 = 0;
pub const ABS_MT_SLOT: u16 = 47;
pub const ABS_MT_TRACKING_ID: u16 = 57;
pub const ABS_MT_POSITION_X: u16 = 53;
pub const ABS_MT_POSITION_Y: u16 = 54;
pub const SYN_REPORT: u16 = 0;
pub const KEY_VOLUMEDOWN: u16 = 114;
pub const KEY_VOLUMEUP: u16 = 115;

const DOUBLE_CLICK_THRESHOLD: Duration = Duration::from_millis(500);

#[derive(Debug, Default)]
pub struct VolumeDownDoubleClick {
    last_down: Option<Instant>,
}

impl VolumeDownDoubleClick {
    pub fn Observe(&mut self, event: InputEvent, observed_at: Instant) -> bool {
        let InputEvent::Key { code, down: true } = event else {
            return false;
        };
        if !matches!(code, KEY_VOLUMEDOWN | KEY_VOLUMEUP) {
            return false;
        }
        let paired = self
            .last_down
            .and_then(|last| observed_at.checked_duration_since(last))
            .is_some_and(|elapsed| elapsed < DOUBLE_CLICK_THRESHOLD);
        self.last_down = if paired { None } else { Some(observed_at) };
        paired
    }
}

#[derive(Clone, Copy, Debug)]
struct SlotState {
    x: i32,
    y: i32,
    action: u32,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            action: ACTION_UP,
        }
    }
}

#[derive(Debug)]
pub struct KernelInputParser {
    slot: i32,
    slots: std::collections::HashMap<i32, SlotState>,
}

impl Default for KernelInputParser {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelInputParser {
    pub fn new() -> Self {
        Self {
            slot: 0,
            // main 初始化当前槽 0 为 MOVE；其余槽在首次访问时才创建。
            slots: std::collections::HashMap::from([(
                0,
                SlotState {
                    action: ACTION_MOVE,
                    ..SlotState::default()
                },
            )]),
        }
    }
    pub fn Push(&mut self, value: KernelInputValue, output: &mut Vec<InputEvent>) {
        match (value.type_, value.code) {
            (EV_ABS, ABS_MT_SLOT) => {
                self.slot = value.value;
                self.slots.entry(self.slot).or_default().action = ACTION_MOVE;
            }
            (EV_ABS, ABS_MT_TRACKING_ID) => {
                self.slots.entry(self.slot).or_default().action = if value.value == -1 {
                    ACTION_UP
                } else {
                    ACTION_DOWN
                };
            }
            (EV_ABS, ABS_MT_POSITION_X) => {
                self.slots.entry(self.slot).or_default().x = value.value;
            }
            (EV_ABS, ABS_MT_POSITION_Y) => {
                self.slots.entry(self.slot).or_default().y = value.value;
            }
            (EV_SYN, SYN_REPORT) => {
                // main 每个 SYN 都回调全部槽位，保留 DOWN/UP 和坐标供下一帧复用。
                for (&pointer, state) in &self.slots {
                    output.push(InputEvent::Pointer {
                        pointer: pointer as u32,
                        x: state.x as f32,
                        y: state.y as f32,
                        action: state.action,
                    });
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod parser_tests;

pub type InputCallback = Arc<dyn Fn(InputEvent) + Send + Sync + 'static>;
pub type InputCallbackSlot = Arc<Mutex<Option<InputCallback>>>;

pub trait InputBackend: Send + 'static {
    fn Start(&mut self) -> Result<(), WindowError>;
    // 返回 true 时由后端持有进程级读取线程，服务只负责注册可更新的回调槽。
    fn StartDetached(&mut self, _callback: InputCallbackSlot) -> Result<bool, WindowError> {
        Ok(false)
    }
    fn UpdateScreen(
        &mut self,
        width: u32,
        height: u32,
        orientation: Orientation,
    ) -> Result<(), WindowError>;
    fn Stop(&mut self);
    fn PollEvents(&mut self, _output: &mut Vec<InputEvent>) -> Result<(), WindowError> {
        std::thread::yield_now();
        Ok(())
    }
}

pub struct InputService<B: InputBackend> {
    backend: Arc<Mutex<B>>,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    detached: bool,
    callback: InputCallbackSlot,
    screen: AtomicU64,
}

impl<B: InputBackend> InputService<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
            running: Arc::new(AtomicBool::new(false)),
            thread: None,
            detached: false,
            callback: Arc::new(Mutex::new(None)),
            screen: AtomicU64::new(0),
        }
    }

    pub fn Start(&mut self) -> Result<(), WindowError> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.detached = false;
        let start = match self.backend.lock() {
            Ok(mut backend) => backend
                .Start()
                .and_then(|()| backend.StartDetached(Arc::clone(&self.callback))),
            Err(poisoned) => {
                poisoned.into_inner().Stop();
                Err(WindowError::Backend("backend lock poisoned".into()))
            }
        };
        self.detached = match start {
            Ok(detached) => detached,
            Err(error) => {
                self.running.store(false, Ordering::Release);
                return Err(error);
            }
        };
        if self.detached {
            return Ok(());
        }
        let running = Arc::clone(&self.running);
        let backend = Arc::clone(&self.backend);
        let callback = Arc::clone(&self.callback);
        self.thread = Some(thread::spawn(move || {
            crate::threading::enter("input", crate::threading::WorkerRole::Interactive);
            while running.load(Ordering::Acquire) {
                let mut events = Vec::new();
                let poll = match backend.lock() {
                    Ok(mut backend) => backend.PollEvents(&mut events),
                    Err(poisoned) => {
                        poisoned.into_inner().Stop();
                        Err(WindowError::Backend("backend lock poisoned".into()))
                    }
                };
                if poll.is_err() {
                    running.store(false, Ordering::Release);
                    break;
                }
                for event in events {
                    if !event.IsFinite() {
                        continue;
                    }
                    let callback = callback.lock().ok().and_then(|slot| slot.clone());
                    if let Some(callback) = callback {
                        callback(event);
                    }
                }
            }
        }));
        Ok(())
    }

    pub fn UpdateScreen(
        &mut self,
        width: u32,
        height: u32,
        orientation: Orientation,
    ) -> Result<(), WindowError> {
        if width == 0 || height == 0 {
            return Err(WindowError::InvalidSize);
        }
        if width > 0x3fff_ffff {
            return Err(WindowError::InvalidSize);
        }
        let result = self
            .backend
            .lock()
            .map_err(|_| WindowError::Backend("backend lock poisoned".into()))?
            .UpdateScreen(width, height, orientation);
        if result.is_ok() {
            self.screen
                .store(PackScreen(width, height, orientation), Ordering::Release);
        }
        result
    }

    pub fn Screen(&self) -> (u32, u32, Orientation) {
        UnpackScreen(self.screen.load(Ordering::Acquire))
    }

    pub fn SetCallback<F>(&mut self, callback: F)
    where
        F: Fn(InputEvent) + Send + Sync + 'static,
    {
        if let Ok(mut slot) = self.callback.lock() {
            *slot = Some(Arc::new(callback));
        }
    }

    pub fn Dispatch(&self, event: InputEvent) {
        if !event.IsFinite() {
            return;
        }
        let callback = self.callback.lock().ok().and_then(|slot| slot.clone());
        if let Some(callback) = callback {
            callback(event);
        }
    }

    pub fn Stop(&mut self) {
        let was_running = self.running.swap(false, Ordering::AcqRel);
        // 进程级监听与 main 一致继续读取，也保留当前注册槽供后续事件使用。
        if self.detached {
            return;
        }
        let worker = self.thread.take();
        let had_worker = worker.is_some();
        if let Some(thread) = worker {
            let _ = thread.join();
        }
        if was_running || had_worker {
            let mut backend = match self.backend.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            backend.Stop();
        }
    }
}

impl<B: InputBackend> Drop for InputService<B> {
    fn drop(&mut self) {
        self.Stop();
    }
}

#[cfg(target_os = "android")]
pub struct KernelInputBackend<T: KernelTransport> {
    driver: Arc<KernelDriver<T>>,
    listener_fd: libc::c_int,
    listener: Arc<listener::ProcessTouchListener>,
}

#[cfg(target_os = "android")]
impl<T: KernelTransport> KernelInputBackend<T> {
    pub fn new(driver: Arc<KernelDriver<T>>) -> Result<Self, WindowError> {
        let listener = listener::process_listener();
        let listener_fd = listener.open(|| {
            driver
                .CreateTouchInputEventListener()
                .map_err(WindowError::Backend)
        })?;
        Ok(Self {
            driver,
            listener_fd,
            listener,
        })
    }
}

#[cfg(target_os = "android")]
impl<T: KernelTransport + 'static> InputBackend for KernelInputBackend<T> {
    fn Start(&mut self) -> Result<(), WindowError> {
        Ok(())
    }
    fn StartDetached(&mut self, callback: InputCallbackSlot) -> Result<bool, WindowError> {
        self.listener
            .start(reader::FdInputSource(self.listener_fd), callback)?;
        Ok(true)
    }
    fn UpdateScreen(
        &mut self,
        width: u32,
        height: u32,
        orientation: Orientation,
    ) -> Result<(), WindowError> {
        if self.listener_fd <= 0 {
            return Ok(());
        }
        let (width, height) = if orientation.IsRotated() {
            (height, width)
        } else {
            (width, height)
        };
        // main 只下发更新，不用系统调用返回值阻断窗口；失败仅保留诊断。
        if let Err(error) =
            self.driver
                .UpdateTouchScreenInfo(self.listener_fd, width, height, orientation as i8)
        {
            crate::espframe_log!("window.input.screen.error", "error={error}");
        }
        Ok(())
    }
    fn Stop(&mut self) {
        // main 的触摸监听属于整个进程，界面退出不停止线程，也不关闭 fd。
    }
}

fn PackScreen(width: u32, height: u32, orientation: Orientation) -> u64 {
    ((width as u64) << 34) | ((height as u64) << 2) | orientation as u64
}

fn UnpackScreen(value: u64) -> (u32, u32, Orientation) {
    let orientation = match value & 3 {
        0 => Orientation::Portrait,
        1 => Orientation::Landscape,
        2 => Orientation::ReversePortrait,
        _ => Orientation::ReverseLandscape,
    };
    (
        ((value >> 34) & 0x3fff_ffff) as u32,
        ((value >> 2) & 0xffff_ffff) as u32,
        orientation,
    )
}

#[cfg(test)]
mod service_tests;
