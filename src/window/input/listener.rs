//! main 的进程级触摸监听：创建一次，独立线程直接 read，切换界面只替换回调。

use super::reader::{InputSource, KernelInputReader};
use super::{InputCallbackSlot, KernelInputParser, WindowError};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Default)]
struct ListenerState {
    fd: Option<i32>,
    started: bool,
}

#[derive(Default)]
pub(super) struct ProcessTouchListener {
    state: Mutex<ListenerState>,
    callback: Arc<Mutex<Option<InputCallbackSlot>>>,
}

impl ProcessTouchListener {
    pub(super) fn open(
        &self,
        create: impl FnOnce() -> Result<i32, WindowError>,
    ) -> Result<i32, WindowError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WindowError::Backend("touch listener lock poisoned".into()))?;
        if let Some(fd) = state.fd {
            return Ok(fd);
        }
        let fd = create()?;
        if fd <= 0 {
            return Err(WindowError::Backend(format!(
                "kernel touch listener creation failed: {fd}"
            )));
        }
        // 与 main 的全局 listener_fd 一样，描述符保留到进程结束，不随界面析构关闭。
        state.fd = Some(fd);
        crate::espframe_log!("window.input.listener.open", "fd={} mode=main", fd);
        Ok(fd)
    }

    pub(super) fn start(
        &self,
        source: impl InputSource + Send + 'static,
        callback: InputCallbackSlot,
    ) -> Result<(), WindowError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WindowError::Backend("touch listener lock poisoned".into()))?;
        *self
            .callback
            .lock()
            .map_err(|_| WindowError::Backend("touch callback lock poisoned".into()))? =
            Some(callback);
        if state.started {
            // idle、局内和新的 supervisor 共用读取线程，回调始终指向当前界面。
            return Ok(());
        }
        let callbacks = Arc::clone(&self.callback);
        let worker = thread::Builder::new()
            .spawn(move || {
                crate::threading::enter("touch-reader", crate::threading::WorkerRole::Interactive);
                let mut source = source;
                let mut reader = KernelInputReader::new();
                let mut parser = KernelInputParser::new();
                let mut events = Vec::new();
                loop {
                    events.clear();
                    if reader.read(&mut source, &mut parser, &mut events).is_err() {
                        // read == 0 与 main 一样退出；不关闭全局 fd，也不自动重建线程。
                        crate::espframe_log!("window.input.reader.eof");
                        break;
                    }
                    if events.is_empty() {
                        continue;
                    }
                    let slot = callbacks.lock().ok().and_then(|value| value.clone());
                    let callback = slot
                        .as_ref()
                        .and_then(|slot| slot.lock().ok().and_then(|value| value.clone()));
                    if let Some(callback) = callback {
                        for event in events.drain(..) {
                            callback(event);
                        }
                    }
                }
            })
            .map_err(|error| {
                WindowError::Backend(format!("failed to spawn touch reader: {error}"))
            })?;
        state.started = true;
        // 对齐 main 的 detach，不让阻塞 read 进入服务的 Stop/join 或屏幕更新锁。
        drop(worker);
        Ok(())
    }
}

#[cfg(target_os = "android")]
pub(super) fn process_listener() -> Arc<ProcessTouchListener> {
    use std::sync::OnceLock;
    static LISTENER: OnceLock<Arc<ProcessTouchListener>> = OnceLock::new();
    Arc::clone(LISTENER.get_or_init(|| Arc::new(ProcessTouchListener::default())))
}

#[cfg(test)]
mod tests;
