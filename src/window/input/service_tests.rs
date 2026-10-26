use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

#[derive(Default)]
struct DetachedState {
    starts: AtomicUsize,
    registrations: AtomicUsize,
    stops: AtomicUsize,
    polls: AtomicUsize,
    registered: Mutex<Option<InputCallbackSlot>>,
}

impl DetachedState {
    fn dispatch(&self, event: InputEvent) {
        // 模拟进程监听持有注册槽，调用回调时不持有注册锁或槽位锁。
        let slot = self.registered.lock().unwrap().clone().unwrap();
        let callback = slot.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(event);
        }
    }

    fn assert_no_service_reader_or_cleanup(&self) {
        assert_eq!(self.polls.load(Ordering::Relaxed), 0);
        assert_eq!(self.stops.load(Ordering::Relaxed), 0);
    }
}

struct DetachedInput {
    state: Arc<DetachedState>,
}

impl InputBackend for DetachedInput {
    fn Start(&mut self) -> Result<(), WindowError> {
        self.state.starts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn StartDetached(&mut self, callback: InputCallbackSlot) -> Result<bool, WindowError> {
        self.state.registrations.fetch_add(1, Ordering::Relaxed);
        *self.state.registered.lock().unwrap() = Some(callback);
        Ok(true)
    }

    fn UpdateScreen(
        &mut self,
        _width: u32,
        _height: u32,
        _orientation: Orientation,
    ) -> Result<(), WindowError> {
        Ok(())
    }

    fn Stop(&mut self) {
        self.state.stops.fetch_add(1, Ordering::Relaxed);
    }

    fn PollEvents(&mut self, _output: &mut Vec<InputEvent>) -> Result<(), WindowError> {
        self.state.polls.fetch_add(1, Ordering::Relaxed);
        Err(WindowError::Backend(
            "detached backend must not use the service reader".into(),
        ))
    }
}

fn detached_service(state: Arc<DetachedState>) -> InputService<DetachedInput> {
    InputService::new(DetachedInput { state })
}

#[test]
fn detached_backend_has_no_service_worker_and_stop_does_not_close_it() {
    let state = Arc::new(DetachedState::default());
    let mut service = detached_service(Arc::clone(&state));
    service.Start().unwrap();
    service.Start().unwrap();
    assert!(service.detached);
    assert!(service.running.load(Ordering::Acquire));
    assert!(service.thread.is_none());
    service
        .UpdateScreen(1080, 1920, Orientation::Portrait)
        .unwrap();
    assert_eq!(service.Screen(), (1080, 1920, Orientation::Portrait));
    service.Stop();
    assert!(!service.running.load(Ordering::Acquire));
    service.Stop();
    drop(service);
    assert_eq!(state.starts.load(Ordering::Relaxed), 1);
    assert_eq!(state.registrations.load(Ordering::Relaxed), 1);
    state.assert_no_service_reader_or_cleanup();
}

#[test]
fn detached_registration_observes_later_callback_changes() {
    let state = Arc::new(DetachedState::default());
    let mut service = detached_service(Arc::clone(&state));
    service.Start().unwrap();
    let registered = state.registered.lock().unwrap().clone().unwrap();
    assert!(Arc::ptr_eq(&registered, &service.callback));
    let (delivered, received) = mpsc::channel();
    let first_sender = delivered.clone();
    service.SetCallback(move |event| first_sender.send((1, event)).unwrap());
    let first = InputEvent::new(9, 170, 180);
    state.dispatch(first);
    service.SetCallback(move |event| delivered.send((2, event)).unwrap());
    let second = InputEvent::new(10, 190, 200);
    state.dispatch(second);
    assert_eq!(
        received.try_iter().collect::<Vec<_>>(),
        [(1, first), (2, second)]
    );
    drop(service);
    state.assert_no_service_reader_or_cleanup();
}

#[test]
fn detached_registration_survives_service_stop_and_drop() {
    let state = Arc::new(DetachedState::default());
    let mut service = detached_service(Arc::clone(&state));
    let (delivered, received) = mpsc::channel();
    service.SetCallback(move |event| delivered.send(event).unwrap());
    service.Start().unwrap();
    let first = InputEvent::new(11, 210, 220);
    service.Stop();
    state.dispatch(first);
    drop(service);
    let second = InputEvent::new(12, 230, 240);
    state.dispatch(second);
    assert_eq!(received.try_iter().collect::<Vec<_>>(), [first, second]);
    state.assert_no_service_reader_or_cleanup();
}

#[test]
fn dropping_old_detached_service_does_not_clear_new_registration() {
    let state = Arc::new(DetachedState::default());
    let mut previous = detached_service(Arc::clone(&state));
    previous.SetCallback(|_| panic!("old callback must have been replaced"));
    previous.Start().unwrap();
    let mut current = detached_service(Arc::clone(&state));
    let (delivered, received) = mpsc::channel();
    current.SetCallback(move |event| delivered.send(event).unwrap());
    current.Start().unwrap();
    drop(previous);
    let event = InputEvent::new(13, 250, 260);
    state.dispatch(event);
    assert_eq!(received.try_recv().unwrap(), event);
    drop(current);
    assert_eq!(state.registrations.load(Ordering::Relaxed), 2);
    state.assert_no_service_reader_or_cleanup();
}
