use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use super::{SensorError, SensorPlatform};

type ConvertFn = unsafe extern "C" fn(*const c_void, *mut c_void);

pub(crate) struct EventState {
    delta_x: Arc<AtomicU64>,
    delta_y: Arc<AtomicU64>,
    sequence: Arc<AtomicU64>,
}

impl EventState {
    pub(crate) fn new(
        delta_x: Arc<AtomicU64>,
        delta_y: Arc<AtomicU64>,
        sequence: Arc<AtomicU64>,
    ) -> Self {
        Self {
            delta_x,
            delta_y,
            sequence,
        }
    }

    pub(crate) fn event(&self, sensor_type: i32, bytes: &mut [u8]) {
        if sensor_type != 4 || bytes.len() < 32 {
            return;
        }
        let (delta_x, delta_y) = loop {
            let version = self.sequence.load(Ordering::Acquire);
            if version & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let delta_x = self.delta_x.load(Ordering::Relaxed);
            let delta_y = self.delta_y.load(Ordering::Relaxed);
            if self.sequence.load(Ordering::Acquire) == version {
                break (delta_x, delta_y);
            }
        };
        let x =
            f32::from_le_bytes(bytes[24..28].try_into().unwrap()) + f32::from_bits(delta_x as u32);
        let y =
            f32::from_le_bytes(bytes[28..32].try_into().unwrap()) + f32::from_bits(delta_y as u32);
        bytes[24..28].copy_from_slice(&x.to_le_bytes());
        bytes[28..32].copy_from_slice(&y.to_le_bytes());
    }
}

pub(crate) struct Dispatch {
    event: EventState,
    memory: Arc<dyn EventMemory>,
    original: usize,
    accepting: AtomicBool,
    in_flight: Mutex<usize>,
    drained: Condvar,
}

impl Dispatch {
    fn new(event: EventState, memory: Arc<dyn EventMemory>, original: usize) -> Self {
        Self {
            event,
            memory,
            original,
            accepting: AtomicBool::new(true),
            in_flight: Mutex::new(0),
            drained: Condvar::new(),
        }
    }

    fn event(&self, address: usize) {
        let Some(sensor_type_address) = address.checked_add(12) else {
            return;
        };
        let mut sensor_type = [0u8; 4];
        if self
            .memory
            .read(sensor_type_address, &mut sensor_type)
            .is_err()
            || i32::from_le_bytes(sensor_type) != 4
        {
            return;
        }
        let Some(axes_address) = address.checked_add(24) else {
            return;
        };
        let mut axes = [0u8; 8];
        if self.memory.read(axes_address, &mut axes).is_err() {
            return;
        }
        let mut event = [0u8; 32];
        event[12..16].copy_from_slice(&sensor_type);
        event[24..32].copy_from_slice(&axes);
        self.event.event(4, &mut event);
        let _ = self.memory.write(axes_address, &event[24..32]);
    }

    fn wait_until_drained(&self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *in_flight != 0 {
            in_flight = self
                .drained
                .wait(in_flight)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    #[cfg(test)]
    fn wait_until_drained_at_barrier(
        &self,
        predicate_seen: &std::sync::Barrier,
        continue_to_wait: &std::sync::Barrier,
    ) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *in_flight != 0 {
            predicate_seen.wait();
            continue_to_wait.wait();
            in_flight = self
                .drained
                .wait(in_flight)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

trait EventMemory: Send + Sync {
    fn read(&self, address: usize, bytes: &mut [u8]) -> Result<(), SensorError>;
    fn write(&self, address: usize, bytes: &[u8]) -> Result<(), SensorError>;
}

struct PlatformEventMemory<P>(P);

impl<P: SensorPlatform + Send + Sync> EventMemory for PlatformEventMemory<P> {
    fn read(&self, address: usize, bytes: &mut [u8]) -> Result<(), SensorError> {
        self.0.ReadProcessMemory(address, bytes)
    }

    fn write(&self, address: usize, bytes: &[u8]) -> Result<(), SensorError> {
        self.0.WriteProcessMemory(address, bytes)
    }
}

enum GlobalDispatch {
    Vacant,
    Active(Arc<Dispatch>),
}

static GLOBAL_DISPATCH: Mutex<GlobalDispatch> = Mutex::new(GlobalDispatch::Vacant);

pub(crate) fn publish<P>(
    event: EventState,
    platform: P,
    original: usize,
) -> Result<Arc<Dispatch>, SensorError>
where
    P: SensorPlatform + Send + Sync + 'static,
{
    let mut global = GLOBAL_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match &*global {
        GlobalDispatch::Vacant => {
            let dispatch = Arc::new(Dispatch::new(
                event,
                Arc::new(PlatformEventMemory(platform)),
                original,
            ));
            *global = GlobalDispatch::Active(dispatch.clone());
            Ok(dispatch)
        }
        GlobalDispatch::Active(_) => Err(SensorError::AlreadyActive),
    }
}

pub(crate) fn rollback(dispatch: &Arc<Dispatch>) {
    let mut global = GLOBAL_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if matches!(&*global, GlobalDispatch::Active(active) if Arc::ptr_eq(active, dispatch)) {
        dispatch.accepting.store(false, Ordering::Release);
        *global = GlobalDispatch::Vacant;
    }
    drop(global);
    dispatch.wait_until_drained();
}

pub(crate) fn retire(dispatch: &Arc<Dispatch>) -> Result<(), SensorError> {
    {
        let global = GLOBAL_DISPATCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &*global {
            GlobalDispatch::Active(active) if Arc::ptr_eq(active, dispatch) => {
                dispatch.accepting.store(false, Ordering::Release);
            }
            _ => return Err(SensorError::NotActive),
        }
    }
    dispatch.wait_until_drained();
    let mut global = GLOBAL_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if matches!(&*global, GlobalDispatch::Active(active) if Arc::ptr_eq(active, dispatch)) {
        *global = GlobalDispatch::Vacant;
        Ok(())
    } else {
        Err(SensorError::NotActive)
    }
}

struct InFlight {
    dispatch: Arc<Dispatch>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut in_flight = self
            .dispatch
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *in_flight -= 1;
        if *in_flight == 0 {
            self.dispatch.drained.notify_all();
        }
    }
}

enum Entry {
    Active(InFlight),
    Forward(usize),
    Missing,
}

fn enter() -> Entry {
    let global = GLOBAL_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match &*global {
        GlobalDispatch::Active(dispatch) if dispatch.accepting.load(Ordering::Acquire) => {
            *dispatch
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
            Entry::Active(InFlight {
                dispatch: dispatch.clone(),
            })
        }
        GlobalDispatch::Active(dispatch) => Entry::Forward(dispatch.original),
        GlobalDispatch::Vacant => Entry::Missing,
    }
}

unsafe fn call_original(original: usize, event: *const c_void, sensor_event: *mut c_void) {
    let original: ConvertFn = unsafe { core::mem::transmute(original) };
    unsafe { original(event, sensor_event) };
}

#[allow(non_snake_case)]
/// Converts a hooked sensor callback payload and forwards to the original ABI.
///
/// # Safety
/// The C ABI inputs must satisfy the original callback's requirements, the
/// published original callback pointer must remain live, and hook publication,
/// teardown synchronization, and callback lifetime rules must be observed.
pub unsafe extern "C" fn ConvertToSensorEvent(event: *const c_void, sensor_event: *mut c_void) {
    match enter() {
        Entry::Active(entry) => {
            if let Some(address) = event.addr().checked_add(0).filter(|address| *address != 0) {
                entry.dispatch.event(address);
            }
            unsafe { call_original(entry.dispatch.original, event, sensor_event) };
        }
        Entry::Forward(original) => unsafe { call_original(original, event, sensor_event) },
        Entry::Missing => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Barrier};
    use std::time::Duration;

    fn event_state() -> EventState {
        EventState::new(
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    #[test]
    fn callback_completion_cannot_pass_waiter_between_predicate_and_wait() {
        struct RejectMemory;
        impl EventMemory for RejectMemory {
            fn read(&self, _: usize, _: &mut [u8]) -> Result<(), SensorError> {
                Err(SensorError::Platform)
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), SensorError> {
                Err(SensorError::Platform)
            }
        }
        let dispatch = Arc::new(Dispatch::new(event_state(), Arc::new(RejectMemory), 1));
        *dispatch.in_flight.lock().unwrap() = 1;
        let entry = InFlight {
            dispatch: dispatch.clone(),
        };
        let predicate_seen = Arc::new(Barrier::new(2));
        let continue_to_wait = Arc::new(Barrier::new(2));

        let waiter_dispatch = dispatch.clone();
        let waiter_seen = predicate_seen.clone();
        let waiter_continue = continue_to_wait.clone();
        let (waiter_done_tx, waiter_done_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            waiter_dispatch.wait_until_drained_at_barrier(&waiter_seen, &waiter_continue);
            waiter_done_tx.send(()).unwrap();
        });
        predicate_seen.wait();

        let (callback_done_tx, callback_done_rx) = mpsc::channel();
        let callback = std::thread::spawn(move || {
            drop(entry);
            callback_done_tx.send(()).unwrap();
        });
        let callback_completed_while_waiter_held_lock = callback_done_rx
            .recv_timeout(Duration::from_millis(100))
            .is_ok();

        continue_to_wait.wait();
        assert!(
            waiter_done_rx.recv_timeout(Duration::from_secs(1)).is_ok(),
            "drain waiter missed callback completion"
        );
        assert!(
            !callback_completed_while_waiter_held_lock,
            "callback changed the drain predicate without its mutex"
        );
        waiter.join().unwrap();
        callback.join().unwrap();
    }
}
