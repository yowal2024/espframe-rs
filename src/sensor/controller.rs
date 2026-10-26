use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::dispatch::{publish, retire, rollback, Dispatch, EventState};
use super::{ConvertToSensorEvent, SensorError, SensorHook, SensorPlatform};

const IDLE_NS: u64 = 100_000_000;

#[allow(non_snake_case)]
pub trait AimRotation {
    fn AddRotation(&mut self, yaw: f32, pitch: f32);
    /// 直接发布角速度，单位为度/秒；数值不随调用频率改变。
    fn SetAngularVelocity(&mut self, yaw_deg_per_sec: f32, pitch_deg_per_sec: f32);
    fn RequiresExplicitStop(&self) -> bool;
    fn SetAxisRemap(&mut self, swap_xy: bool, reverse_x: bool, reverse_y: bool);
}

pub(super) fn AngularVelocityDelta(yaw: f32, pitch: f32, remap: u8) -> (f32, f32) {
    if !yaw.is_finite() || !pitch.is_finite() {
        return (0.0, 0.0);
    }
    let (mut yaw, mut pitch) = (yaw, pitch);
    if remap & 1 != 0 {
        core::mem::swap(&mut yaw, &mut pitch);
    }
    if remap & 2 != 0 {
        yaw = -yaw;
    }
    if remap & 4 != 0 {
        pitch = -pitch;
    }
    // Android 陀螺仪事件承载弧度/秒。输入已经是速率，不再使用上一帧间隔折算。
    (-yaw.to_radians(), -pitch.to_radians())
}

#[allow(non_snake_case)]
pub fn ComputeDelta(yaw: f32, pitch: f32, previous_ns: u64, now_ns: u64, remap: u8) -> (f32, f32) {
    if !yaw.is_finite() || !pitch.is_finite() {
        return (0.0, 0.0);
    }
    let (mut yaw, mut pitch) = (yaw, pitch);
    if remap & 1 != 0 {
        core::mem::swap(&mut yaw, &mut pitch);
    }
    if remap & 2 != 0 {
        yaw = -yaw;
    }
    if remap & 4 != 0 {
        pitch = -pitch;
    }
    let dt = if previous_ns == 0 || now_ns < previous_ns {
        33 * 1_000_000
    } else {
        now_ns
            .saturating_sub(previous_ns)
            .clamp(10 * 1_000_000, 100 * 1_000_000)
    };
    let factor = core::f32::consts::PI / 180.0 * 1_000_000_000.0 / dt as f32;
    let (x, y) = (-yaw * factor, -pitch * factor);
    if x.is_finite() && y.is_finite() {
        (x, y)
    } else {
        (0.0, 0.0)
    }
}

struct StateWriteGuard<'a> {
    sequence: &'a AtomicU64,
    version: u64,
}

impl Drop for StateWriteGuard<'_> {
    fn drop(&mut self) {
        self.sequence.store(self.version + 2, Ordering::Release);
    }
}

fn BeginStateWrite(sequence: &AtomicU64) -> StateWriteGuard<'_> {
    loop {
        let current = sequence.load(Ordering::Acquire);
        if current & 1 != 0 {
            std::thread::yield_now();
            continue;
        }
        if sequence
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return StateWriteGuard {
                sequence,
                version: current,
            };
        }
    }
}

fn ClearState(
    cleared: &AtomicBool,
    delta_x: &AtomicU64,
    delta_y: &AtomicU64,
    clear_count: &AtomicU64,
    sequence: &AtomicU64,
    expected_sequence: Option<u64>,
) {
    let guard = match expected_sequence {
        Some(version) => {
            if version & 1 != 0
                || sequence
                    .compare_exchange(version, version + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return;
            }
            StateWriteGuard { sequence, version }
        }
        None => BeginStateWrite(sequence),
    };
    if !cleared.load(Ordering::Acquire) {
        cleared.store(true, Ordering::Release);
        delta_x.store(0, Ordering::Relaxed);
        delta_y.store(0, Ordering::Relaxed);
        clear_count.fetch_add(1, Ordering::AcqRel);
    }
    drop(guard);
}

pub trait Clock {
    fn NowNs(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    fn NowNs(&self) -> u64 {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128) as u64
    }
}

pub struct SensorController<
    P: SensorPlatform + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
> {
    hook: SensorHook<P>,
    clock: C,
    remap: AtomicU8,
    stop_watchdog: std::sync::Arc<AtomicBool>,
    last_call: std::sync::Arc<AtomicU64>,
    delta_x: std::sync::Arc<AtomicU64>,
    delta_y: std::sync::Arc<AtomicU64>,
    state_sequence: std::sync::Arc<AtomicU64>,
    watchdog: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    cleared: std::sync::Arc<AtomicBool>,
    clear_count: std::sync::Arc<AtomicU64>,
    dispatch: Option<std::sync::Arc<Dispatch>>,
}
impl<
        P: SensorPlatform + Clone + Send + Sync + 'static,
        C: Clock + Clone + Send + Sync + 'static,
    > SensorController<P, C>
{
    pub fn new(platform: P, clock: C) -> Self {
        Self {
            hook: SensorHook::new(platform),
            clock,
            remap: AtomicU8::new(0),
            stop_watchdog: std::sync::Arc::new(AtomicBool::new(true)),
            last_call: std::sync::Arc::new(AtomicU64::new(0)),
            delta_x: std::sync::Arc::new(AtomicU64::new(0)),
            delta_y: std::sync::Arc::new(AtomicU64::new(0)),
            state_sequence: std::sync::Arc::new(AtomicU64::new(0)),
            watchdog: std::sync::Mutex::new(None),
            cleared: std::sync::Arc::new(AtomicBool::new(true)),
            clear_count: std::sync::Arc::new(AtomicU64::new(0)),
            dispatch: None,
        }
    }
    pub fn Start(&mut self) -> Result<(), SensorError> {
        if self.dispatch.is_some() || self.hook.IsActive() {
            return Err(SensorError::AlreadyActive);
        }
        let event = EventState::new(
            self.delta_x.clone(),
            self.delta_y.clone(),
            self.state_sequence.clone(),
        );
        let event_platform = self.hook.platform.clone();
        let mut published = None;
        let result =
            self.hook
                .StartWithPublisher(ConvertToSensorEvent as *const () as usize, |original| {
                    let dispatch = publish(event, event_platform, original)?;
                    published = Some(dispatch);
                    Ok(())
                });
        match result {
            Ok(()) => self.dispatch = published,
            Err(error) => {
                if self.hook.IsActive() {
                    self.dispatch = published;
                } else if let Some(dispatch) = published.as_ref() {
                    rollback(dispatch);
                }
                return Err(error);
            }
        }
        self.StartWatchdog();
        Ok(())
    }
    fn StartWatchdog(&self) {
        self.stop_watchdog.store(false, Ordering::Release);
        if let Ok(mut slot) = self.watchdog.lock() {
            if slot.is_none() {
                let stop = self.stop_watchdog.clone();
                let last = self.last_call.clone();
                let dx = self.delta_x.clone();
                let dy = self.delta_y.clone();
                let cleared = self.cleared.clone();
                let clear_count = self.clear_count.clone();
                let sequence = self.state_sequence.clone();
                let clock = self.clock.clone();
                *slot = Some(std::thread::spawn(move || {
                    crate::threading::enter(
                        "sensor-watchdog",
                        crate::threading::WorkerRole::Service,
                    );
                    while !stop.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(33));
                        let observed_sequence = sequence.load(Ordering::Acquire);
                        if !cleared.load(Ordering::Acquire)
                            && observed_sequence & 1 == 0
                            && clock.NowNs().saturating_sub(last.load(Ordering::Relaxed)) >= IDLE_NS
                        {
                            ClearState(
                                &cleared,
                                &dx,
                                &dy,
                                &clear_count,
                                &sequence,
                                Some(observed_sequence),
                            );
                        }
                    }
                }));
            }
        }
    }
    pub fn Stop(&mut self) -> Result<(), SensorError> {
        let restore = self.hook.Stop();
        let retire_result = if restore.is_ok() {
            if let Some(dispatch) = self.dispatch.take() {
                if let Err(error) = retire(&dispatch) {
                    self.dispatch = Some(dispatch);
                    Err(error)
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };
        self.StopWatchdogAndClear();
        restore?;
        retire_result
    }
    fn StopWatchdogAndClear(&self) {
        self.stop_watchdog.store(true, Ordering::Release);
        if let Ok(mut slot) = self.watchdog.lock() {
            if let Some(thread) = slot.take() {
                let _ = thread.join();
            }
        }
        self.Clear();
    }
    pub fn TickWatchdog(&self) {
        let observed_sequence = self.state_sequence.load(Ordering::Acquire);
        if !self.stop_watchdog.load(Ordering::Acquire)
            && !self.cleared.load(Ordering::Acquire)
            && observed_sequence & 1 == 0
            && self
                .clock
                .NowNs()
                .saturating_sub(self.last_call.load(Ordering::Relaxed))
                >= IDLE_NS
        {
            ClearState(
                &self.cleared,
                &self.delta_x,
                &self.delta_y,
                &self.clear_count,
                &self.state_sequence,
                Some(observed_sequence),
            );
        }
    }
    pub fn Event(&self, sensor_type: i32, bytes: &mut [u8]) {
        EventState::new(
            self.delta_x.clone(),
            self.delta_y.clone(),
            self.state_sequence.clone(),
        )
        .event(sensor_type, bytes);
    }
    pub fn ClearCount(&self) -> u64 {
        self.clear_count.load(Ordering::Acquire)
    }
    fn Clear(&self) {
        ClearState(
            &self.cleared,
            &self.delta_x,
            &self.delta_y,
            &self.clear_count,
            &self.state_sequence,
            None,
        );
    }
}
impl<
        P: SensorPlatform + Clone + Send + Sync + 'static,
        C: Clock + Clone + Send + Sync + 'static,
    > AimRotation for SensorController<P, C>
{
    fn AddRotation(&mut self, yaw: f32, pitch: f32) {
        let _guard = BeginStateWrite(&self.state_sequence);
        let now = self.clock.NowNs();
        let previous = self.last_call.swap(now, Ordering::Relaxed);
        let (x, y) = ComputeDelta(
            yaw,
            pitch,
            previous,
            now,
            self.remap.load(Ordering::Relaxed),
        );
        self.cleared.store(x == 0.0 && y == 0.0, Ordering::Release);
        self.delta_x.store(x.to_bits() as u64, Ordering::Relaxed);
        self.delta_y.store(y.to_bits() as u64, Ordering::Relaxed);
    }
    fn SetAngularVelocity(&mut self, yaw_deg_per_sec: f32, pitch_deg_per_sec: f32) {
        let _guard = BeginStateWrite(&self.state_sequence);
        let (x, y) = AngularVelocityDelta(
            yaw_deg_per_sec,
            pitch_deg_per_sec,
            self.remap.load(Ordering::Relaxed),
        );
        self.last_call.store(self.clock.NowNs(), Ordering::Relaxed);
        self.cleared.store(x == 0.0 && y == 0.0, Ordering::Release);
        self.delta_x.store(x.to_bits() as u64, Ordering::Relaxed);
        self.delta_y.store(y.to_bits() as u64, Ordering::Relaxed);
    }
    fn RequiresExplicitStop(&self) -> bool {
        true
    }
    fn SetAxisRemap(&mut self, swap: bool, reverse_x: bool, reverse_y: bool) {
        self.remap.store(
            u8::from(swap) | (u8::from(reverse_x) << 1) | (u8::from(reverse_y) << 2),
            Ordering::Relaxed,
        );
    }
}
impl<
        P: SensorPlatform + Clone + Send + Sync + 'static,
        C: Clock + Clone + Send + Sync + 'static,
    > Drop for SensorController<P, C>
{
    fn drop(&mut self) {
        let _ = self.Stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_watchdog_sequence_cannot_clear_new_delta() {
        let sequence = AtomicU64::new(0);
        let cleared = AtomicBool::new(true);
        let delta_x = AtomicU64::new(0);
        let delta_y = AtomicU64::new(0);
        let clear_count = AtomicU64::new(0);

        let _guard = BeginStateWrite(&sequence);
        cleared.store(false, Ordering::Release);
        delta_x.store(11, Ordering::Relaxed);
        delta_y.store(22, Ordering::Relaxed);
        drop(_guard);
        let stale_observation = sequence.load(Ordering::Acquire);

        let _guard = BeginStateWrite(&sequence);
        delta_x.store(33, Ordering::Relaxed);
        delta_y.store(44, Ordering::Relaxed);
        drop(_guard);

        ClearState(
            &cleared,
            &delta_x,
            &delta_y,
            &clear_count,
            &sequence,
            Some(stale_observation),
        );
        assert!(!cleared.load(Ordering::Acquire));
        assert_eq!(delta_x.load(Ordering::Relaxed), 33);
        assert_eq!(delta_y.load(Ordering::Relaxed), 44);
        assert_eq!(clear_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn state_write_guard_restores_even_sequence_on_panic() {
        let sequence = AtomicU64::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = BeginStateWrite(&sequence);
            panic!("test panic while publishing state");
        }));
        assert!(result.is_err());
        assert_eq!(sequence.load(Ordering::Acquire), 2);
    }
}
