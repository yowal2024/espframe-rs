//! Kernel-backed gyro output; works from SurfaceFlinger without libsensorservice.
use super::{controller::AngularVelocityDelta, Clock, ComputeDelta, SensorError};
use crate::kernel::{
    abi::{GYRO_EVENT_APPEND, GYRO_EVENT_X, GYRO_EVENT_Y},
    KernelDriver, KernelTransport,
};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct OutputState {
    stopped: bool,
    enabled: bool,
    last_update: u64,
    diagnostics: OutputDiagnostics,
}

#[derive(Default)]
struct OutputDiagnostics {
    start_ns: u64,
    writes: u64,
    zeros: u64,
    expired: u64,
    reversals: u64,
    max_gap_ns: u64,
    max_abs: f32,
    previous: [f32; 2],
}

impl OutputDiagnostics {
    fn publish(&mut self, now: u64, gap: u64, x: f32, y: f32) {
        if !crate::debug_log::enabled() {
            return;
        }
        if self.writes == 0 {
            self.start_ns = now;
        }
        self.writes += 1;
        self.zeros += u64::from(x == 0.0 && y == 0.0);
        // Ignore floating point residue when counting meaningful reversals.
        if self.previous.iter().zip([x, y]).any(|(old, new)| {
            old.abs() > 0.0001
                && new.abs() > 0.0001
                && old.is_sign_positive() != new.is_sign_positive()
        }) {
            self.reversals += 1;
        }
        self.previous = [x, y];
        self.max_gap_ns = self.max_gap_ns.max(gap);
        self.max_abs = self.max_abs.max(x.abs()).max(y.abs());
        if now.saturating_sub(self.start_ns) >= 1_000_000_000 {
            crate::espframe_log!(
                "sensor.kernel.window",
                "writes={} zeros={} expired={} reversals={} max_gap_us={} max_abs_rad_s={:.5}",
                self.writes,
                self.zeros,
                self.expired,
                self.reversals,
                self.max_gap_ns / 1000,
                self.max_abs
            );
            *self = Self {
                previous: [x, y],
                ..Self::default()
            };
        }
    }
}

struct Output<T: KernelTransport> {
    driver: KernelDriver<T>,
    state: Mutex<OutputState>,
    changed: Condvar,
}

impl<T: KernelTransport> Output<T> {
    fn disable(&self) -> Result<(), SensorError> {
        self.driver
            .ConfigureGyroEvent(0, [0.0; 3])
            .map_err(SensorError::KernelRejected)
    }

    fn expire(
        &self,
        state: &mut OutputState,
        now: u64,
        timeout: Option<Duration>,
    ) -> Result<(), SensorError> {
        if !state.stopped
            && state.enabled
            && timeout.is_some_and(|timeout| {
                now.saturating_sub(state.last_update)
                    >= timeout.as_nanos().min(u64::MAX as u128) as u64
            })
        {
            self.disable()?;
            state.enabled = false;
            state.diagnostics.expired += 1;
            crate::espframe_log!(
                "sensor.kernel.expired",
                "idle_us={}",
                now.saturating_sub(state.last_update) / 1000
            );
        }
        Ok(())
    }
}

pub struct KernelSensorController<T: KernelTransport + 'static, C: Clock + Send + Sync + 'static> {
    output: Arc<Output<T>>,
    clock: Arc<C>,
    idle_timeout: Option<Duration>,
    watchdog: Option<std::thread::JoinHandle<()>>,
    active: bool,
    remap: u8,
    previous_ns: u64,
}

impl<T: KernelTransport + 'static, C: Clock + Send + Sync + 'static> KernelSensorController<T, C> {
    /// Persistent output; callers must explicitly clear or stop it.
    pub fn new(driver: KernelDriver<T>, clock: C) -> Self {
        Self::WithIdleTimeout(driver, clock, None)
    }

    /// Timeout is a userspace output policy. None publishes until explicit stop.
    pub fn WithIdleTimeout(
        driver: KernelDriver<T>,
        clock: C,
        idle_timeout: Option<Duration>,
    ) -> Self {
        Self {
            output: Arc::new(Output {
                driver,
                state: Mutex::new(OutputState {
                    stopped: true,
                    enabled: false,
                    last_update: 0,
                    diagnostics: OutputDiagnostics::default(),
                }),
                changed: Condvar::new(),
            }),
            clock: Arc::new(clock),
            idle_timeout,
            watchdog: None,
            active: false,
            remap: 0,
            previous_ns: 0,
        }
    }

    pub fn Start(&mut self) -> Result<(), SensorError> {
        if self.active {
            return Err(SensorError::AlreadyActive);
        }
        // Probes support and removes stale output before publishing anything.
        let mut state = self.output.state.lock().unwrap_or_else(|e| e.into_inner());
        self.output.disable()?;
        state.stopped = false;
        state.enabled = false;
        if self.idle_timeout.is_some() {
            let output = Arc::clone(&self.output);
            let clock = Arc::clone(&self.clock);
            let timeout = self.idle_timeout;
            self.watchdog = match std::thread::Builder::new()
                .name("gyro-watchdog".into())
                .spawn(move || {
                    crate::threading::enter("gyro-watchdog", crate::threading::WorkerRole::Service);
                    let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
                    while !state.stopped {
                        state = output
                            .changed
                            .wait_timeout(state, Duration::from_millis(33))
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                        if let Err(error) = output.expire(&mut state, clock.NowNs(), timeout) {
                            crate::espframe_log!(
                                "sensor.kernel.watchdog.error",
                                "error={}",
                                error
                            );
                        }
                    }
                }) {
                Ok(worker) => Some(worker),
                Err(_) => {
                    state.stopped = true;
                    return Err(SensorError::Platform);
                }
            };
        }
        self.previous_ns = 0;
        self.active = true;
        Ok(())
    }

    pub fn TickWatchdog(&self) -> Result<(), SensorError> {
        let mut state = self.output.state.lock().unwrap_or_else(|e| e.into_inner());
        self.output
            .expire(&mut state, self.clock.NowNs(), self.idle_timeout)
    }

    pub fn Stop(&mut self) -> Result<(), SensorError> {
        if self.active {
            let result = {
                let mut state = self.output.state.lock().unwrap_or_else(|e| e.into_inner());
                // Serializes expiry/updates/stop: an old expiry cannot clear a new write.
                let result = self.output.disable();
                state.stopped = true;
                if result.is_ok() {
                    state.enabled = false;
                }
                self.output.changed.notify_all();
                result
            };
            if let Some(worker) = self.watchdog.take() {
                let _ = worker.join();
            }
            result?;
            self.active = false;
            self.previous_ns = 0;
        }
        Ok(())
    }

    fn publish(&self, x: f32, y: f32) -> Result<(), SensorError> {
        if !self.active {
            return Err(SensorError::NotActive);
        }
        let mut state = self.output.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.stopped {
            return Err(SensorError::NotActive);
        }
        let enabled = x != 0.0 || y != 0.0;
        // Preserve physical input and Z. Kernel configuration has no timeout.
        if enabled {
            self.output
                .driver
                .ConfigureGyroEvent(GYRO_EVENT_APPEND | GYRO_EVENT_X | GYRO_EVENT_Y, [x, y, 0.0])
                .map_err(SensorError::KernelRejected)?;
        } else {
            self.output.disable()?;
        }
        let now = self.clock.NowNs();
        let gap = if state.enabled {
            now.saturating_sub(state.last_update)
        } else {
            0
        };
        state.diagnostics.publish(now, gap, x, y);
        state.enabled = enabled;
        state.last_update = now;
        Ok(())
    }

    pub fn AddRotation(&mut self, yaw: f32, pitch: f32) -> Result<(), SensorError> {
        if !yaw.is_finite() || !pitch.is_finite() {
            return Err(SensorError::InvalidValue);
        }
        let now = self.clock.NowNs();
        let (x, y) = ComputeDelta(yaw, pitch, self.previous_ns, now, self.remap);
        self.publish(x, y)?;
        self.previous_ns = now;
        Ok(())
    }

    pub fn SetAngularVelocity(&mut self, yaw: f32, pitch: f32) -> Result<(), SensorError> {
        if !yaw.is_finite() || !pitch.is_finite() {
            return Err(SensorError::InvalidValue);
        }
        let (x, y) = AngularVelocityDelta(yaw, pitch, self.remap);
        self.publish(x, y)?;
        self.previous_ns = self.clock.NowNs();
        Ok(())
    }

    pub fn SetAxisRemap(&mut self, swap: bool, reverse_x: bool, reverse_y: bool) {
        self.remap = u8::from(swap) | (u8::from(reverse_x) << 1) | (u8::from(reverse_y) << 2);
    }
}

impl<T: KernelTransport + 'static, C: Clock + Send + Sync + 'static> Drop
    for KernelSensorController<T, C>
{
    fn drop(&mut self) {
        if let Err(error) = self.Stop() {
            crate::espframe_log!("sensor.kernel.stop.error", "error={}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::abi::CMD_GYRO_EVENT_CONFIGURE;
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Transport(Arc<Mutex<(Vec<[usize; 5]>, isize)>>);
    impl KernelTransport for Transport {
        unsafe fn Invoke(&self, _: i32, _: u64, command: usize, args: [usize; 5]) -> isize {
            assert_eq!(command, CMD_GYRO_EVENT_CONFIGURE);
            let mut s = self.0.lock().unwrap();
            s.0.push(args);
            s.1
        }
    }
    struct TestClock;
    impl Clock for TestClock {
        fn NowNs(&self) -> u64 {
            1_000_000_000
        }
    }
    fn setup() -> (Transport, KernelSensorController<Transport, TestClock>) {
        let t = Transport::default();
        t.0.lock().unwrap().1 = 1;
        let c = KernelSensorController::new(KernelDriver::new(123, 456, 789, t.clone()), TestClock);
        (t, c)
    }
    #[test]
    fn velocity_preserves_axis_mapping_and_has_no_kernel_timeout() {
        let (t, mut c) = setup();
        c.Start().unwrap();
        c.SetAxisRemap(true, true, false);
        c.SetAngularVelocity(90.0, 180.0).unwrap();
        let s = t.0.lock().unwrap();
        assert_eq!(s.0[0], [0; 5]);
        let args = s.0[1];
        assert_eq!(
            args[0],
            (GYRO_EVENT_APPEND | GYRO_EVENT_X | GYRO_EVENT_Y) as usize
        );
        assert!((f32::from_bits(args[1] as u32) - core::f32::consts::PI).abs() < 1e-6);
        assert!((f32::from_bits(args[2] as u32) + core::f32::consts::FRAC_PI_2).abs() < 1e-6);
        assert_eq!(&args[3..], &[0, 0]);
    }
    #[test]
    fn zero_and_drop_disable_and_inactive_output_fails() {
        let (t, mut c) = setup();
        assert_eq!(c.SetAngularVelocity(1.0, 2.0), Err(SensorError::NotActive));
        c.Start().unwrap();
        c.SetAngularVelocity(1.0, 2.0).unwrap();
        c.SetAngularVelocity(0.0, 0.0).unwrap();
        drop(c);
        let s = t.0.lock().unwrap();
        assert_eq!(&s.0[2..], &[[0; 5], [0; 5]]);
    }
    #[test]
    fn old_kernel_and_failed_write_are_propagated() {
        let (t, mut c) = setup();
        t.0.lock().unwrap().1 = -38;
        assert_eq!(c.Start(), Err(SensorError::KernelRejected(-38)));
        t.0.lock().unwrap().1 = 1;
        c.Start().unwrap();
        t.0.lock().unwrap().1 = 0;
        assert_eq!(
            c.SetAngularVelocity(1.0, 2.0),
            Err(SensorError::KernelRejected(0))
        );
        assert_eq!(c.Stop(), Err(SensorError::KernelRejected(0)));
        t.0.lock().unwrap().1 = 1;
        c.Stop().unwrap();
    }
    #[test]
    fn invalid_values_never_cross_abi() {
        let (t, mut c) = setup();
        c.Start().unwrap();
        assert_eq!(
            c.SetAngularVelocity(f32::NAN, 0.0),
            Err(SensorError::InvalidValue)
        );
        assert_eq!(c.output.driver.ConfigureGyroEvent(32, [0.0; 3]), Err(-22));
        assert_eq!(t.0.lock().unwrap().0.len(), 1);
    }
    #[test]
    fn angle_delta_keeps_original_time_conversion() {
        let (t, mut c) = setup();
        c.Start().unwrap();
        c.AddRotation(3.0, -6.0).unwrap();
        let expected = ComputeDelta(3.0, -6.0, 0, 1_000_000_000, 0);
        let s = t.0.lock().unwrap();
        assert_eq!(s.0[1][1], expected.0.to_bits() as usize);
        assert_eq!(s.0[1][2], expected.1.to_bits() as usize);
    }

    #[test]
    fn watchdog_disables_without_producer_ticks_and_stop_joins() {
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        };
        struct ManualClock(Arc<AtomicU64>);
        impl Clock for ManualClock {
            fn NowNs(&self) -> u64 {
                self.0.load(Ordering::Relaxed)
            }
        }
        struct NotifyingTransport(mpsc::Sender<[usize; 5]>);
        impl KernelTransport for NotifyingTransport {
            unsafe fn Invoke(&self, _: i32, _: u64, _: usize, args: [usize; 5]) -> isize {
                self.0.send(args).unwrap();
                1
            }
        }
        let (tx, rx) = mpsc::channel();
        let time = Arc::new(AtomicU64::new(1));
        let mut c = KernelSensorController::WithIdleTimeout(
            KernelDriver::new(1, 2, 3, NotifyingTransport(tx)),
            ManualClock(time.clone()),
            Some(Duration::from_millis(100)),
        );
        c.Start().unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), [0; 5]);
        c.SetAngularVelocity(1., 2.).unwrap();
        assert_ne!(rx.recv_timeout(Duration::from_secs(2)).unwrap()[0], 0);
        time.store(100_000_001, Ordering::Relaxed);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), [0; 5]);
        c.Stop().unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), [0; 5]);
        assert!(c.watchdog.is_none());
        assert_eq!(c.SetAngularVelocity(1., 2.), Err(SensorError::NotActive));
    }

    #[test]
    fn failed_expiry_keeps_output_enabled_for_retry() {
        let (t, mut c) = setup();
        c.Start().unwrap();
        c.SetAngularVelocity(1., 2.).unwrap();
        let mut state = c.output.state.lock().unwrap();
        t.0.lock().unwrap().1 = 0;
        assert_eq!(
            c.output
                .expire(&mut state, 2_000_000_000, Some(Duration::from_millis(100))),
            Err(SensorError::KernelRejected(0))
        );
        assert!(state.enabled);
        t.0.lock().unwrap().1 = 1;
        c.output
            .expire(&mut state, 2_000_000_000, Some(Duration::from_millis(100)))
            .unwrap();
        assert!(!state.enabled);
    }

    #[test]
    fn idle_timeout_is_optional_and_refreshed_by_new_output() {
        use std::sync::atomic::{AtomicU64, Ordering};
        struct ManualClock(Arc<AtomicU64>);
        impl Clock for ManualClock {
            fn NowNs(&self) -> u64 {
                self.0.load(Ordering::Relaxed)
            }
        }
        for timeout in [
            None,
            Some(Duration::from_millis(100)),
            Some(Duration::from_secs(1)),
        ] {
            let t = Transport::default();
            t.0.lock().unwrap().1 = 1;
            let time = Arc::new(AtomicU64::new(1_000_000_000));
            let mut c = KernelSensorController::WithIdleTimeout(
                KernelDriver::new(1, 2, 3, t.clone()),
                ManualClock(time.clone()),
                timeout,
            );
            c.Start().unwrap();
            c.SetAngularVelocity(1., 2.).unwrap();
            time.store(1_099_000_000, Ordering::Relaxed);
            c.TickWatchdog().unwrap();
            assert_eq!(t.0.lock().unwrap().0.len(), 2);
            c.SetAngularVelocity(3., 4.).unwrap();
            time.store(1_100_000_000, Ordering::Relaxed);
            c.TickWatchdog().unwrap();
            assert_eq!(t.0.lock().unwrap().0.len(), 3);
            time.store(2_099_000_000, Ordering::Relaxed);
            c.TickWatchdog().unwrap();
            let calls = t.0.lock().unwrap().0.clone();
            if timeout.is_some() {
                assert_eq!(calls.len(), 4);
                assert_eq!(calls[3], [0; 5]);
            } else {
                assert_eq!(calls.len(), 3);
                assert!(c.watchdog.is_none());
            }
        }
    }
}
