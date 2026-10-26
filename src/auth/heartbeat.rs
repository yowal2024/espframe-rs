use super::{AuthClient, AuthTransport, Clock, CryptoRandom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

pub trait HeartbeatSource: Send + 'static {
    #[allow(non_snake_case)]
    fn Check(&mut self) -> Result<i32, String>;
}

impl<T, R, C> HeartbeatSource for AuthClient<T, R, C>
where
    T: AuthTransport + Send + 'static,
    R: CryptoRandom + Send + 'static,
    C: Clock + Send + 'static,
{
    fn Check(&mut self) -> Result<i32, String> {
        let code = self
            .Heartbeat()
            .map(|response| response.code)
            .map_err(|error| error.to_string())?;
        i32::try_from(code).map_err(|_| format!("heartbeat code {code} is out of range"))
    }
}

#[derive(Clone)]
pub struct HeartbeatPermit {
    shared: Arc<HeartbeatShared>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeartbeatAuthorization {
    Pending,
    TransientFailure(String),
    Authorized,
    Terminal(String),
}

impl HeartbeatPermit {
    #[allow(non_snake_case)]
    pub fn Authorization(&self) -> HeartbeatAuthorization {
        match &self.shared.lock().authorization {
            Authorization::Pending => HeartbeatAuthorization::Pending,
            Authorization::TransientFailure(error) => {
                HeartbeatAuthorization::TransientFailure(error.clone())
            }
            Authorization::Authorized => HeartbeatAuthorization::Authorized,
            Authorization::Terminal(error) => HeartbeatAuthorization::Terminal(error.clone()),
        }
    }

    #[allow(non_snake_case)]
    pub fn WaitUntilAuthorized(&self) -> Result<(), String> {
        self.wait_until_authorized(None)
    }

    #[allow(non_snake_case)]
    pub fn WaitUntilAuthorizedOr(&self, stop: &AtomicBool) -> Result<(), String> {
        self.wait_until_authorized(Some(stop))
    }

    fn wait_until_authorized(&self, stop: Option<&AtomicBool>) -> Result<(), String> {
        const STOP_POLL: Duration = Duration::from_millis(20);
        loop {
            if stop.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                return Err("heartbeat wait cancelled".to_owned());
            }
            let mut state = self.shared.lock();
            match &state.authorization {
                Authorization::Pending | Authorization::TransientFailure(_) => {
                    if stop.is_some() {
                        let (guard, _) = self
                            .shared
                            .changed
                            .wait_timeout(state, STOP_POLL)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        state = guard;
                    } else {
                        state = self.shared.wait(state);
                    }
                }
                Authorization::Authorized => return Ok(()),
                Authorization::Terminal(error) => return Err(error.clone()),
            }
        }
    }
}

enum Authorization {
    Pending,
    TransientFailure(String),
    Authorized,
    Terminal(String),
}

struct HeartbeatState {
    authorization: Authorization,
    stop_requested: bool,
}

struct HeartbeatShared {
    state: Mutex<HeartbeatState>,
    changed: Condvar,
}

impl HeartbeatShared {
    fn lock(&self) -> MutexGuard<'_, HeartbeatState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn wait<'a>(&self, state: MutexGuard<'a, HeartbeatState>) -> MutexGuard<'a, HeartbeatState> {
        self.changed
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub struct HeartbeatMonitor {
    shared: Arc<HeartbeatShared>,
    worker: Option<JoinHandle<()>>,
}

impl HeartbeatMonitor {
    #[allow(non_snake_case)]
    pub fn Start<S>(mut source: S, interval: Duration, retry_limit: usize) -> Self
    where
        S: HeartbeatSource,
    {
        let shared = Arc::new(HeartbeatShared {
            state: Mutex::new(HeartbeatState {
                authorization: Authorization::Pending,
                stop_requested: false,
            }),
            changed: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::spawn(move || {
            crate::threading::enter("heartbeat", crate::threading::WorkerRole::Service);
            let mut consecutive_failures = 0usize;
            loop {
                if worker_shared.lock().stop_requested {
                    break;
                }

                let transient_error = match source.Check() {
                    Ok(0) => {
                        consecutive_failures = 0;
                        let mut state = worker_shared.lock();
                        if state.stop_requested {
                            break;
                        }
                        state.authorization = Authorization::Authorized;
                        worker_shared.changed.notify_all();
                        let (state, _) = worker_shared
                            .changed
                            .wait_timeout(state, interval)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if state.stop_requested {
                            break;
                        }
                        continue;
                    }
                    Ok(code) if code > 0 => {
                        let mut state = worker_shared.lock();
                        state.authorization =
                            Authorization::Terminal(format!("heartbeat returned code {code}"));
                        worker_shared.changed.notify_all();
                        break;
                    }
                    Ok(code) => format!("heartbeat returned transient code {code}"),
                    Err(error) => error,
                };
                consecutive_failures = consecutive_failures.saturating_add(1);
                let mut state = worker_shared.lock();
                if state.stop_requested {
                    break;
                }
                if consecutive_failures > retry_limit {
                    state.authorization = Authorization::Terminal(format!(
                        "heartbeat retry limit exceeded after {consecutive_failures} failures: {transient_error}"
                    ));
                    worker_shared.changed.notify_all();
                    break;
                }
                state.authorization = Authorization::TransientFailure(transient_error);
                worker_shared.changed.notify_all();
            }
        });

        Self {
            shared,
            worker: Some(worker),
        }
    }

    #[allow(non_snake_case)]
    pub fn Permit(&self) -> HeartbeatPermit {
        HeartbeatPermit {
            shared: Arc::clone(&self.shared),
        }
    }

    #[allow(non_snake_case)]
    pub fn Shutdown(&mut self) -> Result<(), String> {
        {
            let mut state = self.shared.lock();
            state.stop_requested = true;
            if !matches!(state.authorization, Authorization::Terminal(_)) {
                state.authorization =
                    Authorization::Terminal("heartbeat monitor shut down".to_owned());
            }
            self.shared.changed.notify_all();
        }
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| "heartbeat worker panicked".to_owned()),
            None => Ok(()),
        }
    }
}

impl Drop for HeartbeatMonitor {
    fn drop(&mut self) {
        let _ = self.Shutdown();
    }
}
