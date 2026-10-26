use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::{mpsc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use thiserror::Error;

pub type ConfigValue = Value;

/// EspFrame-owned runtime configuration represented as flattened key/value
/// entries.  Host adapters may project this into richer typed settings.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Config {
    entries: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl Config {
    pub fn validate(self) -> Self {
        self
    }
    pub fn to_entries(&self) -> BTreeMap<String, String> {
        self.entries.clone()
    }
    pub fn from_entries(entries: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        Ok(Self {
            entries: entries.clone(),
        })
    }
    pub fn from_entries_owned(entries: BTreeMap<String, String>) -> Self {
        Self { entries }
    }
    pub fn set_entry(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }
}

pub const ROOT_SECTION: &str = "_root";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteConfigData {
    pub extends: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RemoteConfigEnvelope {
    pub code: i64,
    pub msg: String,
    pub data: Option<RemoteConfigData>,
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum RemoteConfigError {
    #[error("remote config is not loaded")]
    NotLoaded,
    #[error("remote config client error: {0}")]
    Client(String),
    #[error("remote config server returned code {code}: {msg}")]
    Server { code: i64, msg: String },
    #[error("remote config envelope error: {0}")]
    Envelope(String),
}

pub trait RemoteConfigClient {
    type Error: Display;

    fn fetch_user_extends(&mut self) -> Result<RemoteConfigEnvelope, Self::Error>;

    fn save_user_extends(
        &mut self,
        extends: BTreeMap<String, String>,
    ) -> Result<RemoteConfigEnvelope, Self::Error>;
}

pub trait RemoteConfigWritebackSink: Send + Sync {
    fn stage(&self, config: Config);
    fn flush(&self) -> Result<(), RemoteConfigError>;
    fn shutdown(&self) -> Result<(), RemoteConfigError>;
}

pub struct RemoteConfigStore<C> {
    client: C,
    sections: BTreeMap<String, BTreeMap<String, ConfigValue>>,
    loaded: bool,
}

pub struct RemoteConfigWriteback<C>
where
    C: RemoteConfigClient + Send + 'static,
    C::Error: Send,
{
    command: mpsc::Sender<WritebackCommand>,
    worker: Mutex<Option<JoinHandle<Result<(), RemoteConfigError>>>>,
    _marker: std::marker::PhantomData<fn() -> C>,
}

enum WritebackCommand {
    Stage(Box<Config>),
    Flush(mpsc::Sender<Result<(), RemoteConfigError>>),
    Shutdown(mpsc::Sender<Result<(), RemoteConfigError>>),
}

const MIN_RETRY_DELAY: Duration = Duration::from_millis(10);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

impl<C> RemoteConfigStore<C>
where
    C: RemoteConfigClient,
{
    pub fn new(client: C) -> Self {
        Self {
            client,
            sections: BTreeMap::new(),
            loaded: false,
        }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn load(&mut self) -> Result<(), RemoteConfigError> {
        let envelope = self
            .client
            .fetch_user_extends()
            .map_err(|error| RemoteConfigError::Client(error.to_string()))?;
        if envelope.code != 0 {
            return Err(RemoteConfigError::Server {
                code: envelope.code,
                msg: envelope.msg,
            });
        }
        let data = envelope
            .data
            .ok_or_else(|| RemoteConfigError::Envelope("missing data".into()))?;
        let mut sections: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        for (flat_key, raw_value) in data.extends {
            if flat_key.is_empty() {
                continue;
            }
            let (section, key) = split_flat_key(&flat_key);
            let value = parse_value(&raw_value);
            sections
                .entry(section.to_owned())
                .or_default()
                .insert(key.to_owned(), value);
        }
        self.sections = sections;
        self.loaded = true;
        Ok(())
    }

    pub fn save(&mut self) -> Result<(), RemoteConfigError> {
        if !self.loaded {
            return Err(RemoteConfigError::NotLoaded);
        }
        let extends = self.flatten_sections()?;
        let envelope = self
            .client
            .save_user_extends(extends)
            .map_err(|error| RemoteConfigError::Client(error.to_string()))?;
        if envelope.code != 0 {
            return Err(RemoteConfigError::Server {
                code: envelope.code,
                msg: envelope.msg,
            });
        }
        Ok(())
    }

    pub fn stage_runtime_config(&mut self, config: &Config) -> bool {
        let config = config.clone().validate();
        let mut changed = false;
        for (flat_key, raw_value) in config.to_entries() {
            if flat_key.is_empty() {
                continue;
            }
            let (section, key) = split_flat_key(&flat_key);
            let value = parse_value(&raw_value);
            changed |= self.put_entry(section.to_owned(), key.to_owned(), value);
        }
        changed
    }

    pub fn save_runtime_config(&mut self, config: &Config) -> Result<(), RemoteConfigError> {
        self.stage_runtime_config(config);
        self.save()
    }

    /// Project the successfully loaded flattened store into the typed runtime
    /// configuration while retaining unknown values in this store for future
    /// saves.  A failed or not-yet-attempted load can never fabricate defaults
    /// as a production success.
    pub fn runtime_config(&self) -> Result<Config, RemoteConfigError> {
        if !self.loaded {
            return Err(RemoteConfigError::NotLoaded);
        }
        let entries = self.flatten_sections()?;
        Config::from_entries(&entries).map_err(|error| {
            RemoteConfigError::Envelope(format!("runtime config is invalid: {error:?}"))
        })
    }

    pub fn read_string(&self, section: &str, key: &str, default: impl Into<String>) -> String {
        self.lookup(section, key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| default.into())
    }

    pub fn read_i64(&self, section: &str, key: &str, default: i64) -> i64 {
        self.lookup(section, key)
            .and_then(Value::as_i64)
            .unwrap_or(default)
    }

    pub fn read_u64(&self, section: &str, key: &str, default: u64) -> u64 {
        self.lookup(section, key)
            .and_then(Value::as_u64)
            .unwrap_or(default)
    }

    pub fn read_f64(&self, section: &str, key: &str, default: f64) -> f64 {
        self.lookup(section, key)
            .and_then(Value::as_f64)
            .unwrap_or(default)
    }

    pub fn read_bool(&self, section: &str, key: &str, default: bool) -> bool {
        self.lookup(section, key)
            .and_then(Value::as_bool)
            .unwrap_or(default)
    }

    pub fn put_value(
        &mut self,
        section: impl Into<String>,
        key: impl Into<String>,
        value: ConfigValue,
    ) -> bool {
        self.put_entry(section.into(), key.into(), value)
    }

    pub fn put_string(
        &mut self,
        section: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> bool {
        self.put_entry(section.into(), key.into(), Value::String(value.into()))
    }

    pub fn put_i64(
        &mut self,
        section: impl Into<String>,
        key: impl Into<String>,
        value: i64,
    ) -> bool {
        self.put_entry(section.into(), key.into(), Value::from(value))
    }

    pub fn put_u64(
        &mut self,
        section: impl Into<String>,
        key: impl Into<String>,
        value: u64,
    ) -> bool {
        self.put_entry(section.into(), key.into(), Value::from(value))
    }

    pub fn put_f64(
        &mut self,
        section: impl Into<String>,
        key: impl Into<String>,
        value: f64,
    ) -> bool {
        self.put_entry(section.into(), key.into(), Value::from(value))
    }

    pub fn put_bool(
        &mut self,
        section: impl Into<String>,
        key: impl Into<String>,
        value: bool,
    ) -> bool {
        self.put_entry(section.into(), key.into(), Value::from(value))
    }

    pub fn remove_key(&mut self, section: &str, key: &str) -> bool {
        let mut changed = false;
        if let Some(values) = self.sections.get_mut(section) {
            changed = values.remove(key).is_some();
        }
        changed
    }

    pub fn clear(&mut self) -> bool {
        let changed = !self.sections.is_empty();
        self.sections.clear();
        changed
    }

    fn lookup(&self, section: &str, key: &str) -> Option<&Value> {
        self.sections.get(section)?.get(key)
    }

    fn put_entry(&mut self, section: String, key: String, value: Value) -> bool {
        let values = self.sections.entry(section).or_default();
        match values.get(&key) {
            Some(existing) if existing == &value => false,
            _ => {
                values.insert(key, value);
                true
            }
        }
    }

    fn flatten_sections(&self) -> Result<BTreeMap<String, String>, RemoteConfigError> {
        let mut flat = BTreeMap::new();
        for (section, values) in &self.sections {
            for (key, value) in values {
                let flat_key = if section == ROOT_SECTION {
                    key.clone()
                } else {
                    format!("{section}.{key}")
                };
                let text = serde_json::to_string(value)
                    .map_err(|error| RemoteConfigError::Envelope(error.to_string()))?;
                flat.insert(flat_key, text);
            }
        }
        Ok(flat)
    }
}

fn parse_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

fn split_flat_key(flat_key: &str) -> (&str, &str) {
    match flat_key.split_once('.') {
        Some((section, key)) => (section, key),
        None => (ROOT_SECTION, flat_key),
    }
}

impl<C> RemoteConfigWriteback<C>
where
    C: RemoteConfigClient + Send + 'static,
    C::Error: Send,
{
    pub fn new(store: RemoteConfigStore<C>, debounce: Duration) -> Self {
        let (command_tx, command_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            crate::threading::enter("config-writeback", crate::threading::WorkerRole::Service);
            run_writeback_worker(store, command_rx, debounce)
        });
        Self {
            command: command_tx,
            worker: Mutex::new(Some(worker)),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn stage(&self, config: Config) {
        <Self as RemoteConfigWritebackSink>::stage(self, config);
    }

    pub fn flush(&self) -> Result<(), RemoteConfigError> {
        <Self as RemoteConfigWritebackSink>::flush(self)
    }

    pub fn shutdown(&self) -> Result<(), RemoteConfigError> {
        <Self as RemoteConfigWritebackSink>::shutdown(self)
    }

    fn request(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<(), RemoteConfigError>>) -> WritebackCommand,
    ) -> Result<(), RemoteConfigError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.command.send(command(reply_tx)).map_err(|_| {
            RemoteConfigError::Client("remote config writeback worker is closed".into())
        })?;
        reply_rx.recv().map_err(|_| {
            RemoteConfigError::Client("remote config writeback worker is closed".into())
        })?
    }
}

impl<C> RemoteConfigWritebackSink for RemoteConfigWriteback<C>
where
    C: RemoteConfigClient + Send + 'static,
    C::Error: Send,
{
    fn stage(&self, config: Config) {
        let _ = self.command.send(WritebackCommand::Stage(Box::new(config)));
    }

    fn flush(&self) -> Result<(), RemoteConfigError> {
        self.request(WritebackCommand::Flush)
    }

    fn shutdown(&self) -> Result<(), RemoteConfigError> {
        let result = self.request(WritebackCommand::Shutdown);
        if let Some(worker) = self.worker.lock().expect("writeback poisoned").take() {
            let join = worker.join().map_err(|_| {
                RemoteConfigError::Client("remote config writeback worker panicked".into())
            })?;
            return result.and(join);
        }
        result
    }
}

impl<C> Drop for RemoteConfigWriteback<C>
where
    C: RemoteConfigClient + Send + 'static,
    C::Error: Send,
{
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_writeback_worker<C>(
    mut store: RemoteConfigStore<C>,
    command_rx: mpsc::Receiver<WritebackCommand>,
    debounce: Duration,
) -> Result<(), RemoteConfigError>
where
    C: RemoteConfigClient + Send + 'static,
    C::Error: Send,
{
    let mut pending: Option<Config> = None;
    let mut deadline: Option<Instant> = None;
    let mut retry_attempt = 0u32;
    loop {
        match deadline {
            Some(target) => {
                let now = Instant::now();
                if now >= target {
                    let result = flush_pending(&mut store, &mut pending);
                    deadline = schedule_after_flush(result, &pending, debounce, &mut retry_attempt);
                    continue;
                }
                match command_rx.recv_timeout(target.saturating_duration_since(now)) {
                    Ok(WritebackCommand::Stage(config)) => {
                        pending = Some(*config);
                        retry_attempt = 0;
                        deadline = Some(Instant::now() + debounce);
                    }
                    Ok(WritebackCommand::Flush(reply)) => {
                        let result = flush_pending(&mut store, &mut pending);
                        let _ = reply.send(result.clone());
                        deadline =
                            schedule_after_flush(result, &pending, debounce, &mut retry_attempt);
                    }
                    Ok(WritebackCommand::Shutdown(reply)) => {
                        let result = flush_pending(&mut store, &mut pending);
                        let _ = reply.send(result.clone());
                        return result;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let result = flush_pending(&mut store, &mut pending);
                        deadline =
                            schedule_after_flush(result, &pending, debounce, &mut retry_attempt);
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return flush_pending(&mut store, &mut pending);
                    }
                }
            }
            None => match command_rx.recv() {
                Ok(WritebackCommand::Stage(config)) => {
                    pending = Some(*config);
                    retry_attempt = 0;
                    deadline = Some(Instant::now() + debounce);
                }
                Ok(WritebackCommand::Flush(reply)) => {
                    let result = flush_pending(&mut store, &mut pending);
                    let _ = reply.send(result.clone());
                    deadline = schedule_after_flush(result, &pending, debounce, &mut retry_attempt);
                }
                Ok(WritebackCommand::Shutdown(reply)) => {
                    let result = flush_pending(&mut store, &mut pending);
                    let _ = reply.send(result.clone());
                    return result;
                }
                Err(_) => return flush_pending(&mut store, &mut pending),
            },
        }
    }
}

fn schedule_after_flush(
    result: Result<(), RemoteConfigError>,
    pending: &Option<Config>,
    debounce: Duration,
    retry_attempt: &mut u32,
) -> Option<Instant> {
    if result.is_ok() {
        *retry_attempt = 0;
        return pending.as_ref().map(|_| Instant::now() + debounce);
    }

    if pending.is_some() {
        let delay = retry_delay(debounce, *retry_attempt);
        *retry_attempt = retry_attempt.saturating_add(1);
        Some(Instant::now() + delay)
    } else {
        *retry_attempt = 0;
        None
    }
}

fn retry_delay(debounce: Duration, attempt: u32) -> Duration {
    let base = debounce.max(MIN_RETRY_DELAY);
    let multiplier = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
    base.checked_mul(multiplier)
        .unwrap_or(MAX_RETRY_DELAY)
        .min(MAX_RETRY_DELAY)
}

fn flush_pending<C>(
    store: &mut RemoteConfigStore<C>,
    pending: &mut Option<Config>,
) -> Result<(), RemoteConfigError>
where
    C: RemoteConfigClient,
{
    let Some(config) = pending.as_ref() else {
        return Ok(());
    };
    store.save_runtime_config(config)?;
    pending.take();
    Ok(())
}
