#![allow(non_snake_case)]

#[cfg(panic = "unwind")]
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};

use crate::math::Vec3;

use super::{DfcolArchive, DfcolZipModels, Scene};

pub const PACK_STORED_BYTES: usize = 81_894_203;

pub trait PackBytes: Send + Sync {
    fn Bytes(&self) -> &[u8];
}

#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackStatus {
    NoCommittedPack = 0,
    PackCommitted = 1,
    ActiveSceneReady = 2,
}

trait SceneLoader: Send + Sync + 'static {
    fn LoadScene(&self, pack: Arc<dyn PackBytes>, map_name: &str) -> Option<Arc<Scene>>;
}

struct RealSceneLoader;

impl SceneLoader for RealSceneLoader {
    fn LoadScene(&self, pack: Arc<dyn PackBytes>, map_name: &str) -> Option<Arc<Scene>> {
        let model = DfcolZipModels()
            .iter()
            .find(|model| model.map_name == map_name)?;
        let archive = DfcolArchive::Open(pack.Bytes()).ok()?;
        let bytes = archive
            .Inflate(model.entry_name, model.raw_size as usize)
            .ok()?;
        Scene::Load(&bytes, model.map_name).ok()
    }
}

struct RegistryState {
    pending_generation: u64,
    pending: Option<Arc<dyn PackBytes>>,
    committed_generation: u64,
    committed: Option<Arc<dyn PackBytes>>,
    requested_map: String,
    request_token: u64,
    loading_token: u64,
    loading_map: String,
    failed_token: u64,
    failed_map: String,
    work_revision: u64,
    shutdown: bool,
}

struct RegistryShared {
    state: Mutex<RegistryState>,
    load_cv: Condvar,
    active: RwLock<Option<Arc<Scene>>>,
}

pub struct DfcolRegistry {
    shared: Arc<RegistryShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    loader: Arc<dyn SceneLoader>,
}

impl DfcolRegistry {
    pub fn New() -> Self {
        Self::WithLoader(Arc::new(RealSceneLoader))
    }

    fn WithLoader(loader: Arc<dyn SceneLoader>) -> Self {
        Self {
            shared: Arc::new(RegistryShared {
                state: Mutex::new(RegistryState {
                    pending_generation: 0,
                    pending: None,
                    committed_generation: 0,
                    committed: None,
                    requested_map: String::new(),
                    request_token: 0,
                    loading_token: 0,
                    loading_map: String::new(),
                    failed_token: 0,
                    failed_map: String::new(),
                    work_revision: 0,
                    shutdown: false,
                }),
                load_cv: Condvar::new(),
                active: RwLock::new(None),
            }),
            worker: Mutex::new(None),
            loader,
        }
    }

    #[cfg(test)]
    fn NewWithLoaderForTests(loader: Arc<dyn SceneLoader>) -> Self {
        Self::WithLoader(loader)
    }

    #[cfg(test)]
    fn DebugActiveMapForTests(&self) -> Option<String> {
        self.shared
            .active
            .read()
            .ok()
            .and_then(|active| active.as_ref().map(|scene| scene.Name().to_owned()))
    }

    fn CanonicalMap(level_name: &str) -> String {
        if level_name.is_empty() {
            return "SecretService".to_owned();
        }
        if DfcolZipModels()
            .iter()
            .any(|model| model.map_name == level_name)
        {
            level_name.to_owned()
        } else {
            String::new()
        }
    }

    fn EnsureLoadWorkerLocked(&self) -> bool {
        let Ok(mut worker) = self.worker.lock() else {
            return false;
        };
        if worker.is_some() {
            return true;
        }
        let shared = Arc::clone(&self.shared);
        let loader = Arc::clone(&self.loader);
        let Ok(handle) = thread::Builder::new()
            .name("dfcol-loader".to_owned())
            .spawn(move || {
                crate::threading::enter("dfcol-loader", crate::threading::WorkerRole::Service);
                Self::LoadWorker(shared, loader)
            })
        else {
            return false;
        };
        *worker = Some(handle);
        true
    }

    fn TryQueueRequestedLocked(&self, state: &mut RegistryState) {
        if state.requested_map.is_empty() {
            return;
        }
        if state.failed_token == state.request_token && state.failed_map == state.requested_map {
            return;
        }
        if state.loading_token == state.request_token && state.loading_map == state.requested_map {
            return;
        }
        if self
            .shared
            .active
            .read()
            .ok()
            .and_then(|active| {
                active
                    .as_ref()
                    .map(|scene| scene.Name() == state.requested_map)
            })
            .unwrap_or(false)
        {
            return;
        }
        if state.committed.is_none() || !self.EnsureLoadWorkerLocked() {
            return;
        }
        state.work_revision = state.work_revision.wrapping_add(1);
        self.shared.load_cv.notify_one();
    }

    fn LoadWorker(shared: Arc<RegistryShared>, loader: Arc<dyn SceneLoader>) {
        let mut observed_revision = 0;
        loop {
            let job = {
                let Ok(mut state) = shared.state.lock() else {
                    return;
                };
                while observed_revision == state.work_revision && !state.shutdown {
                    let Ok(waited) = shared.load_cv.wait(state) else {
                        return;
                    };
                    state = waited;
                }
                if state.shutdown {
                    return;
                }
                observed_revision = state.work_revision;
                if state.requested_map.is_empty()
                    || (state.failed_token == state.request_token
                        && state.failed_map == state.requested_map)
                {
                    continue;
                }
                let Some(pack) = state.committed.clone() else {
                    continue;
                };
                if shared
                    .active
                    .read()
                    .ok()
                    .and_then(|active| {
                        active
                            .as_ref()
                            .map(|scene| scene.Name() == state.requested_map)
                    })
                    .unwrap_or(false)
                {
                    continue;
                }
                let job = LoadJob {
                    map_name: state.requested_map.clone(),
                    pack,
                    token: state.request_token,
                };
                state.loading_token = job.token;
                state.loading_map = job.map_name.clone();
                job
            };

            // `panic=unwind` keeps a faulty map loader isolated to this worker.
            // Release Android builds use `panic=abort`; there is no unwind
            // boundary in that mode, so invoke the loader directly and let the
            // process-level abort policy apply to an unexpected panic.
            #[cfg(panic = "unwind")]
            let scene = catch_unwind(AssertUnwindSafe(|| {
                loader.LoadScene(Arc::clone(&job.pack), &job.map_name)
            }))
            .unwrap_or(None);
            #[cfg(panic = "abort")]
            let scene = loader.LoadScene(Arc::clone(&job.pack), &job.map_name);
            Self::PublishLoadResult(&shared, job, scene);
        }
    }

    fn PublishLoadResult(shared: &RegistryShared, job: LoadJob, scene: Option<Arc<Scene>>) {
        let Ok(mut state) = shared.state.lock() else {
            return;
        };
        if state.loading_token == job.token && state.loading_map == job.map_name {
            state.loading_token = 0;
            state.loading_map.clear();
        }
        if job.token != state.request_token || job.map_name != state.requested_map {
            return;
        }
        let Some(committed) = state.committed.as_ref() else {
            return;
        };
        if !Arc::ptr_eq(committed, &job.pack) {
            return;
        }
        if let Some(scene) = scene {
            state.failed_token = 0;
            state.failed_map.clear();
            if let Ok(mut active) = shared.active.write() {
                *active = Some(scene);
            }
        } else {
            state.failed_token = job.token;
            state.failed_map = job.map_name;
            if let Ok(mut active) = shared.active.write() {
                *active = None;
            }
        }
    }

    pub fn new() -> Self {
        Self::New()
    }

    pub fn BeginPack(&self, generation: u64) -> bool {
        let Ok(mut state) = self.shared.state.lock() else {
            return false;
        };
        if generation == 0 || generation <= state.committed_generation {
            return false;
        }
        state.pending = None;
        state.pending_generation = generation;
        true
    }

    pub fn AdoptPack(&self, generation: u64, pack: Arc<dyn PackBytes>) -> bool {
        self.TryAdoptPack(generation, pack).is_ok()
    }

    pub fn TryAdoptPack(
        &self,
        generation: u64,
        pack: Arc<dyn PackBytes>,
    ) -> Result<(), Arc<dyn PackBytes>> {
        if generation == 0 || DfcolArchive::Open(pack.Bytes()).is_err() {
            return Err(pack);
        }
        let Ok(mut state) = self.shared.state.lock() else {
            return Err(pack);
        };
        if state.pending_generation != generation {
            return Err(pack);
        }
        state.pending = Some(pack);
        Ok(())
    }

    pub fn CommitPack(&self, generation: u64, expected_count: u32) -> bool {
        if generation == 0 || expected_count != 1 {
            return false;
        }
        let Ok(mut state) = self.shared.state.lock() else {
            return false;
        };
        if state.pending_generation != generation
            || generation <= state.committed_generation
            || state.pending.is_none()
        {
            return false;
        }
        state.committed = state.pending.take();
        state.committed_generation = generation;
        state.pending_generation = 0;
        state.request_token = state.request_token.wrapping_add(1);
        state.failed_token = 0;
        state.failed_map.clear();
        if let Ok(mut active) = self.shared.active.write() {
            *active = None;
        }
        self.TryQueueRequestedLocked(&mut state);
        true
    }

    pub fn AbortPack(&self, generation: u64) {
        if let Ok(mut state) = self.shared.state.lock() {
            if state.pending_generation == generation {
                state.pending = None;
                state.pending_generation = 0;
            }
        }
    }

    pub fn RequestMap(&self, level_name: &str) {
        let map_name = Self::CanonicalMap(level_name);
        let Ok(mut state) = self.shared.state.lock() else {
            return;
        };
        let active_matches = self
            .shared
            .active
            .read()
            .ok()
            .and_then(|active| active.as_ref().map(|scene| scene.Name() == map_name))
            .unwrap_or(false);
        let has_active = self
            .shared
            .active
            .read()
            .map(|active| active.is_some())
            .unwrap_or(false);
        if map_name == state.requested_map && (!has_active || active_matches) {
            if !has_active {
                self.TryQueueRequestedLocked(&mut state);
            }
            return;
        }
        state.requested_map = map_name;
        state.request_token = state.request_token.wrapping_add(1);
        state.failed_token = 0;
        state.failed_map.clear();
        if let Ok(mut active) = self.shared.active.write() {
            *active = None;
        }
        self.TryQueueRequestedLocked(&mut state);
    }

    pub fn ClearActiveScene(&self) {
        let Ok(mut state) = self.shared.state.lock() else {
            return;
        };
        state.requested_map.clear();
        state.request_token = state.request_token.wrapping_add(1);
        state.failed_token = 0;
        state.failed_map.clear();
        if let Ok(mut active) = self.shared.active.write() {
            *active = None;
        }
    }

    pub fn GetPackStatus(&self) -> PackStatus {
        let Ok(state) = self.shared.state.lock() else {
            return PackStatus::NoCommittedPack;
        };
        if state.committed.is_none() {
            return PackStatus::NoCommittedPack;
        }
        drop(state);
        match self.shared.active.read() {
            Ok(active) if active.is_some() => PackStatus::ActiveSceneReady,
            _ => PackStatus::PackCommitted,
        }
    }

    pub fn LinecastLocal(&self, from: Vec3, to: Vec3, world_origin: Vec3) -> bool {
        let Ok(active) = self.shared.active.read() else {
            return true;
        };
        let Some(scene) = active.as_ref() else {
            return true;
        };
        if !from.is_finite() || !to.is_finite() || !world_origin.is_finite() {
            return true;
        }
        let persistent_from = from + world_origin;
        let persistent_to = to + world_origin;
        if !persistent_from.is_finite() || !persistent_to.is_finite() {
            return true;
        }
        scene.Linecast(persistent_from, persistent_to)
    }

    pub fn LinecastLocalBatch(
        &self,
        from: Vec3,
        targets: &[Vec3],
        world_origin: Vec3,
        blocked: &mut [bool],
    ) {
        blocked.fill(true);
        if blocked.len() != targets.len() || !from.is_finite() || !world_origin.is_finite() {
            return;
        }

        let persistent_from = from + world_origin;
        if !persistent_from.is_finite() {
            return;
        }
        let still_active = self.WithActiveSceneSnapshot(|scene| {
            for (blocked, &target) in blocked.iter_mut().zip(targets) {
                if !target.is_finite() {
                    continue;
                }
                let persistent_to = target + world_origin;
                if persistent_to.is_finite() {
                    *blocked = scene.Linecast(persistent_from, persistent_to);
                }
            }
        });
        if !still_active {
            blocked.fill(true);
        }
    }

    // Keep the immutable scene alive without holding the registry lock while
    // geometry is queried. Results are usable only if that exact scene remains active.
    fn WithActiveSceneSnapshot(&self, query: impl FnOnce(&Scene)) -> bool {
        let scene = {
            let Ok(active) = self.shared.active.read() else {
                return false;
            };
            let Some(scene) = active.as_ref() else {
                return false;
            };
            Arc::clone(scene)
        };

        query(&scene);

        self.shared
            .active
            .read()
            .ok()
            .and_then(|active| active.as_ref().map(|current| Arc::ptr_eq(current, &scene)))
            .unwrap_or(false)
    }
}

impl Default for DfcolRegistry {
    fn default() -> Self {
        Self::New()
    }
}

struct LoadJob {
    map_name: String,
    pack: Arc<dyn PackBytes>,
    token: u64,
}

impl Drop for DfcolRegistry {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.shutdown = true;
            self.shared.load_cv.notify_all();
        }
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(handle) = worker.take() {
                let _ = handle.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Condvar;
    use std::thread;
    use std::time::{Duration, Instant};

    struct FixturePack(Vec<u8>);

    impl PackBytes for FixturePack {
        fn Bytes(&self) -> &[u8] {
            &self.0
        }
    }

    struct Gate {
        open: Mutex<bool>,
        cv: Condvar,
    }

    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                open: Mutex::new(false),
                cv: Condvar::new(),
            })
        }

        fn wait(&self) {
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.cv.wait(open).unwrap();
            }
        }

        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.cv.notify_all();
        }
    }

    enum LoadAction {
        Succeed,
        Fail,
        Panic,
        WaitThenSucceed(Arc<Gate>),
    }

    struct RecordingLoader {
        calls: Arc<(Mutex<Vec<String>>, Condvar)>,
        actions: Mutex<VecDeque<LoadAction>>,
    }

    impl RecordingLoader {
        fn new(actions: impl IntoIterator<Item = LoadAction>) -> Arc<Self> {
            Arc::new(Self {
                calls: Arc::new((Mutex::new(Vec::new()), Condvar::new())),
                actions: Mutex::new(actions.into_iter().collect()),
            })
        }

        fn wait_for_calls(&self, count: usize) -> Vec<String> {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (lock, cv) = &*self.calls;
            let mut calls = lock.lock().unwrap();
            while calls.len() < count {
                let now = Instant::now();
                assert!(now < deadline, "timed out waiting for {count} loader calls");
                let timeout = deadline - now;
                calls = cv.wait_timeout(calls, timeout).unwrap().0;
            }
            calls.clone()
        }

        fn calls(&self) -> Vec<String> {
            self.calls.0.lock().unwrap().clone()
        }
    }

    impl SceneLoader for RecordingLoader {
        fn LoadScene(&self, _: Arc<dyn PackBytes>, map_name: &str) -> Option<Arc<Scene>> {
            {
                let (lock, cv) = &*self.calls;
                lock.lock().unwrap().push(map_name.to_owned());
                cv.notify_all();
            }
            let action = self.actions.lock().unwrap().pop_front();
            match action {
                Some(LoadAction::Succeed) | None => Some(scene(map_name)),
                Some(LoadAction::Fail) => None,
                Some(LoadAction::Panic) => panic!("loader panic for {map_name}"),
                Some(LoadAction::WaitThenSucceed(gate)) => {
                    gate.wait();
                    Some(scene(map_name))
                }
            }
        }
    }

    fn wait_for_status(registry: &DfcolRegistry, status: PackStatus) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if registry.GetPackStatus() == status {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(registry.GetPackStatus(), status);
    }

    fn catalog_pack() -> Arc<dyn PackBytes> {
        let models = DfcolZipModels();
        let mut bytes = Vec::new();
        let mut local_offsets = [0usize; 7];
        for (index, model) in models.iter().enumerate() {
            local_offsets[index] = bytes.len();
            bytes.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&8u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&model.raw_crc32.to_le_bytes());
            bytes.extend_from_slice(&2u32.to_le_bytes());
            bytes.extend_from_slice(&model.raw_size.to_le_bytes());
            bytes.extend_from_slice(&(model.entry_name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(model.entry_name.as_bytes());
            bytes.extend_from_slice(&[0x03, 0x00]);
        }
        let central_start = bytes.len();
        for (index, model) in models.iter().enumerate() {
            bytes.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&8u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&model.raw_crc32.to_le_bytes());
            bytes.extend_from_slice(&2u32.to_le_bytes());
            bytes.extend_from_slice(&model.raw_size.to_le_bytes());
            bytes.extend_from_slice(&(model.entry_name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(local_offsets[index] as u32).to_le_bytes());
            bytes.extend_from_slice(model.entry_name.as_bytes());
        }
        let central_size = bytes.len() - central_start;
        bytes.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.extend_from_slice(&(central_size as u32).to_le_bytes());
        bytes.extend_from_slice(&(central_start as u32).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        Arc::new(FixturePack(bytes))
    }

    fn scene(name: &str) -> Arc<Scene> {
        let mut bytes = vec![0u8; 64 + 12 + 92];
        bytes[..8].copy_from_slice(b"DFCOL\r\n\x1a");
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&64u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&1u32.to_le_bytes());
        bytes[48..56].copy_from_slice(&(104u64).to_le_bytes());
        write_vec3(&mut bytes, 64, [1.0, 1.0, 1.0]);
        write_identity_quat(&mut bytes, 76);
        write_vec3(&mut bytes, 92, [0.0, 0.0, 0.0]);
        bytes[104] = 2;
        write_vec3(&mut bytes, 108, [1.0, 1.0, 1.0]);
        write_identity_quat(&mut bytes, 120);
        write_identity_quat(&mut bytes, 136);
        write_vec3(&mut bytes, 152, [0.0, 0.0, 0.0]);
        recompute_crcs(&mut bytes);
        Scene::Load(&bytes, name).unwrap()
    }

    fn write_f32(bytes: &mut [u8], offset: usize, value: f32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_vec3(bytes: &mut [u8], offset: usize, value: [f32; 3]) {
        for (index, value) in value.into_iter().enumerate() {
            write_f32(bytes, offset + index * 4, value);
        }
    }

    fn write_identity_quat(bytes: &mut [u8], offset: usize) {
        write_vec3(bytes, offset, [0.0, 0.0, 0.0]);
        write_f32(bytes, offset + 12, 1.0);
    }

    fn recompute_crcs(bytes: &mut [u8]) {
        let mut payload_crc = crc32fast::Hasher::new();
        payload_crc.update(&bytes[64..]);
        bytes[56..60].copy_from_slice(&payload_crc.finalize().to_le_bytes());
        let mut header_crc = crc32fast::Hasher::new();
        header_crc.update(&bytes[..60]);
        bytes[60..64].copy_from_slice(&header_crc.finalize().to_le_bytes());
    }

    fn committed_registry(loader: Arc<dyn SceneLoader>) -> DfcolRegistry {
        let registry = DfcolRegistry::NewWithLoaderForTests(loader);
        assert!(registry.BeginPack(1));
        assert!(registry.AdoptPack(1, catalog_pack()));
        assert!(registry.CommitPack(1, 1));
        registry
    }

    fn registry_with_active_scene() -> DfcolRegistry {
        let registry = DfcolRegistry::New();
        *registry.shared.active.write().unwrap() = Some(scene("SecretService"));
        registry
    }

    #[test]
    fn batch_matches_singular_queries_and_applies_world_origin_once() {
        let registry = registry_with_active_scene();
        let origin = Vec3::new(100.0, -200.0, 50.0);
        let from = Vec3::new(-2.0, 0.0, 0.0) - origin;
        let targets = [
            Vec3::new(2.0, 0.0, 0.0) - origin,
            Vec3::new(-2.0, 5.0, 0.0) - origin,
            from,
            Vec3::zero() - origin,
        ];
        let expected = targets.map(|to| registry.LinecastLocal(from, to, origin));
        assert_eq!(expected, [true, false, false, true]);
        let mut blocked = [false; 4];
        registry.LinecastLocalBatch(from, &targets, origin, &mut blocked);
        assert_eq!(blocked, expected);
    }

    #[test]
    fn batch_invalid_endpoints_do_not_skip_other_targets() {
        let registry = registry_with_active_scene();
        let from = Vec3::new(-2.0, 0.0, 0.0);
        let targets = [
            Vec3::new(-2.0, 5.0, 0.0),
            Vec3::new(f32::NAN, 0.0, 0.0),
            Vec3::new(2.0, 0.0, 0.0),
            Vec3::new(f32::INFINITY, 0.0, 0.0),
            Vec3::new(-2.0, -5.0, 0.0),
        ];
        let mut blocked = [false; 5];
        registry.LinecastLocalBatch(from, &targets, Vec3::zero(), &mut blocked);
        assert_eq!(blocked, [false, true, true, true, false]);
    }

    #[test]
    fn batch_invalid_shared_inputs_and_lengths_fail_closed() {
        let registry = registry_with_active_scene();
        let from = Vec3::new(-2.0, 0.0, 0.0);
        let targets = [Vec3::new(-2.0, 5.0, 0.0); 2];
        for (from, origin) in [
            (Vec3::new(f32::NAN, 0.0, 0.0), Vec3::zero()),
            (from, Vec3::new(0.0, f32::INFINITY, 0.0)),
            (Vec3::new(f32::MAX, 0.0, 0.0), Vec3::new(f32::MAX, 0.0, 0.0)),
        ] {
            let mut blocked = [false; 2];
            registry.LinecastLocalBatch(from, &targets, origin, &mut blocked);
            assert_eq!(blocked, [true; 2]);
        }
        let mut short = [false];
        registry.LinecastLocalBatch(from, &targets, Vec3::zero(), &mut short);
        assert_eq!(short, [true]);
        let mut long = [false; 3];
        registry.LinecastLocalBatch(from, &targets, Vec3::zero(), &mut long);
        assert_eq!(long, [true; 3]);
        registry.LinecastLocalBatch(from, &[], Vec3::zero(), &mut []);
    }

    #[test]
    fn batch_translated_endpoint_overflow_is_independently_blocked() {
        let registry = registry_with_active_scene();
        let from = Vec3::new(-f32::MAX, 0.0, 0.0);
        let origin = Vec3::new(f32::MAX, 0.0, 0.0);
        let targets = [Vec3::new(f32::MAX, 0.0, 0.0), from];
        let mut blocked = [false; 2];
        registry.LinecastLocalBatch(from, &targets, origin, &mut blocked);
        assert_eq!(blocked, [true, false]);
    }

    #[test]
    fn active_snapshot_releases_lock_and_detects_clear_during_queries() {
        let registry = registry_with_active_scene();
        let valid = registry.WithActiveSceneSnapshot(|snapshot| {
            assert!(registry.shared.active.try_write().is_ok());
            registry.ClearActiveScene();
            assert!(!snapshot.Linecast(Vec3::new(-2.0, 0.0, 0.0), Vec3::new(-2.0, 5.0, 0.0)));
        });
        assert!(!valid);
    }

    #[test]
    fn active_snapshot_detects_replacement_even_with_the_same_map_name() {
        let registry = registry_with_active_scene();
        assert!(!registry.WithActiveSceneSnapshot(|snapshot| {
            let replacement = scene(snapshot.Name());
            *registry.shared.active.try_write().unwrap() = Some(replacement);
        }));
    }

    #[test]
    fn active_snapshot_accepts_unchanged_scene_and_skips_missing_scene() {
        let registry = registry_with_active_scene();
        assert!(registry.WithActiveSceneSnapshot(|snapshot| {
            assert!(snapshot.Linecast(Vec3::new(-2.0, 0.0, 0.0), Vec3::new(2.0, 0.0, 0.0)));
        }));
        registry.ClearActiveScene();
        assert!(!registry.WithActiveSceneSnapshot(|_| panic!("missing scene must not be queried")));
    }

    #[test]
    fn stale_loading_result_cannot_replace_a_newer_request() {
        let first_load = Gate::new();
        let loader = RecordingLoader::new([
            LoadAction::WaitThenSucceed(first_load.clone()),
            LoadAction::Succeed,
        ]);
        let registry = committed_registry(loader.clone());

        registry.RequestMap("Brakkesh");
        assert_eq!(loader.wait_for_calls(1), vec!["Brakkesh"]);
        registry.RequestMap("SecretService");
        assert_eq!(loader.calls().len(), 1);
        first_load.release();

        assert_eq!(loader.wait_for_calls(2), vec!["Brakkesh", "SecretService"]);
        wait_for_status(&registry, PackStatus::ActiveSceneReady);
        assert_eq!(
            registry.DebugActiveMapForTests().as_deref(),
            Some("SecretService")
        );
    }

    #[test]
    fn failed_request_token_is_not_retried_until_a_new_pack_commits() {
        let loader = RecordingLoader::new([LoadAction::Fail, LoadAction::Succeed]);
        let registry = committed_registry(loader.clone());

        registry.RequestMap("SecretService");
        assert_eq!(loader.wait_for_calls(1), vec!["SecretService"]);
        wait_for_status(&registry, PackStatus::PackCommitted);
        registry.RequestMap("SecretService");
        thread::sleep(Duration::from_millis(50));
        assert_eq!(loader.calls(), vec!["SecretService"]);

        assert!(registry.BeginPack(2));
        assert!(registry.AdoptPack(2, catalog_pack()));
        assert!(registry.CommitPack(2, 1));

        assert_eq!(
            loader.wait_for_calls(2),
            vec!["SecretService", "SecretService"]
        );
        wait_for_status(&registry, PackStatus::ActiveSceneReady);
    }

    #[test]
    fn panicking_loader_stays_alive_and_retries_same_map_after_new_pack_commit() {
        let loader = RecordingLoader::new([LoadAction::Panic, LoadAction::Succeed]);
        let registry = committed_registry(loader.clone());

        registry.RequestMap("SecretService");
        assert_eq!(loader.wait_for_calls(1), vec!["SecretService"]);

        assert!(registry.BeginPack(2));
        assert!(registry.AdoptPack(2, catalog_pack()));
        assert!(registry.CommitPack(2, 1));

        assert_eq!(
            loader.wait_for_calls(2),
            vec!["SecretService", "SecretService"]
        );
        wait_for_status(&registry, PackStatus::ActiveSceneReady);
    }

    #[test]
    fn committed_generation_rejects_older_and_duplicate_pack_transactions() {
        let loader = RecordingLoader::new([LoadAction::Succeed]);
        let registry = DfcolRegistry::NewWithLoaderForTests(loader.clone());
        assert!(registry.BeginPack(10));
        assert!(registry.AdoptPack(10, catalog_pack()));
        assert!(registry.CommitPack(10, 1));
        registry.RequestMap("SecretService");
        assert_eq!(loader.wait_for_calls(1), vec!["SecretService"]);
        wait_for_status(&registry, PackStatus::ActiveSceneReady);

        for generation in [9, 10] {
            assert!(!registry.BeginPack(generation));
            assert!(!registry.AdoptPack(generation, catalog_pack()));
            assert!(!registry.CommitPack(generation, 1));
            assert_eq!(registry.GetPackStatus(), PackStatus::ActiveSceneReady);
            assert_eq!(
                registry.DebugActiveMapForTests().as_deref(),
                Some("SecretService")
            );
        }
        assert_eq!(loader.calls(), vec!["SecretService"]);
    }

    #[test]
    fn duplicate_request_while_loading_is_not_queued_twice() {
        let load = Gate::new();
        let loader = RecordingLoader::new([LoadAction::WaitThenSucceed(load.clone())]);
        let registry = committed_registry(loader.clone());

        registry.RequestMap("SecretService");
        assert_eq!(loader.wait_for_calls(1), vec!["SecretService"]);
        registry.RequestMap("SecretService");
        thread::sleep(Duration::from_millis(50));

        assert_eq!(loader.calls(), vec!["SecretService"]);
        load.release();
        wait_for_status(&registry, PackStatus::ActiveSceneReady);
    }

    #[test]
    fn clear_cancels_an_in_flight_request() {
        let load = Gate::new();
        let loader = RecordingLoader::new([LoadAction::WaitThenSucceed(load.clone())]);
        let registry = committed_registry(loader.clone());

        registry.RequestMap("SecretService");
        assert_eq!(loader.wait_for_calls(1), vec!["SecretService"]);
        registry.ClearActiveScene();
        load.release();
        thread::sleep(Duration::from_millis(50));

        assert_eq!(registry.DebugActiveMapForTests(), None);
        assert_eq!(registry.GetPackStatus(), PackStatus::PackCommitted);
        assert_eq!(loader.calls(), vec!["SecretService"]);
    }

    #[cfg(panic = "abort")]
    #[test]
    fn abort_profile_loads_scene_without_unwind_boundary() {
        let loader = RecordingLoader::new([LoadAction::Succeed]);
        let registry = committed_registry(loader.clone());

        registry.RequestMap("SecretService");
        assert_eq!(loader.wait_for_calls(1), vec!["SecretService"]);
        wait_for_status(&registry, PackStatus::ActiveSceneReady);
        assert_eq!(
            registry.DebugActiveMapForTests().as_deref(),
            Some("SecretService")
        );
    }
}
