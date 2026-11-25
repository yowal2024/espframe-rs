//! Shared UDP capture ring owned by the calling Rust process.
//! pid selects captured sockets only. Published slots remain immutable until
//! this single consumer releases them; no references into a slot escape Read.
use super::{abi::*, KernelDriver, KernelTransport};
use core::{
    mem::{offset_of, size_of},
    ptr::{self, NonNull},
};
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc,
};

pub const CP_START: usize = 1;
pub const CP_STOP: usize = 2;
// Reproducible trusted ARM64 ELF, built from kernel/plugins/udp_capture.c.
const CAPTURE_PLUGIN: &[u8] = include_bytes!("plugins/udp_capture.cp");

#[repr(C)]
pub struct UdpCapSharedHeader {
    pub state: AtomicU32,
    pub queue_count: u32,
    pub slots_per_queue: u32,
    pub reserved: [u8; 52],
}

#[repr(C)]
pub struct UdpCapSharedQueue {
    pub producer: AtomicU64,
    pub captured: AtomicU64,
    pub overflow: AtomicU64,
    pub reserved: [u8; 40],
    pub consumer: AtomicU64,
    pub consumer_pad: [u8; 56],
}

const _: () = assert!(size_of::<UdpCapSharedHeader>() == 64);
const _: () = assert!(size_of::<UdpCapSharedQueue>() == 128);
const _: () = assert!(offset_of!(UdpCapSharedQueue, consumer) == 64);
const _: () = assert!(size_of::<UdpCapPacket>() == 2112);

// A private sentinel is zeroed in fork children while the shared ring is
// DONTFORK. Checking this memory avoids getpid()/syscalls on every read.
struct ForkGuard {
    #[cfg(unix)]
    address: NonNull<AtomicU32>,
    #[cfg(unix)]
    bytes: usize,
    #[cfg(not(unix))]
    value: AtomicU32,
}
impl ForkGuard {
    fn new() -> Result<Self, isize> {
        #[cfg(unix)]
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE);
            if page <= 0 {
                return Err(-22);
            }
            let bytes = page as usize;
            let p = libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(-12);
            }
            if libc::madvise(p, bytes, libc::MADV_WIPEONFORK) != 0
                || libc::madvise(p, bytes, libc::MADV_DONTDUMP) != 0
            {
                libc::munmap(p, bytes);
                return Err(-22);
            }
            let address = NonNull::new(p.cast::<AtomicU32>()).ok_or(-12isize)?;
            address.as_ptr().write(AtomicU32::new(1));
            Ok(Self { address, bytes })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                value: AtomicU32::new(1),
            })
        }
    }
    fn marker(&self) -> &AtomicU32 {
        #[cfg(unix)]
        {
            unsafe { self.address.as_ref() }
        }
        #[cfg(not(unix))]
        {
            &self.value
        }
    }
    fn owned(&self) -> bool {
        self.marker().load(Ordering::Relaxed) == 1
    }
}
impl Drop for ForkGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::munmap(self.address.as_ptr().cast(), self.bytes);
        }
    }
}

struct SharedMapping {
    address: NonNull<u8>,
    bytes: usize,
    guard: ForkGuard,
}
impl SharedMapping {
    fn new() -> Result<Self, isize> {
        let guard = ForkGuard::new()?;
        let bytes = UDP_CAP_SHARED_DEFAULT;
        #[cfg(unix)]
        let address = unsafe {
            let p = libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(-12);
            }
            if libc::madvise(p, bytes, libc::MADV_DONTFORK) != 0
                || libc::madvise(p, bytes, libc::MADV_DONTDUMP) != 0
            {
                libc::munmap(p, bytes);
                return Err(-22);
            }
            NonNull::new(p.cast()).ok_or(-12isize)?
        };
        // Host transport emulation only; the real syscall transport is ARM64.
        #[cfg(not(unix))]
        let address = unsafe {
            let layout = std::alloc::Layout::from_size_align(bytes, 4096).map_err(|_| -22isize)?;
            NonNull::new(std::alloc::alloc_zeroed(layout)).ok_or(-12isize)?
        };
        Ok(Self {
            address,
            bytes,
            guard,
        })
    }
    fn owned(&self) -> bool {
        self.guard.owned()
    }
    fn header(&self) -> *mut UdpCapSharedHeader {
        self.address.as_ptr().cast()
    }
}
impl Drop for SharedMapping {
    fn drop(&mut self) {
        // MADV_DONTFORK excludes this address from the child. Never access or
        // unmap it there (the address could already have been reused).
        if !self.owned() {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc::munmap(self.address.as_ptr().cast(), self.bytes);
        }
        #[cfg(not(unix))]
        unsafe {
            std::alloc::dealloc(
                self.address.as_ptr(),
                std::alloc::Layout::from_size_align(self.bytes, 4096).unwrap(),
            );
        }
    }
}

struct RingReader {
    queues: *mut UdpCapSharedQueue,
    packets: *mut UdpCapPacket,
    capacity: usize,
    tails: Vec<u64>,
    heads: Vec<u64>,
    sequence: u64,
}
impl RingReader {
    // Only used after successful INIT; kernel's release publishes all geometry.
    unsafe fn new(mapping: &SharedMapping) -> Result<Self, isize> {
        let h = mapping.header();
        if unsafe { (*h).state.load(Ordering::Acquire) } != UDP_CAP_ACTIVE {
            return Err(-108);
        }
        let count = unsafe { ptr::addr_of!((*h).queue_count).read() } as usize;
        let capacity = unsafe { ptr::addr_of!((*h).slots_per_queue).read() } as usize;
        if count == 0
            || !(2..=UDP_CAP_QUEUE_SLOTS_MAX).contains(&capacity)
            || !capacity.is_power_of_two()
        {
            return Err(-71);
        }
        let queue_bytes = count
            .checked_mul(size_of::<UdpCapSharedQueue>())
            .ok_or(-71isize)?;
        let packet_bytes = count
            .checked_mul(capacity)
            .and_then(|n| n.checked_mul(size_of::<UdpCapPacket>()))
            .ok_or(-71isize)?;
        let required = size_of::<UdpCapSharedHeader>()
            .checked_add(queue_bytes)
            .and_then(|n| n.checked_add(packet_bytes))
            .ok_or(-71isize)?;
        if required > mapping.bytes {
            return Err(-71);
        }
        let queues = unsafe {
            mapping
                .address
                .as_ptr()
                .add(size_of::<UdpCapSharedHeader>())
        }
        .cast();
        let packets = unsafe {
            mapping
                .address
                .as_ptr()
                .add(size_of::<UdpCapSharedHeader>() + queue_bytes)
        }
        .cast();
        Ok(Self {
            queues,
            packets,
            capacity,
            tails: vec![0; count],
            heads: vec![0; count],
            sequence: 0,
        })
    }

    unsafe fn read(&mut self, out: &mut [UdpCapPacket]) -> Result<UdpCapReadStats, isize> {
        if out.is_empty() {
            return Err(-22);
        }
        let mut result = UdpCapReadStats::default();
        // Bound this batch by a snapshot, preserving the old batch limit and
        // never chasing an indefinitely advancing producer.
        for i in 0..self.tails.len() {
            let q = unsafe { self.queues.add(i) };
            let head = unsafe { (*q).producer.load(Ordering::Acquire) };
            if head.wrapping_sub(self.tails[i]) > self.capacity as u64 {
                return Err(-71);
            }
            self.heads[i] = head;
            result.captured = result
                .captured
                .wrapping_add(unsafe { (*q).captured.load(Ordering::Relaxed) });
            result.overflow = result
                .overflow
                .wrapping_add(unsafe { (*q).overflow.load(Ordering::Relaxed) });
        }
        for target in out.iter_mut().take(UDP_CAP_BATCH_MAX) {
            let mut choice = None;
            for i in 0..self.tails.len() {
                if self.tails[i] == self.heads[i] {
                    continue;
                }
                let slot = i * self.capacity + (self.tails[i] as usize & (self.capacity - 1));
                let p = unsafe { self.packets.add(slot) };
                let ts = unsafe { ptr::addr_of!((*p).ts_ns).read() };
                let key = (ts, self.tails[i].wrapping_add(1), i);
                if choice.is_none_or(|(old, _)| key < old) {
                    choice = Some((key, p));
                }
            }
            let Some(((_, _, i), p)) = choice else {
                break;
            };
            let len = unsafe { ptr::addr_of!((*p).payload_len).read() } as usize;
            if len > UDP_CAP_MAX_PAYLOAD as usize {
                return Err(-71);
            }
            // Copy only the fixed metadata and valid payload. The caller must
            // use payload_len; output bytes beyond it retain their old values.
            unsafe {
                ptr::copy_nonoverlapping(
                    p.cast::<u8>(),
                    (target as *mut UdpCapPacket).cast::<u8>(),
                    offset_of!(UdpCapPacket, payload),
                );
                ptr::copy_nonoverlapping(
                    ptr::addr_of!((*p).payload).cast::<u8>(),
                    target.payload.as_mut_ptr(),
                    len,
                );
            }
            self.sequence = self.sequence.wrapping_add(1);
            if self.sequence == 0 {
                self.sequence = 1;
            }
            target.seq = self.sequence;
            self.tails[i] = self.tails[i].wrapping_add(1);
            // No reads of p occur after this release, including on failure.
            unsafe {
                (*self.queues.add(i))
                    .consumer
                    .store(self.tails[i], Ordering::Release);
            }
            result.count += 1;
        }
        Ok(result)
    }
}

pub struct UdpCaptureSession<T: KernelTransport> {
    driver: Arc<KernelDriver<T>>,
    mapping: SharedMapping,
    reader: RingReader,
    handle: u64,
    active: bool,
}
// Only &mut self can consume/stop; private pointers never escape. Moving the
// session between threads in the owning process does not move its mmap.
unsafe impl<T: KernelTransport> Send for UdpCaptureSession<T> {}

impl<T: KernelTransport> KernelDriver<T> {
    /// Load the bundled capture plugin. Target PID selects sockets; the calling
    /// mm owns the plugin and any mapping subsequently bound to its handle.
    pub fn UdpCapLoad(&self, target_pid: i32, min_payload: u16, max_payload: u16) -> Result<u64, isize> {
        if target_pid <= 0 || min_payload == 0 || min_payload > max_payload
            || u32::from(max_payload) > UDP_CAP_MAX_PAYLOAD {
            return Err(-22);
        }
        let mut config = [0u8; 4];
        config[..2].copy_from_slice(&min_payload.to_ne_bytes());
        config[2..].copy_from_slice(&max_payload.to_ne_bytes());
        match unsafe { self.Invoke(CMD_PLUGIN_LOAD, [CAPTURE_PLUGIN.as_ptr() as usize,
            CAPTURE_PLUGIN.len(), config.as_ptr() as usize, config.len(), target_pid as usize]) } {
            n if n > 0 => Ok(n as u64),
            n if n < 0 => Err(n),
            _ => Err(-71),
        }
    }

    /// Register a mapping in the caller that loaded this capture handle.
    ///
    /// # Safety
    /// address..address+bytes must be a dedicated page-aligned shared writable
    /// MAP_SHARED mapping, marked MADV_DONTFORK. Do not access it during START;
    /// thereafter use the ownership protocol. Retain it until STOP/UNLOAD completes.
    pub unsafe fn UdpCapBindRaw(
        &self,
        handle: u64,
        address: *mut u8,
        bytes: usize,
    ) -> isize {
        if handle == 0 || handle > isize::MAX as u64
            || address.is_null()
            || bytes == 0
            || bytes > UDP_CAP_SHARED_MAX
        {
            return -22;
        }
        unsafe {
            self.Invoke(
                CMD_PLUGIN_CONTROL,
                [
                    handle as usize,
                    CP_START,
                    address as usize,
                    bytes,
                    0,
                ],
            )
        }
    }

    /// Stop capture and unload its plugin. Use CP_STOP through raw CONTROL only
    /// when retaining a loaded handle for a subsequent bind is intentional.
    pub fn UdpCapStop(&self, handle: u64) -> Result<(), isize> {
        if handle == 0 || handle > isize::MAX as u64 {
            return Err(-22);
        }
        match unsafe { self.Invoke(CMD_PLUGIN_UNLOAD, [handle as usize, 0, 0, 0, 0]) } {
            0 => Ok(()),
            n if n < 0 => Err(n),
            _ => Err(-71),
        }
    }

    pub fn UdpCapStart(
        self: &Arc<Self>,
        target_pid: i32,
        min_payload: u16,
        max_payload: u16,
    ) -> Result<UdpCaptureSession<T>, isize> {
        let mapping = SharedMapping::new()?;
        let handle = self.UdpCapLoad(target_pid, min_payload, max_payload)?;
        let result = unsafe {
            self.UdpCapBindRaw(
                handle,
                mapping.address.as_ptr(),
                mapping.bytes,
            )
        };
        if result != 0 {
            let _ = self.UdpCapStop(handle);
            return Err(if result < 0 { result } else { -71 });
        }
        let reader = match unsafe { RingReader::new(&mapping) } {
            Ok(reader) => reader,
            Err(e) => {
                let _ = self.UdpCapStop(handle as u64);
                return Err(e);
            }
        };
        Ok(UdpCaptureSession {
            driver: Arc::clone(self),
            mapping,
            reader,
            handle: handle as u64,
            active: true,
        })
    }
}

impl<T: KernelTransport> UdpCaptureSession<T> {
    pub fn Read(&mut self, output: &mut [UdpCapPacket]) -> Result<UdpCapReadStats, isize> {
        if !self.mapping.owned() {
            return Err(-18);
        }
        if !self.active
            || unsafe { (*self.mapping.header()).state.load(Ordering::Acquire) } != UDP_CAP_ACTIVE
        {
            return Err(-108);
        }
        unsafe { self.reader.read(output) }
    }

    pub fn Stop(&mut self) -> Result<(), isize> {
        if !self.mapping.owned() {
            return Err(-18);
        }
        if !self.active {
            return Ok(());
        }
        let result = self.driver.UdpCapStop(self.handle);
        // Invalidating the ring releases pages, but a loaded plugin still owns
        // its slot. Never turn a failed unload into success using ring state.
        if result.is_ok() || result == Err(-116) {
            self.active = false;
            return Ok(());
        }
        result
    }
}
impl<T: KernelTransport> Drop for UdpCaptureSession<T> {
    fn drop(&mut self) {
        let _ = self.Stop();
        // Even if transport fails, munmap triggers notifier cleanup; the kernel
        // retains its pinned pages until every in-flight producer is drained.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct State {
        address: usize,
        next: u64,
        calls: Vec<usize>,
        bad_geometry: bool,
        stop_error: Option<isize>,
    }
    #[derive(Clone, Default)]
    struct Mock(Arc<Mutex<State>>);
    impl KernelTransport for Mock {
        unsafe fn Invoke(&self, _: i32, _: u64, command: usize, args: [usize; 5]) -> isize {
            let mut s = self.0.lock().unwrap();
            s.calls.push(command);
            match command {
                CMD_PLUGIN_LOAD => {
                    assert_eq!(args[3..], [4, 42]);
                    let config = unsafe { core::slice::from_raw_parts(args[2] as *const u8, 4) };
                    assert_eq!(config, [1, 0, 0, 8]);
                    s.next += 1;
                    s.next as isize
                },
                CMD_PLUGIN_CONTROL => unsafe {
                    assert_eq!(args[..2], [s.next as usize, CP_START]);
                    assert_eq!(&args[3..], &[UDP_CAP_SHARED_DEFAULT, 0]);
                    assert_eq!(args[2] % 4096, 0);
                    s.address = args[2];
                    let h = s.address as *mut UdpCapSharedHeader;
                    ptr::addr_of_mut!((*h).queue_count).write(if s.bad_geometry {
                        u32::MAX
                    } else {
                        4
                    });
                    ptr::addr_of_mut!((*h).slots_per_queue).write(8);
                    (*h).state.store(UDP_CAP_ACTIVE, Ordering::Release);
                    0
                },
                CMD_PLUGIN_UNLOAD => unsafe {
                    assert_eq!(args, [s.next as usize, 0, 0, 0, 0]);
                    if let Some(error) = s.stop_error { return error; }
                    (*(s.address as *mut UdpCapSharedHeader))
                        .state
                        .store(UDP_CAP_STOPPED, Ordering::Release);
                    0
                },
                _ => panic!("unexpected capture data-transfer command"),
            }
        }
    }
    fn start() -> (Mock, UdpCaptureSession<Mock>) {
        let mock = Mock::default();
        let session = Arc::new(KernelDriver::new(1, 2, 99, mock.clone()))
            .UdpCapStart(42, 1, 2048)
            .unwrap();
        (mock, session)
    }
    unsafe fn publish(address: usize, cpu: usize, ts: u64, length: usize, value: u8) -> bool {
        let h = address as *mut UdpCapSharedHeader;
        let q = unsafe { h.add(1) }.cast::<UdpCapSharedQueue>();
        let count = unsafe { (*h).queue_count } as usize;
        let capacity = unsafe { (*h).slots_per_queue } as usize;
        let queue = unsafe { q.add(cpu) };
        let head = unsafe { (*queue).producer.load(Ordering::Relaxed) };
        let tail = unsafe { (*queue).consumer.load(Ordering::Acquire) };
        if head.wrapping_sub(tail) == capacity as u64 {
            return false;
        }
        let packets = unsafe { q.add(count) }.cast::<UdpCapPacket>();
        let p = unsafe { packets.add(cpu * capacity + head as usize % capacity) };
        let mut packet = UdpCapPacket {
            ts_ns: ts,
            seq: head.wrapping_add(1),
            payload_len: length as u16,
            ..Default::default()
        };
        if length <= packet.payload.len() {
            packet.payload[..length].fill(value);
        }
        unsafe {
            p.write(packet);
            (*queue)
                .captured
                .store(head.wrapping_add(1), Ordering::Relaxed);
            (*queue)
                .producer
                .store(head.wrapping_add(1), Ordering::Release);
        }
        true
    }
    #[test]
    fn plugin_controls_merge_and_consume_without_transport_calls() {
        let (mock, mut session) = start();
        let address = mock.0.lock().unwrap().address;
        unsafe {
            assert!(publish(address, 0, 30, 6, 3));
            assert!(publish(address, 0, 50, 2, 5));
            assert!(publish(address, 1, 10, 4, 1));
            assert!(publish(address, 1, 40, 3, 4));
        }
        let mut packets = [UdpCapPacket::default(); 3];
        assert_eq!(
            session.Read(&mut packets).unwrap(),
            UdpCapReadStats {
                count: 3,
                captured: 4,
                overflow: 0
            }
        );
        assert_eq!(
            packets.map(|p| (p.seq, p.ts_ns)),
            [(1, 10), (2, 30), (3, 40)]
        );
        assert_eq!(session.Read(&mut packets).unwrap().count, 1);
        assert_eq!(
            (packets[0].seq, packets[0].ts_ns, packets[0].payload_len),
            (4, 50, 2)
        );
        let before = packets;
        assert_eq!(session.Read(&mut packets).unwrap().count, 0);
        assert_eq!(packets, before);
        assert_eq!(session.Read(&mut []), Err(-22));
        assert_eq!(mock.0.lock().unwrap().calls, [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL]);
        session.Stop().unwrap();
        assert_eq!(session.Read(&mut packets), Err(-108));
        drop(session);
        assert_eq!(
            mock.0.lock().unwrap().calls,
            [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL, CMD_PLUGIN_UNLOAD]
        );
    }
    #[test]
    fn detects_bad_geometry_and_releases_registration() {
        let mock = Mock::default();
        mock.0.lock().unwrap().bad_geometry = true;
        let driver = Arc::new(KernelDriver::new(1, 2, 3, mock.clone()));
        assert!(matches!(driver.UdpCapStart(42, 1, 2048), Err(-71)));
        assert_eq!(
            mock.0.lock().unwrap().calls,
            [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL, CMD_PLUGIN_UNLOAD]
        );
    }
    #[test]
    fn failed_bind_unloads_the_loaded_plugin() {
        #[derive(Clone)]
        struct Failure(Arc<Mutex<Vec<usize>>>);
        impl KernelTransport for Failure {
            unsafe fn Invoke(&self, _: i32, _: u64, command: usize, args: [usize; 5]) -> isize {
                self.0.lock().unwrap().push(command);
                match command {
                    CMD_PLUGIN_LOAD => 19,
                    CMD_PLUGIN_CONTROL => { assert_eq!(args[..2], [19, CP_START]); -14 },
                    CMD_PLUGIN_UNLOAD => { assert_eq!(args, [19, 0, 0, 0, 0]); 0 },
                    _ => panic!("unexpected command"),
                }
            }
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = Arc::new(KernelDriver::new(1, 2, 3, Failure(calls.clone())));
        assert!(matches!(driver.UdpCapStart(42, 1, 2048), Err(-14)));
        assert_eq!(*calls.lock().unwrap(), [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL, CMD_PLUGIN_UNLOAD]);
    }
    #[test]
    fn invalid_ring_still_requires_plugin_unload() {
        let (mock, mut session) = start();
        unsafe { (*session.mapping.header()).state.store(UDP_CAP_INVALID, Ordering::Release); }
        mock.0.lock().unwrap().stop_error = Some(-16);
        assert_eq!(session.Stop(), Err(-16));
        mock.0.lock().unwrap().stop_error = None;
        assert_eq!(session.Stop(), Ok(()));
        drop(session);
        assert_eq!(mock.0.lock().unwrap().calls,
            [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL, CMD_PLUGIN_UNLOAD, CMD_PLUGIN_UNLOAD]);
    }
    #[test]
    fn rejects_bad_producer_and_payload_without_acknowledging() {
        let (mock, mut session) = start();
        let address = mock.0.lock().unwrap().address;
        let q = session.reader.queues;
        unsafe {
            (*q).producer.store(9, Ordering::Release);
        }
        assert_eq!(session.Read(&mut [UdpCapPacket::default()]), Err(-71));
        unsafe {
            assert_eq!((*q).consumer.load(Ordering::Acquire), 0);
            (*q).producer.store(0, Ordering::Release);
            assert!(publish(address, 0, 1, 2049, 0));
        }
        assert_eq!(session.Read(&mut [UdpCapPacket::default()]), Err(-71));
        unsafe {
            assert_eq!((*q).consumer.load(Ordering::Acquire), 0);
        }
    }
    #[test]
    fn ring_wrap_and_full_slots_preserve_unconsumed_data() {
        let (mock, mut session) = start();
        let address = mock.0.lock().unwrap().address;
        for round in 0..64u64 {
            for n in 0..8 {
                unsafe {
                    assert!(publish(address, 2, round * 8 + n, n as usize + 1, n as u8));
                }
            }
            unsafe {
                assert!(!publish(address, 2, 999, 1, 99));
            }
            let mut packets = [UdpCapPacket::default(); 8];
            assert_eq!(session.Read(&mut packets).unwrap().count, 8);
            for (n, p) in packets.iter().enumerate() {
                assert_eq!(p.ts_ns, round * 8 + n as u64);
                assert!(p.payload[..n + 1].iter().all(|b| *b == n as u8));
            }
        }
    }
    #[test]
    fn counter_wrap_is_valid_for_power_of_two_capacity() {
        let (mock, mut session) = start();
        let address = mock.0.lock().unwrap().address;
        session.reader.tails[0] = u64::MAX - 1;
        unsafe {
            (*session.reader.queues)
                .producer
                .store(u64::MAX - 1, Ordering::Release);
            (*session.reader.queues)
                .consumer
                .store(u64::MAX - 1, Ordering::Release);
            assert!(publish(address, 0, 1, 2, 3));
            assert!(publish(address, 0, 2, 2, 4));
            assert!(publish(address, 0, 3, 2, 5));
        }
        let mut out = [UdpCapPacket::default(); 3];
        assert_eq!(session.Read(&mut out).unwrap().count, 3);
        assert_eq!(out.map(|p| p.payload[0]), [3, 4, 5]);
        unsafe {
            assert_eq!((*session.reader.queues).consumer.load(Ordering::Acquire), 1);
        }
    }
    #[test]
    fn child_cannot_access_or_stop_parents_dontfork_mapping() {
        let (mock, mut session) = start();
        session.mapping.guard.marker().store(0, Ordering::Relaxed);
        assert_eq!(session.Read(&mut [UdpCapPacket::default()]), Err(-18));
        assert_eq!(session.Stop(), Err(-18));
        assert_eq!(mock.0.lock().unwrap().calls, [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL]);
        session.mapping.guard.marker().store(1, Ordering::Relaxed);
    }
    #[test]
    fn concurrent_four_producers_publish_complete_records() {
        const EACH: u64 = 25_000;
        let (mock, mut session) = start();
        let address = mock.0.lock().unwrap().address;
        let threads: Vec<_> = (0..4)
            .map(|cpu| {
                std::thread::spawn(move || {
                    for n in 0..EACH {
                        while !unsafe {
                            publish(address, cpu, n * 4 + cpu as u64, 257, cpu as u8 + 1)
                        } {
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        let mut seen = [0u64; 4];
        let mut out = [UdpCapPacket::default(); UDP_CAP_BATCH_MAX];
        let mut count = 0;
        while count < EACH * 4 {
            let result = session.Read(&mut out).unwrap();
            if result.count == 0 {
                std::thread::yield_now();
            }
            for p in out.iter().take(result.count as usize) {
                let cpu = p.payload[0] as usize - 1;
                assert!(cpu < 4);
                assert_eq!(p.ts_ns, seen[cpu] * 4 + cpu as u64);
                assert_eq!(p.payload_len, 257);
                assert!(p.payload[..257].iter().all(|b| *b == cpu as u8 + 1));
                seen[cpu] += 1;
                count += 1;
                assert_eq!(p.seq, count);
            }
        }
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(seen, [EACH; 4]);
        assert_eq!(mock.0.lock().unwrap().calls, [CMD_PLUGIN_LOAD, CMD_PLUGIN_CONTROL]);
    }
}
