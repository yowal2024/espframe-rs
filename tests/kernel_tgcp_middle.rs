use espframe::kernel::abi::*;
use espframe::kernel::tcp_plugin::*;
use espframe::kernel::{KernelDriver, KernelTransport};
use std::mem::{align_of, offset_of, size_of};

struct Transport<F>(F);
impl<F: Fn(usize, [usize; 5]) -> isize + Send + Sync> KernelTransport for Transport<F> {
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        assert_eq!((scno, option), (123, 456));
        (self.0)(command, args)
    }
}
fn ready() -> TcpPluginEvent {
    let mut r = TcpPluginEvent::default();
    r.seq = 1; r.session_id = 7; r.socket_id = 81; r.ts_ns = 1000;
    r.target_pid = 42; r.sock_uid = 12345; r.family = 2;
    r.event_type = TP_EVENT_METADATA; r.local_port = 34123; r.remote_port = 18081;
    r.local_addr[10..12].fill(255); r.remote_addr[10..12].fill(255);
    r.local_addr[12..].copy_from_slice(&[10,24,0,1]); r.remote_addr[12..].copy_from_slice(&[10,24,0,2]);
    r.payload[..16].fill(0x11); r.payload[16..20].copy_from_slice(&3u32.to_ne_bytes());
    r.payload_len = 20; r
}
#[test]
fn wire_layout_and_compacted_commands_match_c() {
    assert_eq!(size_of::<TcpPluginEvent>(), 4200);
    assert_eq!(align_of::<TcpPluginEvent>(), 8);
    assert_eq!(offset_of!(TcpPluginEvent, payload), 104);
    assert_eq!(offset_of!(TcpPluginEvent, stream_offset), 88);
    assert_eq!(size_of::<TcpPluginReadInfo>(), 16);
    assert_eq!(size_of::<TgcpMiddleStats>(), 56);
    assert_eq!(size_of::<TgcpMiddleEvent>(), 4216); // typed client view, not wire ABI
    assert_eq!(CMD_PLUGIN_LOAD, CMD_GYRO_EVENT_CONFIGURE + 1);
    assert_eq!(CMD_PLUGIN_CONTROL, CMD_PLUGIN_LOAD + 1);
    assert_eq!(CMD_PLUGIN_UNLOAD, CMD_PLUGIN_CONTROL + 1);
}
#[test]
fn load_uses_shared_command_and_complete_config_without_target_pid() {
    let image = [1,2,3,4];
    let driver = KernelDriver::new(123,456,0,Transport(|cmd,a:[usize;5]| {
        assert_eq!(cmd,CMD_PLUGIN_LOAD); assert_eq!((a[1],a[3],a[4]),(4,72,0));
        let data = unsafe { std::slice::from_raw_parts(a[2] as *const u8,72) };
        assert_eq!(&data[..4],&1u32.to_ne_bytes());
        assert_eq!(&data[4..8],&5u32.to_ne_bytes());
        assert_eq!(data[8],23); assert!(data[9..].iter().all(|v| *v==0)); 7
    }));
    assert_eq!(unsafe {driver.TgcpPluginLoad(&image,&[23],5)},Ok(7));
}
#[test]
fn invalid_dh_encoding_is_rejected_before_transport() {
    let driver = KernelDriver::new(123,456,0,Transport(|_,_|panic!("invalid configuration")));
    for (prime,g) in [(vec![],5),(vec![23;65],5),(vec![0],5),(vec![0,23],5),
        (vec![22],5),(vec![3],2),(vec![23],0),(vec![23],1),(vec![23],22),(vec![23],23)] {
        assert_eq!(unsafe {driver.TgcpPluginLoad(&[1],&prime,g)},Err(-22));
    }
}
#[test]
fn dh_range_boundaries_do_not_claim_primality() {
    let driver = KernelDriver::new(123,456,0,Transport(|cmd,_|{assert_eq!(cmd,CMD_PLUGIN_LOAD);7}));
    for (prime,g,valid) in [(vec![5],2,true),(vec![5],3,true),(vec![5],4,false),
        (vec![9],2,true),(vec![255;4],u32::MAX-2,true),(vec![255;4],u32::MAX-1,false),
        (vec![1,0,0,0,0],u32::MAX,false),(vec![1,0,0,0,1],u32::MAX,true)] {
        assert_eq!(unsafe {driver.TgcpPluginLoad(&[1],&prime,g)},if valid {Ok(7)} else {Err(-22)});
    }
}
#[test]
fn reverse_expansion_preserves_full_batches_without_allocating_per_read() {
    for count in [1,2,16] {
        let driver=KernelDriver::new(123,456,42,Transport(move |cmd,a:[usize;5]|{
            assert_eq!(cmd,CMD_PLUGIN_CONTROL); assert_eq!((a[0],a[1],a[3]),(7,TP_READ,16));
            let out=unsafe {std::slice::from_raw_parts_mut(a[2] as *mut TcpPluginEvent,count)};
            for (i,r) in out.iter_mut().enumerate() {
                *r=ready();r.seq=(i+1) as u64;
                if i!=0 {r.event_type=TP_EVENT_DATA;r.payload.fill(0);r.payload_len=4096;
                    r.payload.fill(i as u8);r.stream_offset=(i-1) as u64*4096;r.flags=2|u32::from(i==1);}
            }
            unsafe {*(a[4] as *mut TcpPluginReadInfo)=TcpPluginReadInfo{dropped:4,session_id:7};} count as isize
        }));
        let mut out=vec![TgcpMiddleEvent::default();18];
        let info=driver.TgcpMiddleRead(7,&mut out).unwrap();
        assert_eq!((info.count,info.session_id,info.dropped),(count as u32,7,4));
        assert_eq!(out[0].kc,[0x11;16]);assert_eq!(out[0].key_mode,3);
        for (i,r) in out.iter().enumerate().take(count).skip(1) {assert_eq!(r.payload,[i as u8;4096]);assert_eq!(r.kc,[0;16]);}
        for r in out.iter().skip(count) {assert_eq!(r.seq,0);assert_eq!(r.payload,[0;4096]);}
    }
}
#[test]
fn malformed_records_wipe_the_entire_caller_buffer() {
    for variant in 0..17 {
        let driver=KernelDriver::new(123,456,42,Transport(move |_,a:[usize;5]|{
            let out=unsafe {&mut *(a[2] as *mut TcpPluginEvent)};*out=ready();
            let info=unsafe {&mut *(a[4] as *mut TcpPluginReadInfo)};info.session_id=7;
            match variant {
                0=>return 17,1=>info.session_id=0,2=>out.session_id=8,3=>out.socket_id=0,
                4=>out.event_type=99,5=>out.payload[16..20].copy_from_slice(&1u32.to_ne_bytes()),
                6=>out.family=10,7=>out.remote_addr[10]=0,8=>out.payload_len=4097,
                9=>out.reserved=1,10=>{out.event_type=TP_EVENT_DATA;out.stream_offset=u64::MAX;},
                11=>out.seq=0,12=>out.sock_uid=0,13=>out.sock_uid=32768,
                14=>out.payload_len=19,15=>out.payload[100]=1,_=>return -14,
            } 1
        }));
        let mut out=vec![TgcpMiddleEvent::default();16];out[15].kc.fill(0xaa);
        assert_eq!(driver.TgcpMiddleRead(7,&mut out).unwrap_err(),if variant==16 {-14} else {-71},"variant={variant}");
        assert!(out.iter().all(|r|r.kc==[0;16] && r.payload==[0;4096] && r.key_mode==0));
    }
}
#[test]
fn stats_and_stop_are_handle_scoped() {
    let driver=KernelDriver::new(123,456,0,Transport(|cmd,a:[usize;5]|{
        assert_eq!(cmd,CMD_PLUGIN_CONTROL);assert_eq!(a[0],7);
        match a[1] {
            TP_STATS=>{assert_eq!((a[3],a[4]),(56,0));let s=unsafe {&mut *(a[2] as *mut TgcpMiddleStats)};s.session_id=7;s.status=1;},
            TP_STOP=>assert_eq!(&a[2..],&[0;3]),
            _=>panic!("wrong operation"),
        } 0
    }));
    assert_eq!(driver.TgcpMiddleStats(7).unwrap().session_id,7);
    assert_eq!(driver.TcpPluginStats(7).unwrap().session_id,7);
    assert_eq!(driver.TgcpMiddleStop(7),Ok(()));
    assert_eq!(driver.TgcpMiddleStats(0),Err(-22));
}
#[test]
fn configure_returns_new_handle_and_errors_propagate() {
    let driver=KernelDriver::new(123,456,42,Transport(|cmd,a:[usize;5]|{
        assert_eq!(cmd,CMD_PLUGIN_CONTROL);assert_eq!((a[0],a[1],a[3],a[4]),(7,TP_CONFIG,72,0));9
    }));
    assert_eq!(driver.TgcpPluginConfigure(7,&[23],5),Ok(9));
    let driver=KernelDriver::new(123,456,42,Transport(|_,_|-116));
    assert_eq!(driver.TgcpMiddleStop(7),Err(-116));
    assert_eq!(driver.TgcpMiddleStats(7),Err(-116));
    assert_eq!(driver.TgcpMiddleRead(7,&mut [TgcpMiddleEvent::default()]).unwrap_err(),-116);
}
#[test]
fn invalid_stats_rejected() {
    for (status,session,padding) in [(2,7,0),(4,7,0),(1,0,0),(3,7,0),(1,7,1),(0,8,0)] {
        let driver=KernelDriver::new(123,456,42,Transport(move |_,a:[usize;5]|{
            let s=unsafe {&mut *(a[2] as *mut TgcpMiddleStats)};
            s.status=status;s.session_id=session;s.padding=padding;0
        }));
        assert_eq!(driver.TgcpMiddleStats(7),Err(-71));
    }
}

#[test]
fn generic_read_preserves_plugin_metadata_and_rejects_bad_generation() {
    for stale in [false, true] {
        let driver = KernelDriver::new(123, 456, 0, Transport(move |cmd, a: [usize; 5]| {
            assert_eq!(cmd, CMD_PLUGIN_CONTROL);
            assert_eq!((a[0], a[1], a[3]), (7, TP_READ, 1));
            let record = unsafe { &mut *(a[2] as *mut TcpPluginEvent) };
            *record = ready();
            record.payload.fill(0);
            record.payload[..3].copy_from_slice(b"abc");
            record.payload_len = 3;
            unsafe { *(a[4] as *mut TcpPluginReadInfo) = TcpPluginReadInfo {
                dropped: 5, session_id: if stale { 8 } else { 7 },
            }; }
            1
        }));
        let mut records = [TcpPluginEvent::default()];
        let result = driver.TcpPluginRead(7, &mut records);
        if stale {
            assert_eq!(result.unwrap_err(), -71);
            assert_eq!(records[0].seq, 0);
            assert_eq!(records[0].payload, [0; TP_MAX_PAYLOAD]);
        } else {
            let (count, info) = result.unwrap();
            assert_eq!((count, info.dropped), (1, 5));
            assert_eq!(&records[0].payload[..3], b"abc");
        }
    }
}

#[test]
fn generic_controls_reject_invalid_inputs_and_positive_status() {
    let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| panic!("invalid input reached transport")));
    assert_eq!(driver.TcpPluginConfigure(0, &[]), Err(-22));
    assert_eq!(driver.TcpPluginConfigure(7, &vec![0; TP_MAX_CONFIG + 1]), Err(-22));
    assert_eq!(driver.TcpPluginStop(0), Err(-22));
    assert_eq!(driver.TcpPluginStats(0), Err(-22));
    assert_eq!(driver.TcpPluginRead(0, &mut [TcpPluginEvent::default()]).unwrap_err(), -22);
    let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| 1));
    assert_eq!(driver.TcpPluginStats(7), Err(-71));
    assert_eq!(driver.TcpPluginStop(7), Err(-71));
}
