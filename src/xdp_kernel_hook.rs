include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub(crate) use ndas_kernel_ffi::MAX_PACKET_SIZE;

use crate::cli_config::CLIConfig;
use crate::sysstat_helper::SysInfo;
use chrono::Utc;
use crossbeam_queue::ArrayQueue;
pub use ndas_kernel_ffi::{
    perfevent_cleanup, perfevent_configure, perfevent_loop_tick, perfevent_set_promiscuous_mode, PerfEventLoopConfig,
};
use pcap_file::pcap::PacketHeader;
use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{spawn as spawn_thread, JoinHandle};

static mut DUMP_EVENT_QUEUE0: Option<Arc<ArrayQueue<(PacketHeader, Vec<u8>)>>> = None;
static mut MISSED_EVENT_QUEUE0: Option<Arc<ArrayQueue<u64>>> = None;

unsafe extern "C" fn on_event_received(event: *mut c_void, event_length: i32) -> i32 {
    let event_length = event_length as u32;
    let event_length_usize = event_length as usize;
    let current_time = Utc::now();
    let ct_second = current_time.timestamp();
    let ct_nanosecond = current_time.timestamp_subsec_nanos();
    let packet_header = PacketHeader::new(ct_second as u32, ct_nanosecond, event_length, event_length);
    let mut raw_sample = vec![0u8; event_length_usize];
    let raw_sample_ptr = raw_sample.as_mut_ptr();
    std::ptr::copy_nonoverlapping(event, raw_sample_ptr as *mut c_void, event_length_usize);
    let _ = DUMP_EVENT_QUEUE0.as_ref().unwrap().push((packet_header, raw_sample));

    -2
}

unsafe extern "C" fn on_event_missed(missed_count: u64) {
    let _ = MISSED_EVENT_QUEUE0.as_ref().unwrap().push(missed_count);
}

fn init_queue(queue_count: usize) {
    unsafe {
        MISSED_EVENT_QUEUE0 = Some(Arc::new(ArrayQueue::new(queue_count)));
        DUMP_EVENT_QUEUE0 = Some(Arc::new(ArrayQueue::new(queue_count)));
    }
}

fn configure_perfevent(perfevent_config: PerfEventLoopConfig) -> u8 {
    let cpu_count = 0;
    let cpu_count = Box::new(cpu_count);
    let cpu_count = Box::into_raw(cpu_count);
    let perfevent_config = Box::new(perfevent_config);
    let perfevent_config_raw = Box::into_raw(perfevent_config);

    unsafe {
        perfevent_configure(perfevent_config_raw, cpu_count);
    }

    unsafe { *cpu_count }
}

fn set_promiscuous_mode(enable: u8) {
    unsafe {
        perfevent_set_promiscuous_mode(enable);
    }
}

pub(crate) fn start_perfevent_loop(
    stop_flag: &Arc<AtomicBool>,
    config: &CLIConfig,
    sys_info: &SysInfo,
) -> (
    Vec<JoinHandle<()>>,
    Arc<ArrayQueue<(PacketHeader, Vec<u8>)>>,
    Arc<ArrayQueue<u64>>,
) {
    let use_promiscuous_mode = config.promiscuous_mode;
    let max_queue_count = sys_info.get_total_memory() as usize / MAX_PACKET_SIZE as usize;
    init_queue(max_queue_count);
    let c_interface_name = CString::new(config.interface_name.clone()).unwrap();
    let perfevent_config = PerfEventLoopConfig {
        on_event_received: Some(on_event_received),
        on_event_missed: Some(on_event_missed),
        interface_name: c_interface_name.as_ptr(),
    };
    let permitted_cpu_count = configure_perfevent(perfevent_config);

    if use_promiscuous_mode {
        set_promiscuous_mode(1);
    }

    let mut perfevent_loop_handles = Vec::new();

    for i in 0..permitted_cpu_count {
        let stop_flag_clone = stop_flag.clone();
        perfevent_loop_handles.push(spawn_thread(move || {
            let cpu_id = i;
            let mut raw_buffer_length = 0u64;
            let mut raw_buffer = std::ptr::null_mut::<std::ffi::c_void>();

            while !stop_flag_clone.load(Ordering::Relaxed) {
                unsafe {
                    perfevent_loop_tick(cpu_id, &mut raw_buffer, &mut raw_buffer_length);
                }
            }

            if cpu_id == 0 && use_promiscuous_mode {
                set_promiscuous_mode(0);
            }

            std::mem::drop(raw_buffer);
        }));
    }

    unsafe {
        (
            perfevent_loop_handles,
            DUMP_EVENT_QUEUE0.as_ref().unwrap().clone(),
            MISSED_EVENT_QUEUE0.as_ref().unwrap().clone(),
        )
    }
}
