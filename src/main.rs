#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use chrono::Utc;
use crossbeam_queue::SegQueue;
use signal_hook::iterator::Signals;
use signal_hook::{SIGINT, SIGTERM, SIGUSR1};
use std::error::Error;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const FILE_SIZE_LIMIT: u64 = 16 * 1024 * 1024;
//const INTERFACE_NAME: &str = "enp8s0f1np1";
const INTERFACE_NAME: &str = "eth0";

static mut MISSED_EVENT_QUEUE0: Option<SegQueue<u64>> = None;
static mut DUMP_EVENT_QUEUE0: Option<SegQueue<PacketSample>> = None;

unsafe extern "C" fn on_event_received(event: *mut c_void, _event_length: i32) -> i32 {
    let packet = (*(event as *const PacketSample)).clone();
    DUMP_EVENT_QUEUE0.as_ref().unwrap().push(packet);
    -2
}

unsafe extern "C" fn on_event_missed(missed_count: u64) {
    MISSED_EVENT_QUEUE0.as_ref().unwrap().push(missed_count);
}

fn get_missed_event() -> Option<u64> {
    unsafe { MISSED_EVENT_QUEUE0.as_ref().unwrap().pop().ok() }
}

fn get_dump_event() -> Option<PacketSample> {
    unsafe { DUMP_EVENT_QUEUE0.as_ref().unwrap().pop().ok() }
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        MISSED_EVENT_QUEUE0 = Some(SegQueue::new());
        DUMP_EVENT_QUEUE0 = Some(SegQueue::new());
    }

    let stop_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let stop_flag0 = stop_flag.clone();
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGUSR1])?;

    let _ = thread::spawn(move || {
        for _ in signals.forever() {
            stop_flag0.store(true, Ordering::Relaxed);
            break;
        }
    });

    let c_str = CString::new(INTERFACE_NAME).unwrap();

    unsafe {
        perfevent_loop_start(c_str.as_ptr() as *const i8, Some(on_event_received), Some(on_event_missed));
    }

    let mut missed_counter = 0u64;
    let mut total_counter = 0u64;
    let mut temp_bytes = 0u64;
    let mut last_drop_count = 0u64;
    let mut temp_buffer = Vec::new();
    let mut current_filename = format!("{}-{}.pcapng", INTERFACE_NAME, Utc::now().timestamp_nanos());

    while !stop_flag.load(Ordering::Relaxed) {
        while let Some(new_missed_counter) = get_missed_event() {
            missed_counter += new_missed_counter;
            last_drop_count += new_missed_counter;
        }

        while let Some(new_packet) = get_dump_event() {
            total_counter += 1;
            temp_bytes += new_packet.length as u64;
            temp_buffer.push(new_packet);

            if temp_bytes >= FILE_SIZE_LIMIT {
                let pending_save_packets: Vec<PacketSample> = temp_buffer.drain(..).collect();
                temp_buffer = Vec::new();
                let pending_save_count = pending_save_packets.len();

                unsafe {
                    helper_pcapng_save(
                        CString::new(current_filename.clone()).unwrap().as_ptr() as *const i8,
                        c_str.as_ptr() as *const c_char,
                        last_drop_count,
                        Utc::now().timestamp_nanos(),
                        temp_buffer.as_mut_ptr(),
                        pending_save_count as u64,
                    );
                }

                current_filename = format!("{}-{}.pcapng", INTERFACE_NAME, Utc::now().timestamp_nanos());
                let current_time = Utc::now().to_rfc3339();
                println!(
                    "[{}] => Last Loss {} | Last Saved {} | Total Lost {} | Total Saved {}",
                    current_time, last_drop_count, pending_save_count, missed_counter, total_counter,
                );
                last_drop_count = 0;
                temp_bytes = 0;
                break;
            }
        }
    }

    Ok(())
}
