#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod cli_selections;

use chrono::Utc;
use cli_selections::{get_duration, get_file_clipping, get_interface_selection, get_promiscuous_mode};
use crossbeam_queue::SegQueue;
use signal_hook::iterator::Signals;
use signal_hook::{SIGINT, SIGTERM, SIGUSR1};
use std::boxed::Box;
use std::error::Error;
use std::ffi::{c_void, CString};
use std::fs::File;
use std::io::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use systemstat::{Platform, System};

const DATA_ROOT: &str = "/opt/dump";

static mut MISSED_EVENT_QUEUE0: Option<SegQueue<u64>> = None;
static mut DUMP_EVENT_QUEUE0: Option<SegQueue<Vec<u8>>> = None;

unsafe extern "C" fn on_event_received(event: *mut c_void, event_length: i32) -> i32 {
    let mut raw_sample = Vec::new();
    let event_length = event_length as isize;

    for i in 0..event_length {
        raw_sample.push(event.offset(i) as u8);
    }

    DUMP_EVENT_QUEUE0.as_ref().unwrap().push(raw_sample);
    -2
}

unsafe extern "C" fn on_event_missed(missed_count: u64) {
    MISSED_EVENT_QUEUE0.as_ref().unwrap().push(missed_count);
}

fn get_missed_event() -> Option<u64> {
    unsafe { MISSED_EVENT_QUEUE0.as_ref().unwrap().pop().ok() }
}

fn get_dump_event() -> Option<Vec<u8>> {
    unsafe { DUMP_EVENT_QUEUE0.as_ref().unwrap().pop().ok() }
}

fn init_queue() {
    unsafe {
        MISSED_EVENT_QUEUE0 = Some(SegQueue::new());
        DUMP_EVENT_QUEUE0 = Some(SegQueue::new());
    }
}

fn configure_perfevent(perfevent_config: PerfEventLoopConfig) -> u8 {
    let cpu_count = 0;
    let cpu_count = Box::new(cpu_count);
    let cpu_count = Box::into_raw(cpu_count);
    let perfevent_config = Box::new(perfevent_config);
    let perfevent_config = Box::into_raw(perfevent_config);

    unsafe {
        perfevent_configure(perfevent_config, cpu_count);
    }

    unsafe { *cpu_count }
}

fn set_promiscuous_mode(enable: u8) {
    unsafe {
        perfevent_set_promiscuous_mode(enable);
    }
}

fn get_disk_usage(sys: &System) -> u8 {
    let mut avail = 0;
    let mut total = 0;

    match sys.mounts() {
        Ok(mounts) => {
            for mount in mounts.iter() {
                if mount.fs_mounted_on == DATA_ROOT {
                    avail = mount.avail.as_u64();
                    total = mount.total.as_u64();
                    break;
                }
            }
        }
        Err(_) => (),
    }

    if total == 0 {
        0
    } else {
        ((avail as f32 / total as f32) * 100f32) as u8
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let sys = System::new();
    let selected_interface = get_interface_selection()?;
    let selected_clipping = get_file_clipping()?;
    let selected_duration = get_duration()?;
    let use_promiscuous = get_promiscuous_mode()?;

    init_queue();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGUSR1])?;

    let stop_flag_clone = stop_flag.clone();
    let _ = thread::spawn(move || {
        for _ in signals.forever() {
            stop_flag_clone.store(true, Ordering::Relaxed);
            break;
        }
    });

    let c_str = CString::new(selected_interface.clone()).unwrap();
    let perfevent_config = PerfEventLoopConfig {
        on_event_received: Some(on_event_received),
        on_event_missed: Some(on_event_missed),
        interface_name: c_str.as_ptr(),
    };
    let permitted_cpu_count = configure_perfevent(perfevent_config);

    if use_promiscuous {
        set_promiscuous_mode(1);
    }

    let mut perfevent_loop_handles = Vec::new();

    for i in 0..permitted_cpu_count {
        let stop_flag_clone = stop_flag.clone();
        perfevent_loop_handles.push(thread::spawn(move || {
            while !stop_flag_clone.load(Ordering::Relaxed) {
                unsafe {
                    perfevent_loop_tick(i);
                }
            }
        }));
    }

    let mut missed_counter = 0u64;
    let mut total_counter = 0u64;
    let mut temp_bytes = 0u64;
    let mut last_drop_count = 0u64;
    let mut temp_buffer = Vec::new();
    let mut current_filename = format!(
        "{}/{}-{}.pcap-raw",
        DATA_ROOT,
        selected_interface.clone(),
        Utc::now().timestamp_nanos()
    );
    let start_instant = Instant::now();

    while !stop_flag.load(Ordering::Relaxed) && start_instant.elapsed() < selected_duration {
        while let Some(new_missed_counter) = get_missed_event() {
            missed_counter += new_missed_counter;
            last_drop_count += new_missed_counter;
        }

        while let Some(new_packet) = get_dump_event() {
            total_counter += 1;
            temp_bytes += new_packet.len() as u64;
            temp_buffer.push(new_packet);

            if temp_bytes >= selected_clipping {
                let pending_save_packets: Vec<Vec<u8>> = temp_buffer.drain(..).collect();
                temp_buffer = Vec::new();
                let pending_save_count = pending_save_packets.len();

                let mut file_buffer = File::create(current_filename)?;

                for packet in pending_save_packets {
                    file_buffer.write(&packet[..])?;
                }

                current_filename = format!(
                    "{}/{}-{}.pcap-raw",
                    DATA_ROOT,
                    selected_interface.clone(),
                    Utc::now().timestamp_nanos()
                );
                let current_time = Utc::now().to_rfc3339();
                println!(
                    "[{}] => LLoss {} | LCap {} || TLost {} | TCap {} || Disk: {}%",
                    current_time,
                    last_drop_count,
                    pending_save_count,
                    missed_counter,
                    total_counter,
                    get_disk_usage(&sys),
                );
                last_drop_count = 0;
                temp_bytes = 0;
                break;
            }
        }
    }

    for loop_handle in perfevent_loop_handles {
        let _ = loop_handle.join();
    }

    if use_promiscuous {
        set_promiscuous_mode(0);
    }

    Ok(())
}
