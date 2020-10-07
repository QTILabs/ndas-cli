#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use crossbeam_channel::{unbounded as create_unbounded_channel, Receiver, Sender};
use lazy_static::lazy_static;
use signal_hook::iterator::Signals;
use signal_hook::{SIGINT, SIGTERM, SIGUSR1};
use std::error::Error;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

lazy_static! {
    static ref MISSED_EVENT_CHANNEL: (Sender<u64>, Receiver<u64>) = create_unbounded_channel();
    static ref DUMP_EVENT_CHANNEL: (Sender<PacketSample>, Receiver<PacketSample>) = create_unbounded_channel();
}

unsafe extern "C" fn on_event_received(event: *mut c_void, _event_length: i32) -> i32 {
    let packet = *(event as *const PacketSample);
    let _ = DUMP_EVENT_CHANNEL.0.try_send(packet);
    0
}

unsafe extern "C" fn on_event_missed(missed_count: u64) {
    let _ = MISSED_EVENT_CHANNEL.0.try_send(missed_count);
}

fn main() -> Result<(), Box<dyn Error>> {
    let stop_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let stop_flag0 = stop_flag.clone();
    //let stop_flag1 = stop_flag.clone();
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGUSR1])?;
    let mut missed_counter = 0u64;

    let _ = thread::spawn(move || {
        for _ in signals.forever() {
            stop_flag0.store(true, Ordering::Relaxed);
            break;
        }
    });

    let c_str = CString::new("eth0").unwrap();

    unsafe {
        perfevent_loop_start(
            c_str.as_ptr() as *const c_char,
            Some(on_event_received),
            Some(on_event_missed),
        );
    }

    while !stop_flag.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(1000));

        while let Ok(new_missed_counter) = MISSED_EVENT_CHANNEL.1.try_recv() {
            missed_counter += new_missed_counter;
        }

        println!("MISSED EVENTS => {}", missed_counter);
    }

    Ok(())
}
