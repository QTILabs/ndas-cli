#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use signal_hook::iterator::Signals;
use signal_hook::{SIGINT, SIGTERM, SIGUSR1};
use std::error::Error;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

unsafe extern "C" fn on_event_received(_event: *mut c_void, _event_length: i32) -> i32 {
    println!("Got event!");
    0
}

unsafe extern "C" fn on_event_missed(missed_count: u64) {
    println!("Missed {} events!", missed_count);
}

fn main() -> Result<(), Box<dyn Error>> {
    let stop_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGUSR1])?;

    let _ = thread::spawn(move || {
        for _ in signals.forever() {
            stop_flag_clone.store(true, Ordering::Relaxed);
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
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
