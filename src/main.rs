#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub(crate) mod cli_config;
pub(crate) mod event_flusher;
pub(crate) mod sysstat_helper;
pub(crate) mod xdp_kernel_hook;

use cli_config::CLIConfig;
use event_flusher::start_event_flusher;
use signal_hook::iterator::Signals;
use signal_hook::{SIGINT, SIGTERM, SIGUSR1};
use std::boxed::Box;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use sysstat_helper::SysInfo;
use xdp_kernel_hook::start_perfevent_loop;

fn main() -> Result<(), Box<dyn Error>> {
    let sysstat = SysInfo::default();
    let config = CLIConfig::new()?;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGUSR1])?;
    let stop_flag_clone = stop_flag.clone();
    let _ = thread::spawn(move || {
        for _ in signals.forever() {
            stop_flag_clone.store(true, Ordering::Relaxed);
            break;
        }
    });
    let (perfevent_loop_handles, sample_packet_queue, missed_packet_queue) =
        start_perfevent_loop(&stop_flag, &config, &sysstat);
    let _ = start_event_flusher(&stop_flag, &config, sysstat, sample_packet_queue, missed_packet_queue).join();

    for loop_handle in perfevent_loop_handles {
        let _ = loop_handle.join();
    }

    Ok(())
}
