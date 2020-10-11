use crate::cli_config::CLIConfig;
use crate::sysstat_helper::{SysInfo, DATA_ROOT};
use chrono::Utc;
use crossbeam_queue::ArrayQueue;
use std::fs::File;
use std::io::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{spawn as spawn_thread, JoinHandle};
use std::time::Instant;

pub(crate) fn start_event_flusher(
    stop_flag: &Arc<AtomicBool>,
    config: &CLIConfig,
    sysinfo: SysInfo,
    sample_packet_queue: Arc<ArrayQueue<Vec<u8>>>,
    missed_packet_queue: Arc<ArrayQueue<u64>>,
) -> JoinHandle<()> {
    let stop_flag_clone = stop_flag.clone();
    let config_clone = config.clone();

    spawn_thread(move || {
        let mut missed_counter = 0u64;
        let mut total_counter = 0u64;
        let mut temp_bytes = 0u64;
        let mut last_drop_count = 0u64;
        let mut temp_buffer = Vec::new();
        let mut current_filename = format!(
            "{}/{}-{}.pcap-raw",
            DATA_ROOT,
            config_clone.interface_name.clone(),
            Utc::now().timestamp_nanos()
        );
        let start_instant = Instant::now();

        while !stop_flag_clone.load(Ordering::Relaxed) && start_instant.elapsed() < config_clone.record_duration {
            if start_instant.elapsed() < config_clone.record_duration {
                stop_flag_clone.store(true, Ordering::Relaxed);
            }

            while let Some(new_missed_counter) = missed_packet_queue.pop().ok() {
                missed_counter += new_missed_counter;
                last_drop_count += new_missed_counter;
            }

            while let Some(new_packet) = sample_packet_queue.pop().ok() {
                total_counter += 1;
                temp_bytes += new_packet.len() as u64;
                temp_buffer.push(new_packet);

                if temp_bytes >= config_clone.file_size_clipping {
                    let pending_save_packets: Vec<Vec<u8>> = temp_buffer.drain(..).collect();
                    temp_buffer = Vec::new();
                    let pending_save_count = pending_save_packets.len();

                    let mut file_buffer = File::create(current_filename).unwrap();

                    for packet in pending_save_packets {
                        file_buffer.write(&packet[..]).unwrap();
                    }

                    current_filename = format!(
                        "{}/{}-{}.pcap-raw",
                        DATA_ROOT,
                        config_clone.interface_name.clone(),
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
                        sysinfo.get_disk_usage(),
                    );
                    last_drop_count = 0;
                    temp_bytes = 0;
                    break;
                }
            }
        }
    })
}
