use crate::cli_config::CLIConfig;
use crate::sysstat_helper::{SysInfo, DATA_ROOT};
use chrono::Local;
use crossbeam_queue::ArrayQueue;
use std::fs::File;
use std::io::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{spawn as spawn_thread, JoinHandle};
use std::time::{Duration, Instant};

struct CaptureStats {
    sysinfo: SysInfo,
    total_missed_counter: u64,
    total_captured_counter: u64,
    total_captured_counter_bytes: u64,
    last_missed_count: u64,
    last_capture_count: u64,
    last_capture_count_bytes: u64,
}

impl CaptureStats {
    fn new(sysinfo: SysInfo) -> Self {
        Self {
            sysinfo,
            total_missed_counter: 0,
            total_captured_counter: 0,
            total_captured_counter_bytes: 0,
            last_missed_count: 0,
            last_capture_count: 0,
            last_capture_count_bytes: 0,
        }
    }

    fn increment_missed_counter(&mut self, new_missed: u64) {
        self.last_missed_count += new_missed;
        self.total_missed_counter += new_missed;
    }

    fn reset_last_missed(&mut self) -> u64 {
        let last_missed = self.last_missed_count;
        self.last_missed_count = 0;

        last_missed
    }

    fn increment_capture_counter(&mut self, new_packet_size: u64) {
        self.total_captured_counter += 1;
        self.last_capture_count += 1;
        self.total_captured_counter_bytes += new_packet_size;
        self.last_capture_count_bytes += new_packet_size;
    }

    fn reset_last_capture(&mut self) -> (u64, u64) {
        let last_capture = self.last_capture_count;
        let last_capture_bytes = self.last_capture_count_bytes;
        self.last_capture_count = 0;
        self.last_capture_count_bytes = 0;

        (last_capture, last_capture_bytes)
    }

    fn print_to_console(&self) {
        println!(
            "[{}] => LLoss {} | LCap {} || TLost {} | TCap {} | TCapMB {} || Disk: {}%",
            Local::now().to_rfc3339(),
            self.last_missed_count,
            self.last_capture_count,
            self.total_missed_counter,
            self.total_captured_counter,
            self.total_captured_counter_bytes as f64 / 1048576.0,
            self.sysinfo.get_disk_usage(),
        );
    }
}

fn write_all(current_filename: &str, packets: &Vec<Vec<u8>>) {
    let mut file_buffer = File::create(current_filename).unwrap();

    for packet in packets {
        file_buffer.write(&packet[..]).unwrap();
    }
}

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
        let mut stats = CaptureStats::new(sysinfo);
        let mut temp_buffer = Vec::new();
        let mut current_filename = format!(
            "{}/{}-{}.pcap",
            DATA_ROOT,
            config_clone.interface_name.clone(),
            Local::now().format("%Y%m%d-%H%M%S-%f")
        );
        let start_instant = Instant::now();
        let stats_print_interval = Duration::from_secs(1);
        let mut stats_instant = Instant::now();

        while !stop_flag_clone.load(Ordering::Relaxed) && start_instant.elapsed() < config_clone.record_duration {
            if start_instant.elapsed() < config_clone.record_duration {
                stop_flag_clone.store(true, Ordering::Relaxed);
                write_all(&current_filename, &temp_buffer);
            }

            if let Some(new_missed_counter) = missed_packet_queue.pop().ok() {
                stats.increment_missed_counter(new_missed_counter)
            }

            if let Some(new_packet) = sample_packet_queue.pop().ok() {
                stats.increment_capture_counter(new_packet.len() as u64);
                temp_buffer.push(new_packet);
            }

            if stats.last_capture_count_bytes >= config_clone.file_size_clipping {
                let pending_save_packets: Vec<Vec<u8>> = temp_buffer.drain(..).collect();
                temp_buffer = Vec::new();
                write_all(&current_filename, &pending_save_packets);
                stats.reset_last_capture();
                stats.reset_last_missed();
                current_filename = format!(
                    "{}/{}-{}.pcap",
                    DATA_ROOT,
                    config_clone.interface_name.clone(),
                    Local::now().format("%Y%m%d-%H%M%S-%f")
                );
            }

            if stats_instant.elapsed() >= stats_print_interval {
                stats.print_to_console();
                stats_instant = Instant::now();
            }
        }
    })
}
