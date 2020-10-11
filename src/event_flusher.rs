use crate::cli_config::CLIConfig;
use crate::sysstat_helper::{SysInfo, DATA_ROOT};
use crate::xdp_kernel_hook::MAX_PACKET_SIZE;
use chrono::{DateTime, Local};
use crossbeam_queue::ArrayQueue;
use pcap_file::pcap::{Packet, PacketHeader, PcapHeader, PcapWriter};
use pcap_file::DataLink;
use std::fs::{create_dir_all, File};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{spawn as spawn_thread, JoinHandle};
use std::time::{Duration, Instant};

const MAGIC_NUMBER: u32 = 0xB33FC453;
const VERSION_MAJOR: u16 = 0;
const VERSION_MINOR: u16 = 1;

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

    fn reset_all_last_counter(&mut self) -> (u64, u64, u64) {
        let capture_counter = self.reset_last_capture();
        (self.reset_last_missed(), capture_counter.0, capture_counter.1)
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

#[allow(dead_code)] // reserved
fn write_all(pcap_writer: &mut PcapWriter<File>, packets: &Vec<(PacketHeader, Vec<u8>)>) {
    for packet in packets {
        write_packet(pcap_writer, packet);
    }
}

fn write_packet(pcap_writer: &mut PcapWriter<File>, packet: &(PacketHeader, Vec<u8>)) {
    let new_packet = Packet::new(packet.0.ts_sec, packet.0.ts_sec, &packet.1[..], packet.0.incl_len);
    pcap_writer.write_packet(&new_packet).expect("Cannot write packet!");
}

fn ensure_directory_exist(current_time: &DateTime<Local>) -> String {
    let dirname = format!("{}/{}", DATA_ROOT, current_time.format("%Y%m%d"));
    create_dir_all(&dirname).expect("Cannot create directory!");
    dirname
}

fn get_pcap_writer() -> PcapWriter<File> {
    let current_time = Local::now();
    let dirname = ensure_directory_exist(&current_time);
    let filename = current_time.format("%Y%m%d-%H%M%S-%f").to_string();
    let fullpath = format!("{}/{}.pcap", dirname, filename);
    let pcap_file = File::create(fullpath).expect("Error creating file!");
    let pcap_header = PcapHeader {
        magic_number: MAGIC_NUMBER,
        version_major: VERSION_MAJOR,
        version_minor: VERSION_MINOR,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: MAX_PACKET_SIZE,
        datalink: DataLink::ETHERNET,
    };
    PcapWriter::with_header(pcap_header, pcap_file).expect("Unexpected pcap formatting while accessing file!")
}

pub(crate) fn start_event_flusher(
    stop_flag: &Arc<AtomicBool>,
    config: &CLIConfig,
    sysinfo: SysInfo,
    sample_packet_queue: Arc<ArrayQueue<(PacketHeader, Vec<u8>)>>,
    missed_packet_queue: Arc<ArrayQueue<u64>>,
) -> JoinHandle<()> {
    let stop_flag_clone = stop_flag.clone();
    let config_clone = config.clone();

    spawn_thread(move || {
        let start_instant = Instant::now();
        let stats_print_interval = Duration::from_secs(1);
        let mut stats = CaptureStats::new(sysinfo);
        let mut stats_instant = Instant::now();
        let mut current_pcap_writer = get_pcap_writer();

        while !stop_flag_clone.load(Ordering::Relaxed) && start_instant.elapsed() < config_clone.record_duration {
            if start_instant.elapsed() < config_clone.record_duration {
                stop_flag_clone.store(true, Ordering::Relaxed);
            }

            if let Some(new_missed_counter) = missed_packet_queue.pop().ok() {
                stats.increment_missed_counter(new_missed_counter)
            }

            if let Some(new_packet) = sample_packet_queue.pop().ok() {
                stats.increment_capture_counter(new_packet.1.len() as u64);
                write_packet(&mut current_pcap_writer, &new_packet);

                if stats.last_capture_count_bytes >= config_clone.file_size_clipping {
                    stats.reset_all_last_counter();
                    current_pcap_writer = get_pcap_writer();
                }
            }

            if stats_instant.elapsed() >= stats_print_interval {
                stats.print_to_console();
                stats_instant = Instant::now();
            }
        }

        println!("Flushing all remaining capture to disk, please wait...");

        while let Some(new_missed_counter) = missed_packet_queue.pop().ok() {
            stats.increment_missed_counter(new_missed_counter)
        }

        while let Some(new_packet) = sample_packet_queue.pop().ok() {
            stats.increment_capture_counter(new_packet.1.len() as u64);
            write_packet(&mut current_pcap_writer, &new_packet);

            if stats.last_capture_count_bytes >= config_clone.file_size_clipping {
                stats.reset_all_last_counter();
                current_pcap_writer = get_pcap_writer();
            }
        }

        stats.print_to_console();
    })
}
