use sys_info::mem_info;
use systemstat::{Platform, System as SysStat};

pub(crate) const DATA_ROOT: &str = "/opt/dump";

pub(crate) struct SysInfo {
    sysstat: SysStat,
}

impl Default for SysInfo {
    fn default() -> Self {
        Self { sysstat: SysStat::new() }
    }
}

impl SysInfo {
    pub(crate) fn get_total_memory(&self) -> u64 {
        mem_info().expect("Cannot get memory information!").total
    }

    pub(crate) fn get_disk_usage(&self) -> u8 {
        let mut avail = 0;
        let mut total = 0;

        match self.sysstat.mounts() {
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
}
