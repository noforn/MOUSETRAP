/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/
use antilysis;
use sysinfo::{System, RefreshKind};

pub fn check_debugger() -> bool {
    if let Some(true) = antilysis::detected() {
        return true;
    }

    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_memory(sysinfo::MemoryRefreshKind::everything())
            .with_cpu(sysinfo::CpuRefreshKind::everything())
    );
    sys.refresh_all();

    let total_ram_bytes = sys.total_memory();
    if total_ram_bytes < 2 * 1024 * 1024 * 1024 {
        return true;
    }

    let cpu_count = sys.cpus().len();
    if cpu_count < 4 {
        return true;
    }

    if System::uptime() < 900 {
        return true;
    }
    
    false
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/