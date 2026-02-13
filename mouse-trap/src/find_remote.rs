/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use windows::{
    Win32::{
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next,
                TH32CS_SNAPTHREAD, THREADENTRY32,
            },
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION},
            ProcessStatus::{GetProcessImageFileNameA, EnumProcesses},
        },
        Foundation::{CloseHandle, HANDLE},
    },
};

// find target process PID
// returns first matching PID found, or None if not found
pub unsafe fn find_target_pid(process_name: &str) -> Option<u32> {
    let mut pids = [0u32; 1024];
    let mut bytes_returned = 0u32;

    // enum all process IDs
    if EnumProcesses(
        pids.as_mut_ptr(),
        (pids.len() * std::mem::size_of::<u32>()) as u32,
        &mut bytes_returned,
    )
    .is_err()
    {
        return None;
    }

    let count = bytes_returned as usize / std::mem::size_of::<u32>();

    // check each process
    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        }

        // open process with query info access
        let h_process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(handle) => handle,
            Err(_) => continue,
        };

        // get process name
        let mut name_buf = [0u8; 260];
        if GetProcessImageFileNameA(h_process, &mut name_buf) > 0 {
            let name = std::str::from_utf8(&name_buf)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_lowercase();

            if name.contains(&process_name.to_lowercase()) {
                let _ = CloseHandle(h_process);
                return Some(pid);
            }
        }

        let _ = CloseHandle(h_process);
    }

    None
}

// find any user-owned process PID
// checks tokens to filter out SYSTEM + SERVICE
pub unsafe fn give_me_anything() -> Option<u32> {
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser,
        TOKEN_QUERY, TOKEN_USER, IsWellKnownSid,
        WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcessId, IsWow64Process, OpenProcessToken};
    let mut pids = [0u32; 1024];
    let mut bytes_returned = 0u32;
    let my_pid = GetCurrentProcessId();
    if EnumProcesses(
        pids.as_mut_ptr(),
        (pids.len() * std::mem::size_of::<u32>()) as u32,
        &mut bytes_returned,
    )
    .is_err()
    {
        return None;
    }

    let count = bytes_returned as usize / std::mem::size_of::<u32>();
    // skip 0 , 4 (SYSTEM) , and our PID
    for &pid in &pids[..count] {
        if pid == 0 || pid == 4 || pid == my_pid {
            continue;
        }
        let h_process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(handle) => handle,
            Err(_) => continue,
        };
        // skip if not 64-bit
        let mut is_wow64 = windows::core::BOOL(0);
        if IsWow64Process(h_process, &mut is_wow64).is_ok() && is_wow64.as_bool() {
            let _ = CloseHandle(h_process);
            continue;
        }

        // OpenProcessToken and check ownership
        let mut h_token = HANDLE::default();
        if OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token).is_err() {
            let _ = CloseHandle(h_process);
            continue;
        }

        // query token user (SID)
        let mut info_buf = [0u8; 256];
        let mut return_length = 0u32;
        let result = GetTokenInformation(
            h_token,
            TokenUser,
            Some(info_buf.as_mut_ptr() as *mut std::ffi::c_void),
            info_buf.len() as u32,
            &mut return_length,
        );
        let _ = CloseHandle(h_token);

        if result.is_err() {
            let _ = CloseHandle(h_process);
            continue;
        }

        let token_user = &*(info_buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        // skip system accounts
        let is_system = IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(sid, WinLocalServiceSid).as_bool()
            || IsWellKnownSid(sid, WinNetworkServiceSid).as_bool();
        let _ = CloseHandle(h_process);

        if !is_system {
            return Some(pid);
        }
    }
    None
}

// find a thread ID in the specified remote process
// returns first available thread ID, or None if none found
#[allow(dead_code)]
pub unsafe fn find_remote_thread_id(target_pid: u32) -> Option<u32> {
    // snapshot all threads
    let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
        Ok(handle) => handle,
        Err(_) => return None,
    };

    let mut te32 = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    // iterate threads
    if Thread32First(h_snapshot, &mut te32).is_ok() {
        loop {
            // check thread belongs to target process
            if te32.th32OwnerProcessID == target_pid {
                let thread_id = te32.th32ThreadID;
                let _ = CloseHandle(h_snapshot);
                return Some(thread_id);
            }

            if Thread32Next(h_snapshot, &mut te32).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(h_snapshot);
    None
}

// find all thread IDs in the specified remote process
// returns vector of all thread IDs, or empty vector if none found
pub unsafe fn find_all_remote_thread_ids(target_pid: u32) -> Vec<u32> {
    let mut thread_ids = Vec::new();

    // snapshot all threads
    let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
        Ok(handle) => handle,
        Err(_) => return thread_ids,
    };

    let mut te32 = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    // iterate through threads
    if Thread32First(h_snapshot, &mut te32).is_ok() {
        loop {
            // check if thread belongs to target process
            if te32.th32OwnerProcessID == target_pid {
                thread_ids.push(te32.th32ThreadID);
            }

            if Thread32Next(h_snapshot, &mut te32).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(h_snapshot);
    thread_ids
}

// enumerate all PIDs matching a process name
// returns vector of all matching PIDs
#[allow(dead_code)]
pub unsafe fn find_all_pids(process_name: &str) -> Vec<u32> {
    let mut pids = [0u32; 1024];
    let mut bytes_returned = 0u32;
    let mut matching_pids = Vec::new();

    if EnumProcesses(
        pids.as_mut_ptr(),
        (pids.len() * std::mem::size_of::<u32>()) as u32,
        &mut bytes_returned,
    )
    .is_err()
    {
        return matching_pids;
    }

    let count = bytes_returned as usize / std::mem::size_of::<u32>();

    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        }

        let h_process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(handle) => handle,
            Err(_) => continue,
        };

        let mut name_buf = [0u8; 260];
        if GetProcessImageFileNameA(h_process, &mut name_buf) > 0 {
            let name = std::str::from_utf8(&name_buf)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_lowercase();

            if name.contains(&process_name.to_lowercase()) {
                matching_pids.push(pid);
            }
        }

        let _ = CloseHandle(h_process);
    }

    matching_pids
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/