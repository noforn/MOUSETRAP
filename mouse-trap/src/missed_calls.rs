/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winnt::{ACCESS_MASK, PCONTEXT};
use winapi::ctypes::c_void;
use crate::syscall;


pub unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut SIZE_T,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    syscall!(
        "NtAllocateVirtualMemory",
        unsafe extern "system" fn(
            HANDLE,
            *mut *mut c_void,
            usize,
            *mut SIZE_T,
            u32,
            u32
        ) -> i32,
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect
    )
}

pub unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *mut c_void,
    number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
) -> i32 {
    syscall!(
        "NtWriteVirtualMemory",
        unsafe extern "system" fn(
            HANDLE,
            *mut c_void,
            *mut c_void,
            usize,
            *mut usize
        ) -> i32,
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_write,
        number_of_bytes_written
    )
}

pub unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut SIZE_T,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    syscall!(
        "NtProtectVirtualMemory",
        unsafe extern "system" fn(
            HANDLE,
            *mut *mut c_void,
            *mut SIZE_T,
            u32,
            *mut u32
        ) -> i32,
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect
    )
}

pub unsafe fn nt_get_context_thread(
    thread_handle: HANDLE,
    context: PCONTEXT,
) -> i32 {
    syscall!(
        "NtGetContextThread",
        unsafe extern "system" fn(HANDLE, PCONTEXT) -> i32,
        thread_handle,
        context
    )
}

pub unsafe fn nt_set_context_thread(
    thread_handle: HANDLE,
    context: PCONTEXT,
) -> i32 {
    syscall!(
        "NtSetContextThread",
        unsafe extern "system" fn(HANDLE, PCONTEXT) -> i32,
        thread_handle,
        context
    )
}

pub unsafe fn nt_resume_thread(
    thread_handle: HANDLE,
    suspend_count: *mut u32,
) -> i32 {
    syscall!(
        "NtResumeThread",
        unsafe extern "system" fn(HANDLE, *mut u32) -> i32,
        thread_handle,
        suspend_count
    )
}

pub unsafe fn nt_suspend_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> i32 {
    syscall!(
        "NtSuspendThread",
        unsafe extern "system" fn(HANDLE, *mut u32) -> i32,
        thread_handle,
        previous_suspend_count
    )
}

pub unsafe fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut crate::def::ClientId,
) -> i32 {
    syscall!(
        "NtOpenProcess",
        unsafe extern "system" fn(
            *mut HANDLE,
            ACCESS_MASK,
            *mut OBJECT_ATTRIBUTES,
            *mut crate::def::ClientId
        ) -> i32,
        process_handle,
        desired_access,
        object_attributes,
        client_id
    )
}

pub unsafe fn nt_open_thread(
    thread_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut crate::def::ClientId,
) -> i32 {
    syscall!(
        "NtOpenThread",
        unsafe extern "system" fn(
            *mut HANDLE,
            ACCESS_MASK,
            *mut OBJECT_ATTRIBUTES,
            *mut crate::def::ClientId
        ) -> i32,
        thread_handle,
        desired_access,
        object_attributes,
        client_id
    )
}

pub unsafe fn nt_free_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut SIZE_T,
    free_type: u32,
) -> i32 {
    syscall!(
        "NtFreeVirtualMemory",
        unsafe extern "system" fn(
            HANDLE,
            *mut *mut c_void,
            *mut SIZE_T,
            u32
        ) -> i32,
        process_handle,
        base_address,
        region_size,
        free_type
    )
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/