use std::env;
use windows::{
    core::{Result, PCSTR},
    Win32::Storage::FileSystem::DeleteFileA,
};

/// deletes the current executable from disk
/// returns Ok(()) if successful, Err otherwise
pub fn delete_self() -> Result<()> {
    unsafe {
        // get current path
        let exe_path = match env::current_exe() {
            Ok(path) => path,
            Err(_) => return Err(windows::core::Error::from_thread()),
        };

        let exe_path_str = exe_path.to_string_lossy();
        let exe_path_bytes = format!("{}\0", exe_path_str);

        // commit suicide
        DeleteFileA(PCSTR(exe_path_bytes.as_ptr()))?;

        Ok(())
    }
}
