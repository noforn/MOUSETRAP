/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use windows::{
    core::{s, Result, PCSTR},
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, LUID},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        Security::{
            AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueA,
            TokenPrivileges,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
            LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        },
    },
};

pub unsafe fn enable_debug_privilege() -> Result<()> {
    let mut token = HANDLE::default();
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)?;

    let mut luid = LUID::default();
    LookupPrivilegeValueA(PCSTR::null(), s!("SeDebugPrivilege"), &mut luid)?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)?;

    let last_error = GetLastError();
    if last_error.is_err() {
        let _ = CloseHandle(token);
        return Err(last_error.into());
    }

    CloseHandle(token)?;
    Ok(())
}

/// Checks whether the current process token has SeImpersonatePrivilege.
pub unsafe fn has_impersonate_privilege() -> bool {
    let mut token = HANDLE::default();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
        return false;
    }

    // Get the LUID for SeImpersonatePrivilege
    let mut imp_luid = LUID::default();
    if LookupPrivilegeValueA(PCSTR::null(), s!("SeImpersonatePrivilege"), &mut imp_luid).is_err() {
        let _ = CloseHandle(token);
        return false;
    }

    // Query token privileges
    let mut buffer = [0u8; 4096];
    let mut return_length = 0u32;
    if GetTokenInformation(
        token,
        TokenPrivileges,
        Some(buffer.as_mut_ptr() as *mut _),
        buffer.len() as u32,
        &mut return_length,
    )
    .is_err()
    {
        let _ = CloseHandle(token);
        return false;
    }

    // Parse TOKEN_PRIVILEGES structure
    let privs = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
    let count = privs.PrivilegeCount as usize;
    let privileges = std::slice::from_raw_parts(privs.Privileges.as_ptr(), count);

    let found = privileges.iter().any(|p| {
        p.Luid.LowPart == imp_luid.LowPart && p.Luid.HighPart == imp_luid.HighPart
    });

    let _ = CloseHandle(token);
    found
}

/// Enables SeDebugPrivilege on the current thread's impersonation token.
/// Uses winapi OpenThreadToken since windows crate doesn't export it with our features.
pub unsafe fn enable_debug_on_thread_token() -> Result<()> {
    use winapi::um::processthreadsapi::{GetCurrentThread, OpenThreadToken};
    use winapi::um::winnt::{TOKEN_ADJUST_PRIVILEGES as W_TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY as W_TOKEN_QUERY};

    let mut raw_token: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
    let ok = OpenThreadToken(
        GetCurrentThread(),
        W_TOKEN_ADJUST_PRIVILEGES | W_TOKEN_QUERY,
        1, // open as self
        &mut raw_token,
    );

    if ok == 0 {
        return Err(windows::core::Error::from_thread());
    }

    // Wrap in windows HANDLE for AdjustTokenPrivileges
    let token = HANDLE(raw_token as *mut std::ffi::c_void);

    let mut luid = LUID::default();
    LookupPrivilegeValueA(PCSTR::null(), s!("SeDebugPrivilege"), &mut luid)?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)?;

    let last_error = GetLastError();
    if last_error.is_err() {
        let _ = CloseHandle(token);
        return Err(last_error.into());
    }

    CloseHandle(token)?;
    Ok(())
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/