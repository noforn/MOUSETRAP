/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use windows::{
    core::{s, Result, PCSTR},
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, LUID},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueA,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED,
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

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/