# MOUSETRAP

## Executive Summary
MOUSETRAP is a multi-component red-team framework composed of:
- A Rust Windows implant (`mouse-trap/`) that decrypts and executes staged payloads using local fiber or remote thread/fiber hijack paths.
- Assembly-based staged loaders (`cheese/asm-*.asm`), with current variants centered on HTTPS tasking and pipe-backed command execution.
- Python operator tooling for payload generation, encryption, obfuscation, and C2 operations (`cheese/mouse.py`).
- Analysis helpers (`blue/`, `hash_check.py`, `probe_listener.py`).

Key characteristics:
- Runtime payload decryption using hybrid RSA-OAEP + AES-256-CBC.
- HTTPS beacon/task/result channels.
- Anti-analysis checks and syscall-indirection logic.
- Optional remote process/thread execution, PPID spoofing, memory cleanup, and self-delete.

## High-Level Architecture
1. Payload authoring/generation:
- Operator selects ASM loader variant (`asm-https`, `asm-pipes`, `asm-executor`, etc.).
- `assemble.py`/`RSA-enc.py` generate shellcode and encrypted payload artifacts.

2. Packaging:
- `enc_payload.bin` is embedded into Rust implant (`mouse-trap/src/enc_payload.bin`).
- `build.rs` generates per-build obfuscated constants and polymorphic junk code.

3. Runtime:
- Implant resolves/patches runtime behaviors, fetches private key over HTTPS, decrypts staged payload, and executes via selected mode.

4. C2:
- `cheese/mouse.py` provides TLS listener/session queueing/command dispatch/result handling/file collection.

## Implant Runtime Modes and Flags (`mouse-trap/src/main.rs`)
- `/l` (default): local execution path using fibers in current process.
- `/r`: remote thread hijack + fiber-stub execution path.
- `/s`: with `/r`, attempt PPID-spoofed suspended child path first.
- `/c`: post-execution cleanup (zero + free remote allocation after delay).
- `/d`: self-delete attempt.
- `/skip`: bypass anti-analysis/debugger/sandbox checks.

## Rust File-by-File Analysis
### `mouse-trap/build.rs`
- Generates random XOR key and encrypted string constants at build time (AMSI/ETW/NTDLL/Zw-related identifiers).
- Generates `poly_generated.rs` junk/polymorphic logic used by benign initialization path.
- Purpose: reduce static signature stability across builds.

### `mouse-trap/src/main.rs`
- Primary control flow and mode selection.
- Initializes benign logic, optional anti-analysis checks, VEH/syscall hook subsystem.
- Applies AMSI and ETW patch logic.
- Decrypts embedded C2 key URL, fetches remote key, decrypts embedded encrypted payload.
- Executes payload via local fiber or remote fiber hijack logic.
- Optional cleanup (`/c`) and self-delete (`/d`), plus hook teardown.

### `mouse-trap/src/crypto_utils.rs`
- `fetch_key`: HTTPS fetch of key material using `reqwest` with invalid-cert acceptance enabled.
- `decrypt_shellcode`: RSA-OAEP(SHA-256) decrypt of IV+AES key block, then AES-256-CBC payload decrypt with PKCS7 unpad.
- `xor_decrypt`: helper for obfuscated constants/URL decryption.

### `mouse-trap/src/benign_utils.rs`
- Contains benign/noise functions (prime generation, string transform, exports).
- Loads generated polymorphic filler module (`poly_generated.rs`) and fake config objects.
- Purpose: behavioral and static-noise camouflage.

### `mouse-trap/src/nodebug.rs`
- Uses `antilysis` plus runtime environment checks:
- Low RAM threshold check.
- CPU core count threshold check.
- Host uptime threshold check.
- Returns detection boolean used to early-exit unless `/skip` is set.

### `mouse-trap/src/get_privs.rs`
- Attempts enabling `SeDebugPrivilege` on current process token.
- Used when running as admin to expand process/thread access options.

### `mouse-trap/src/find_remote.rs`
- Enumerates processes/threads for candidate targets.
- Functions include:
- Name-based PID discovery (`find_target_pid`).
- Non-SYSTEM 64-bit process fallback selection (`give_me_anything`).
- Thread enumeration by owner PID (`find_all_remote_thread_ids`, etc.).
- Used by remote execution path and spoofing fallback logic.

### `mouse-trap/src/spoof_proc.rs`
- Creates suspended child process with spoofed parent process attribute (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`).
- Uses extended startup attributes and no-window/suspended flags.
- Supports PPID-spoofed staging path before direct thread-hijack fallback.

### `mouse-trap/src/remote_fiber.rs`
- Remote process/thread open helpers via NT wrappers.
- Remote memory allocate/write operations.
- Thread suspend/resume and context get/set.
- Fiber-stub patching:
- Loads embedded `fiber_stub.bin`.
- Replaces placeholder API pointers for `ConvertThreadToFiber`, `CreateFiber`, `SwitchToFiber`.
- Writes stub+shellcode into target process, updates RIP/RDI, resumes execution.
- Optional handle close helpers.

### `mouse-trap/src/suicide.rs`
- Self-delete implementation:
- Optional process termination by PID.
- ADS rename step.
- File disposition via `NtSetInformationFile` with delete flags.
- Implements disk cleanup/suicide behavior.

### `mouse-trap/src/missed_calls.rs`
- Thin wrappers for NT APIs through `syscall!` macro dispatch:
- `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`
- Context/thread/process primitives
- `NtOpenProcess`, `NtOpenThread`, `NtFreeVirtualMemory`, etc.
- Central abstraction for low-level calls used throughout implant.

### `mouse-trap/src/indirect_def.rs`
- Constants and structure definitions used by syscall-indirection subsystem:
- PEB/loader structs.
- PE header/export structs.
- Exception/hardware-breakpoint constants.
- ClientId and argument offset constants for extended syscall args.

### `mouse-trap/src/indirect_utils.rs`
- PEB discovery (`gs:[0x60]`) and loader traversal helpers.
- Module hashing (`dbj2_hash`) and export/NT-header utility functions.
- Supports locating `ntdll` and related metadata for indirect syscall flow.

### `mouse-trap/src/indirect_syscall.rs`
- Defines `syscall!` macro behavior:
- Resolve SSN and target address.
- Set hardware breakpoint state.
- Invoke resolved function pointer.
- Implements `get_ssn_by_name` by parsing `ntdll` export/runtime function data and matching names/hashes.
- Uses decrypted `Zw` prefix constant to track syscall ordinal progression.

### `mouse-trap/src/indirect_hooks.rs`
- Installs two vectored exception handlers:
- One to set hardware breakpoints after forced access-violation.
- One to handle single-step flow and emulate syscall register/state transitions.
- Stores/restores CPU context, handles extended argument copying, and controls instruction flow with trace flag.
- Core of VEH + hardware-breakpoint syscall-indirection mechanism.

### `mouse-trap/src/indirect_lib.rs`
- Re-exports hook/syscall interfaces for broader use.
- Contains test scaffold for indirect syscall invocation (`NtCreateUserProcess` test path).
- Provides debug macro utility gated by feature flag.

## Assembly Loader and Stage Capabilities (`cheese/asm-*.asm`)
Current/active variants:
- `asm-https.asm`:
- WinINet-based HTTPS polling loop.
- GET task retrieval from beacon path.
- In-memory allocation/copy/execute of received stage.

- `asm-pipes.asm`:
- HTTPS polling loop + dual behavior:
- If payload begins with shellcode marker, execute in memory.
- Else execute command through hidden `cmd.exe /c` with redirected pipes, then POST collected stdout/stderr back to C2.

- `asm-executor.asm`:
- HTTPS command fetch path.
- Command execution or in-memory shellcode execution based on task content.

Additional/legacy variants:
- `asm-kill.asm`: small cleanup/termination-focused routine.
- `asm-swiss.asm`, `asm-feta.asm`, `asm-fetaaes.asm`: earlier reverse-shell/staged designs; release notes mark SWISS/FETA lineage as deprecated after RSA-AES transition.

## C2 and Operator Tooling
### `cheese/mouse.py` (listener/operator console)
- Threaded HTTPS server with TLS cert/key support (self-generate if missing).
- Session tracking by source IP, per-session task and command queues.
- Interactive commands:
- `sessions`, `use <id>`, `back`, `mode raw|ps`
- `task <file>` for binary task payload dispatch
- command queueing (PowerShell-wrapped by default in `ps` mode)
- `download <remote_path>` file exfil helper via HTTPS POST upload path
- Result ingestion endpoint and per-session download storage.

### Build/packaging scripts (`cheese/*.py`)
- `assemble.py`: Keystone assembler wrapper for `.asm` -> `.bin`.
- `RSA-enc.py`: key generation + shellcode encryption to `enc_payload.bin` (RSA-OAEP + AES-CBC).
- `RSA-decrypt-test.py`: validation/decrypt test for encrypted payload format.
- `obfuscate-server.py`: XOR-obfuscates URL into Rust byte-array snippet.
- `Gen-IP-Port.py`: generate literal encoding for IP/domain+port insertion into shellcode.
- `hexdomain.py`, `calc_hash.py`, `Txt2Hex.py`: API hash/string-to-hex helpers for shellcode authoring.
- `BRIE.py`, `FETA.py`, `SWISS.py`: legacy shellcode builders retained in repo.
