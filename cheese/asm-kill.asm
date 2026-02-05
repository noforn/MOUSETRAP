start:
    cld
    mov rbp, rsp
    sub rsp, 512
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
    mov r8d, 0x73e2d87e
    call lookup_api
    mov r14, rax

    mov rcx, r12
    mov r8d, 0xc53d4fdb
    call lookup_api
    mov r15, rax

cleanup_stack:
    test r15, r15
    jz do_exit

    lea rcx, [rbp - 512]
    mov rdx, 512
    sub rsp, 32
    call r15
    add rsp, 32

do_exit:
    xor rcx, rcx
    sub rsp, 32
    call r14

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
