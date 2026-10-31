use crate::scheduler::spawn_user;
use crate::syscall::CAP_PRINT;
use crate::{put_num, put_str, CYAN, GRAY, RED};

core::arch::global_asm!(r#"
    .text

    .global user_prog_a_start
    .global user_prog_a_end
user_prog_a_start:
.La_loop:
    mov ax, cs
    and rax, 3
    add rax, 48
    mov rdi, rax
    mov rax, 1
    int 0x80
    mov rcx, 5000000
.La_delay:
    dec rcx
    jnz .La_delay
    jmp .La_loop
user_prog_a_end:

    .global user_prog_b_start
    .global user_prog_b_end
user_prog_b_start:
    mov rbx, 1
.Lb_loop:
    mov rax, rbx
    mov rdi, 88
    int 0x80
    inc rbx
    cmp rbx, 4
    jne .Lb_wait
    mov rbx, 1
.Lb_wait:
    mov rcx, 5000000
.Lb_delay:
    dec rcx
    jnz .Lb_delay
    jmp .Lb_loop
user_prog_b_end:

    .global user_prog_c_start
    .global user_prog_c_end
user_prog_c_start:
    mov rcx, 300000000
.Lc_delay:
    dec rcx
    jnz .Lc_delay
    mov rax, 0xb8000
    mov rbx, [rax]
.Lc_never:
    jmp .Lc_never
user_prog_c_end:

    .global user_prog_d_start
    .global user_prog_d_end
user_prog_d_start:
    mov rcx, 600000000
.Ld_delay:
    dec rcx
    jnz .Ld_delay
    hlt
.Ld_never:
    jmp .Ld_never
user_prog_d_end:
"#);

unsafe extern "C" {
    static user_prog_a_start: u8;
    static user_prog_a_end: u8;
    static user_prog_b_start: u8;
    static user_prog_b_end: u8;
    static user_prog_c_start: u8;
    static user_prog_c_end: u8;
    static user_prog_d_start: u8;
    static user_prog_d_end: u8;
}

/// Start all four apps in ring 3. Only App A holds a capability (PRINT).
/// App C reads kernel memory and App D runs a privileged instruction.
/// Both are expected to be killed by the fault handlers.
pub fn start() {
    // We only take the addresses of the symbols; we never read through them.
    let a0 = (&raw const user_prog_a_start) as usize;
    let a1 = (&raw const user_prog_a_end) as usize;
    let b0 = (&raw const user_prog_b_start) as usize;
    let b1 = (&raw const user_prog_b_end) as usize;
    let c0 = (&raw const user_prog_c_start) as usize;
    let c1 = (&raw const user_prog_c_end) as usize;
    let d0 = (&raw const user_prog_d_start) as usize;
    let d1 = (&raw const user_prog_d_end) as usize;

    let ok_a = spawn_user(a0, a1, CAP_PRINT);
    let ok_b = spawn_user(b0, b1, 0);
    let ok_c = spawn_user(c0, c1, 0);
    let ok_d = spawn_user(d0, d1, 0);

    if ok_a && ok_b && ok_c && ok_d {
        put_str(13, 2, b"Apps run in RING 3", CYAN);
        put_str(24, 30, b"Apps killed:", GRAY);
        put_num(24, 43, 0, RED);
    } else {
        put_str(13, 2, b"USER APP SPAWN FAILED", RED);
    }
}

core::arch::global_asm!(r#"
    .text

    .global user_prog_e_start
    .global user_prog_e_end
user_prog_e_start:
    xor rbx, rbx
.Le_loop:
    mov rax, 3
    mov rdi, rbx
    int 0x80
    inc rbx
    cmp rbx, 3
    jne .Le_wait
    xor rbx, rbx
.Le_wait:
    mov rcx, 5000000
.Le_delay:
    dec rcx
    jnz .Le_delay
    jmp .Le_loop
user_prog_e_end:
"#);

unsafe extern "C" {
    static user_prog_e_start: u8;
    static user_prog_e_end: u8;
}

/// App E: holds FILES but not SECRET, and reads files 0, 1, 2 in turn.
pub fn start_file_app() {
    let e0 = (&raw const user_prog_e_start) as usize;
    let e1 = (&raw const user_prog_e_end) as usize;
    if !spawn_user(e0, e1, crate::syscall::CAP_FILES) {
        put_str(12, 2, b"FILE APP SPAWN FAILED", RED);
    }
}

core::arch::global_asm!(r#"
    .text

    .global user_prog_f_start
    .global user_prog_f_end
user_prog_f_start:
    mov rcx, 900000000
.Lf_delay:
    dec rcx
    jnz .Lf_delay
    lea rax, [rip + user_prog_f_start]
    mov byte ptr [rax], 0x90
.Lf_never:
    jmp .Lf_never
user_prog_f_end:

    .global user_prog_g_start
    .global user_prog_g_end
user_prog_g_start:
    mov rcx, 1200000000
.Lg_delay:
    dec rcx
    jnz .Lg_delay
    mov byte ptr [rsp - 8], 0xc3
    lea rax, [rsp - 8]
    jmp rax
user_prog_g_end:
"#);

unsafe extern "C" {
    static user_prog_f_start: u8;
    static user_prog_f_end: u8;
    static user_prog_g_start: u8;
    static user_prog_g_end: u8;
}

/// App F overwrites its own code (blocked by read-only code pages).
/// App G jumps into its own stack (blocked by NX). Neither holds capabilities.
pub fn start_hardening_demo() {
    let f0 = (&raw const user_prog_f_start) as usize;
    let f1 = (&raw const user_prog_f_end) as usize;
    let g0 = (&raw const user_prog_g_start) as usize;
    let g1 = (&raw const user_prog_g_end) as usize;

    let ok_f = spawn_user(f0, f1, 0);
    let ok_g = spawn_user(g0, g1, 0);
    if !(ok_f && ok_g) {
        put_str(24, 55, b"HARDENING APPS FAILED", RED);
    }
}

core::arch::global_asm!(r#"
    .text

    .global user_prog_h_start
    .global user_prog_h_end
user_prog_h_start:
    mov rcx, 1500000000
.Lh_delay:
    dec rcx
    jnz .Lh_delay
    mov rax, 99
    mov rdi, 0
    int 0x80
.Lh_never:
    jmp .Lh_never
user_prog_h_end:

    .global user_prog_i_start
    .global user_prog_i_end
user_prog_i_start:
    mov rcx, 1800000000
.Li_delay:
    dec rcx
    jnz .Li_delay
    mov rax, 3
    mov rdi, 0
    int 0x80
    mov rax, 4
    mov rdi, 18
    int 0x80
    mov rax, 4
    mov rdi, 0xFFFFFFFF
    int 0x80
    mov rax, 3
    mov rdi, 0
    int 0x80
.Li_never:
    jmp .Li_never
user_prog_i_end:
"#);

unsafe extern "C" {
    static user_prog_h_start: u8;
    static user_prog_h_end: u8;
    static user_prog_i_start: u8;
    static user_prog_i_end: u8;
}

/// App H calls a syscall that does not exist. App I sandboxes itself and
/// then calls a syscall it just gave up, even though it still holds the
/// capability for it. The filter should kill both.
pub fn start_filter_demo() {
    let h0 = (&raw const user_prog_h_start) as usize;
    let h1 = (&raw const user_prog_h_end) as usize;
    let i0 = (&raw const user_prog_i_start) as usize;
    let i1 = (&raw const user_prog_i_end) as usize;

    let ok_h = spawn_user(h0, h1, 0);
    let ok_i = spawn_user(i0, i1, crate::syscall::CAP_PRINT | crate::syscall::CAP_FILES);
    if !(ok_h && ok_i) {
        put_str(24, 55, b"FILTER APPS FAILED", RED);
    }
}
