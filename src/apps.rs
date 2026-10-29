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
