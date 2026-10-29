use crate::scheduler::spawn_user;
use crate::syscall::CAP_PRINT;
use crate::{put_str, CYAN, RED};

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
"#);

unsafe extern "C" {
    static user_prog_a_start: u8;
    static user_prog_a_end: u8;
    static user_prog_b_start: u8;
    static user_prog_b_end: u8;
}

/// Start both apps in ring 3. App A holds PRINT, App B holds nothing.
pub fn start() {
    // SAFETY: the symbols are defined by the assembly above. We only take
    // their addresses; we never read through them as Rust statics.
    let (a0, a1, b0, b1) = unsafe {
        (
            (&raw const user_prog_a_start) as usize,
            (&raw const user_prog_a_end) as usize,
            (&raw const user_prog_b_start) as usize,
            (&raw const user_prog_b_end) as usize,
        )
    };

    let ok_a = spawn_user(a0, a1, CAP_PRINT);
    let ok_b = spawn_user(b0, b1, 0);

    if ok_a && ok_b {
        put_str(13, 2, b"Apps run in RING 3", CYAN);
    } else {
        put_str(13, 2, b"USER APP SPAWN FAILED", RED);
    }
}
