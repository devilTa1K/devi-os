use crate::{put_char, put_num, put_str, CYAN, GRAY, RED, WHITE};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// Capability bits. A thread may only make a call if it holds the bit.
pub const CAP_PRINT: u32 = 1 << 0;
pub const CAP_NETWORK: u32 = 1 << 1;
pub const CAP_FILES: u32 = 1 << 2;
pub const CAP_ALL: u32 = u32::MAX;

// Syscall numbers (in rax). The argument goes in rdi.
pub const SYS_PRINT: u64 = 1;
pub const SYS_NETWORK: u64 = 2;
pub const SYS_FILES: u64 = 3;

// Results (returned in rax).
pub const OK: u64 = 0;
pub const DENIED: u64 = u64::MAX;
pub const UNKNOWN: u64 = u64::MAX - 1;

static ALLOWED_COUNT: AtomicU64 = AtomicU64::new(0);
static DENIED_COUNT: AtomicU64 = AtomicU64::new(0);
static OUT_POS: AtomicUsize = AtomicUsize::new(0);

pub fn draw_panel() {
    put_str(4, 2, b"-- CAPABILITIES --", CYAN);
    put_str(5, 2, b"App A grants: PRINT", GRAY);
    put_str(6, 2, b"App B grants: none", GRAY);
    put_str(8, 2, b"Allowed calls:", GRAY);
    put_str(9, 2, b"Denied calls:", GRAY);
    put_str(10, 2, b"Last denied:", GRAY);
    put_str(11, 2, b"App A output:", GRAY);
}

/// Make a system call from a kernel thread.
pub fn syscall(num: u64, arg: u64) -> u64 {
    let ret: u64;
    // SAFETY: int 0x80 enters our own handler, which preserves every
    // register except rax and returns with iretq.
    unsafe {
        core::arch::asm!("int 0x80", inout("rax") num => ret, in("rdi") arg);
    }
    ret
}

/// Syscall entry. rax = number, rdi = argument. Saves the caller-saved
/// registers, calls the Rust handler with (number, argument) and returns
/// its result in rax. At entry rsp is 8 mod 16 (CPU frame is 40 bytes);
/// 8 pushes + 8 more bytes makes it 16-aligned for the call.
#[unsafe(naked)]
pub extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "sub rsp, 8",
        "mov rsi, rdi",
        "mov rdi, rax",
        "call {handler}",
        "add rsp, 8",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "iretq",
        handler = sym syscall_handler,
    );
}

extern "C" fn syscall_handler(num: u64, arg: u64) -> u64 {
    let (needed, name): (u32, &[u8; 8]) = match num {
        SYS_PRINT => (CAP_PRINT, b"PRINT   "),
        SYS_NETWORK => (CAP_NETWORK, b"NETWORK "),
        SYS_FILES => (CAP_FILES, b"FILES   "),
        _ => return UNKNOWN,
    };

    // Fail closed: if capabilities can't be read, the caller has none.
    let caps = crate::scheduler::current_caps();

    if caps & needed == 0 {
        let n = DENIED_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        put_num(9, 17, n, RED);
        put_str(10, 15, name, RED);
        return DENIED;
    }

    let n = ALLOWED_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    put_num(8, 17, n, WHITE);

    if num == SYS_PRINT {
        // Validate the untrusted argument: printable ASCII only.
        let ch = arg as u8;
        if arg < 128 && ch.is_ascii_graphic() {
            let pos = OUT_POS.fetch_add(1, Ordering::Relaxed) % 24;
            put_char(12, 2 + pos, ch, CYAN);
        }
    }
    OK
}
