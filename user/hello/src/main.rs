#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 6;
#[allow(dead_code)]
const BADPTR: u64 = u64::MAX - 2;

/// Ask the kernel to show `len` bytes at `ptr` in the shell window.
fn write_raw(ptr: u64, len: u64) -> u64 {
    let ret: u64;
    // SAFETY: int 0x80 enters the kernel's syscall gate, which preserves every
    // register except rax.
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") SYS_WRITE => ret,
            in("rdi") ptr,
            in("rsi") len,
            options(nostack)
        );
    }
    ret
}

fn write(msg: &[u8]) -> u64 {
    write_raw(msg.as_ptr() as u64, msg.len() as u64)
}

fn idle() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(feature = "bad"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(b"Hello from Rust!");
    idle()
}

#[cfg(feature = "bad")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let sp: u64;
    // SAFETY: reads the stack pointer only.
    unsafe {
        asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack));
    }
    // End of the stack page, which is the end of this program's memory.
    let top = ((sp - 1) & !0xFFF) + 0x1000;

    let tests: [(u64, u64); 5] = [
        (0xb8000, 16),                // the kernel's screen buffer
        (0xFFFF_FFFF_FFFF_FFF0, 16),  // pointer plus length overflows
        (top - 4, 16),                // starts inside, runs past the end
        (top - 64, 0),                // empty
        (top - 64, 100_000),          // far too long
    ];
    let mut refused = 0;
    for t in tests {
        if write_raw(t.0, t.1) == BADPTR {
            refused += 1;
        }
    }
    if refused == 5 {
        write(b"survived 5 refusals");
    } else {
        write(b"KERNEL ACCEPTED BAD PTR");
    }
    idle()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    idle()
}
