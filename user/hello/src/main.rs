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

// ---- hello (the default program) ----
#[cfg(not(any(feature = "bad", feature = "data", feature = "rotest", feature = "nxtest")))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(b"Hello from Rust!");
    idle()
}

// ---- badwrite: five bad pointers, all must be refused ----
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

// ---- data: an initialized global (.data) and a zeroed one (.bss) ----
#[cfg(feature = "data")]
static mut COUNTER: u64 = 5;
#[cfg(feature = "data")]
static mut ZEROED: [u64; 4] = [0; 4];

#[cfg(feature = "data")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: this program is single-threaded and uses these statics only here.
    let ok = unsafe {
        let c = &raw mut COUNTER;
        let z = &raw mut ZEROED as *mut u64;
        // The initial value must have come from the file.
        let mut good = core::ptr::read_volatile(c) == 5;
        // The bss must start out zeroed.
        for i in 0..4 {
            if core::ptr::read_volatile(z.add(i)) != 0 {
                good = false;
            }
        }
        // Both must be writable.
        core::ptr::write_volatile(c, 6);
        core::ptr::write_volatile(z, 7);
        good && core::ptr::read_volatile(c) == 6 && core::ptr::read_volatile(z) == 7
    };
    if ok {
        write(b"data+bss ok, writable");
    } else {
        write(b"DATA SEGMENT WRONG");
    }
    idle()
}

// ---- rotest: write to read-only constants; the kernel should kill it ----
#[cfg(feature = "rotest")]
static CONSTANT: [u8; 16] = *b"constant data..!";

#[cfg(feature = "rotest")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(b"writing to rodata");
    // SAFETY: deliberate. CONSTANT lives in the read-only segment, so the CPU
    // should refuse this write and the kernel should kill this program.
    unsafe {
        core::ptr::write_volatile(CONSTANT.as_ptr() as *mut u8, b'X');
    }
    write(b"ROTEST NOT KILLED");
    idle()
}

// ---- nxtest: jump into the data segment; the kernel should kill it ----
#[cfg(feature = "nxtest")]
static mut CODE: [u8; 16] = [0xC3; 16];

#[cfg(feature = "nxtest")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(b"jumping into data");
    // SAFETY: deliberate. CODE sits in the writable, non-executable data
    // segment, so the CPU should refuse to run it and the kernel should kill
    // this program.
    unsafe {
        let f: extern "C" fn() = core::mem::transmute((&raw const CODE) as usize);
        f();
    }
    write(b"NXTEST NOT KILLED");
    idle()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    idle()
}
