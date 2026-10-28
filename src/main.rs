#![no_std]
#![no_main]

use core::panic::PanicInfo;

static HELLO: &[u8] = b"DevilTalk OS v0.1 - booted!";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // VGA text memory: 2 bytes per character (char, then color).
    let vga_buffer = 0xb8000 as *mut u8;

    for (i, &byte) in HELLO.iter().enumerate() {
        // SAFETY: 0xb8000 is the VGA text buffer, mapped by the bootloader,
        // and we stay within its first 54 bytes.
        unsafe {
            *vga_buffer.offset(i as isize * 2) = byte;
            *vga_buffer.offset(i as isize * 2 + 1) = 0x4; // red on black
        }
    }

    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
