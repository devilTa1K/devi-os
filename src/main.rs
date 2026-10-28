#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

mod gdt;
mod interrupts;

const VGA: *mut u8 = 0xb8000 as *mut u8;
const COLS: usize = 80;
const ROWS: usize = 25;

const RED: u8 = 0x0C;
const CYAN: u8 = 0x0B;
const WHITE: u8 = 0x0F;
const GRAY: u8 = 0x07;

const INPUT_ROW: usize = 22;
const INPUT_COL: usize = 4;
const INPUT_MAX: usize = 70;

static CURSOR: AtomicUsize = AtomicUsize::new(0);

fn put_char(row: usize, col: usize, ch: u8, color: u8) {
    if row >= ROWS || col >= COLS {
        return;
    }
    let offset = (row * COLS + col) * 2;
    // SAFETY: the bounds check above keeps offset inside the 80x25 VGA
    // text buffer at 0xb8000, which the bootloader leaves mapped.
    unsafe {
        VGA.add(offset).write_volatile(ch);
        VGA.add(offset + 1).write_volatile(color);
    }
}

fn put_str(row: usize, col: usize, s: &[u8], color: u8) {
    for (i, &b) in s.iter().enumerate() {
        put_char(row, col + i, b, color);
    }
}

fn put_num(row: usize, col: usize, mut n: u64, color: u8) {
    let mut digits = [b' '; 12];
    let mut i = digits.len();
    if n == 0 {
        i -= 1;
        digits[i] = b'0';
    }
    while n > 0 && i > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    put_str(row, col, &digits, color);
}

fn clear_screen() {
    for row in 0..ROWS {
        for col in 0..COLS {
            put_char(row, col, b' ', GRAY);
        }
    }
}

fn draw_box(top: usize, left: usize, height: usize, width: usize, color: u8) {
    let bottom = top + height - 1;
    let right = left + width - 1;
    put_char(top, left, 0xC9, color);
    put_char(top, right, 0xBB, color);
    put_char(bottom, left, 0xC8, color);
    put_char(bottom, right, 0xBC, color);
    for c in (left + 1)..right {
        put_char(top, c, 0xCD, color);
        put_char(bottom, c, 0xCD, color);
    }
    for r in (top + 1)..bottom {
        put_char(r, left, 0xBA, color);
        put_char(r, right, 0xBA, color);
    }
}

fn draw_logo() {
    put_str(4, 32, b"   /\\      /\\   ", RED);
    put_str(5, 32, b"  /  \\    /  \\  ", RED);
    draw_box(6, 33, 5, 14, RED);
    put_char(8, 36, b'>', RED);
    put_char(8, 39, b'_', CYAN);
    put_str(12, 35, b"Devil", RED);
    put_str(12, 40, b"Talk", WHITE);
    put_str(13, 32, b"SECURE BY DESIGN", GRAY);
}

/// Called by the keyboard interrupt handler for every decoded character.
/// Untrusted input: accept only printable ASCII and cap the line length.
fn typed_char(c: char) {
    let pos = CURSOR.load(Ordering::Relaxed);
    match c {
        '\n' => {
            for i in 0..INPUT_MAX {
                put_char(INPUT_ROW, INPUT_COL + i, b' ', WHITE);
            }
            CURSOR.store(0, Ordering::Relaxed);
        }
        '\u{8}' => {
            if pos > 0 {
                put_char(INPUT_ROW, INPUT_COL + pos - 1, b' ', WHITE);
                CURSOR.store(pos - 1, Ordering::Relaxed);
            }
        }
        c if c.is_ascii() && !c.is_ascii_control() => {
            if pos < INPUT_MAX {
                put_char(INPUT_ROW, INPUT_COL + pos, c as u8, WHITE);
                CURSOR.store(pos + 1, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    clear_screen();
    draw_logo();
    put_str(16, 26, b"DevilTalk OS v0.1 - booted!", WHITE);

    gdt::init();
    interrupts::init_idt();
    put_str(17, 26, b"IDT + double-fault stack ready", GRAY);
    x86_64::instructions::interrupts::int3();
    put_str(19, 26, b"Keyboard + timer online", WHITE);

    put_str(21, 2, b"Type below (Enter = clear line):", GRAY);
    put_str(INPUT_ROW, 2, b">", RED);
    put_str(24, 0, b"Timer ticks:", GRAY);

    // SAFETY: the IDT already has handlers for the remapped PIC vectors,
    // so it is safe to start the PIC and enable interrupts.
    unsafe {
        interrupts::PICS.lock().initialize();
    }
    x86_64::instructions::interrupts::enable();

    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
