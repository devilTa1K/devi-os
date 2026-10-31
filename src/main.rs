#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use bootloader::bootinfo::MemoryRegionType;
use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::structures::paging::{OffsetPageTable, Translate};
use x86_64::VirtAddr;

mod allocator;
mod gdt;
mod interrupts;
mod memory;
mod scheduler;
mod syscall;
mod apps;
mod audit;
mod fs;
mod shell;
mod task;

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

/// Print n as 0x... and pad with spaces up to `width` characters.
fn put_hex(row: usize, col: usize, n: u64, color: u8, width: usize) {
    let mut buf = [b' '; 20];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut idx = 2;
    let mut started = false;
    for shift in (0..16).rev() {
        let nib = ((n >> (shift * 4)) & 0xF) as u8;
        if nib != 0 || started || shift == 0 {
            started = true;
            buf[idx] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
            idx += 1;
        }
    }
    let w = if width > buf.len() { buf.len() } else { width };
    put_str(row, col, &buf[..w], color);
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

/// Called by the keyboard task for every decoded character.
/// Untrusted input: accept only printable ASCII and cap the line length.
fn typed_char(c: char) {
    let pos = CURSOR.load(Ordering::Relaxed);
    match c {
        '\n' => {
            crate::audit::handle_enter(pos);
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

fn show_translation(row: usize, label: &[u8], addr: VirtAddr, mapper: &OffsetPageTable) {
    put_str(row, 54, label, GRAY);
    match mapper.translate_addr(addr) {
        Some(phys) => put_hex(row, 66, phys.as_u64(), CYAN, 13),
        None => put_str(row, 66, b"unmapped    ", RED),
    }
}

fn show_memory_panel(boot_info: &'static BootInfo, mapper: &OffsetPageTable) {
    let phys_offset = VirtAddr::new(boot_info.physical_memory_offset);

    let mut usable_bytes: u64 = 0;
    for region in boot_info.memory_map.iter() {
        if region.region_type == MemoryRegionType::Usable {
            usable_bytes += region.range.end_addr() - region.range.start_addr();
        }
    }

    put_str(4, 54, b"-- MEMORY --", CYAN);
    put_str(5, 54, b"Usable RAM:", GRAY);
    put_num(5, 64, usable_bytes / (1024 * 1024), WHITE);
    put_str(5, 77, b"MB", GRAY);
    put_str(6, 54, b"Phys map at:", GRAY);
    put_hex(7, 54, boot_info.physical_memory_offset, WHITE, 20);

    put_str(9, 54, b"Translate virt->phys", CYAN);
    show_translation(10, b"VGA 0xb8000:", VirtAddr::new(0xb8000), mapper);
    show_translation(11, b"Map base:", phys_offset, mapper);
    show_translation(12, b"0xdeadbeef:", VirtAddr::new(0xdeadbeef), mapper);
}

/// Proves the heap works: allocate a Box and a Vec, use them, drop them.
fn show_heap_demo() {
    let boxed = Box::new(41u64);
    let mut numbers: Vec<u64> = Vec::new();
    for i in 1..=10 {
        numbers.push(i);
    }
    let sum: u64 = numbers.iter().sum();

    put_str(14, 54, b"-- HEAP (200 KB) --", CYAN);
    put_str(15, 54, b"Box<u64>:", GRAY);
    put_num(15, 64, *boxed + 1, WHITE);
    put_str(16, 54, b"Vec sum:", GRAY);
    put_num(16, 64, sum, WHITE);
}

async fn async_number() -> u32 {
    42
}

/// A first task: awaits another async function and shows the result.
async fn example_task() {
    let number = async_number().await;
    put_str(19, 54, b"-- ASYNC TASK --", CYAN);
    put_str(20, 54, b"async result:", GRAY);
    put_num(20, 68, number as u64, WHITE);
}

/// Demo threads: both loop forever and never yield. They only share the
/// CPU because the timer interrupt preempts them.
extern "C" fn thread_a() -> ! {
    let mut n: u64 = 0;
    put_str(24, 30, b"Thread A:", GRAY);
    loop {
        n += 1;
        if n % 100_000 == 0 {
            put_num(24, 40, n, CYAN);
        }
    }
}

extern "C" fn thread_b() -> ! {
    let mut n: u64 = 0;
    put_str(24, 55, b"Thread B:", GRAY);
    loop {
        n += 1;
        if n % 100_000 == 0 {
            put_num(24, 65, n, RED);
        }
    }
}
entry_point!(kernel_main);

fn kernel_main(boot_info: &'static BootInfo) -> ! {
    clear_screen();
    draw_logo();
    put_str(16, 26, b"DevilTalk OS v0.1 - booted!", WHITE);

    let nx = memory::enable_nx();
    gdt::init();
    interrupts::init_idt();
    put_str(17, 26, b"IDT + double-fault stack ready", GRAY);
    x86_64::instructions::interrupts::int3();
    put_str(19, 26, b"Keyboard + timer online", WHITE);

    let phys_offset = VirtAddr::new(boot_info.physical_memory_offset);
    // SAFETY: the bootloader mapped all physical memory at this offset
    // (map_physical_memory feature), and we call init exactly once.
    let mut mapper = unsafe { memory::init(phys_offset) };
    show_memory_panel(boot_info, &mapper);

    // SAFETY: the memory map comes straight from the bootloader.
    let mut frame_allocator =
        unsafe { memory::BootInfoFrameAllocator::init(&boot_info.memory_map) };

    if allocator::init_heap(&mut mapper, &mut frame_allocator).is_err() {
        put_str(14, 54, b"HEAP INIT FAILED", RED);
        loop {
            x86_64::instructions::hlt();
        }
    }
    fs::init();

    memory::install(mapper, frame_allocator);
    let hardening: &[u8] = if nx {
        b"Hardening: NX on, user code read-only"
    } else {
        b"Hardening: NX FAILED"
    };
    put_str(3, 2, hardening, CYAN);
    syscall::draw_panel();
    scheduler::init();
    audit::init();
    apps::start();
    apps::start_file_app();
    apps::start_hardening_demo();
    scheduler::spawn(audit::monitor, syscall::CAP_ALL);
    

    put_str(21, 2, b"Type below (Enter = clear line):", GRAY);
    put_str(INPUT_ROW, 2, b">", RED);
    put_str(24, 0, b"Timer ticks:", GRAY);

    // SAFETY: the IDT already has handlers for the remapped PIC vectors,
    // so it is safe to start the PIC and enable interrupts.
    unsafe {
        interrupts::PICS.lock().initialize();
    }
    x86_64::instructions::interrupts::enable();

    let mut executor = task::executor::Executor::new();
    
    shell::init();
    executor.spawn(task::Task::new(task::keyboard::print_keypresses()));
    executor.run()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
















