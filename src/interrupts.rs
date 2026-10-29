use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::instructions::port::Port;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

// Remap the PIC to 32..47 so IRQs don't collide with CPU exceptions (0..31).
pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

// SAFETY: the offsets are valid and do not overlap CPU exceptions.
pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

static TICKS: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        // SAFETY: the index must be valid in the TSS. gdt.rs puts the
        // emergency stack in exactly this slot.
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
        }
        // SAFETY: timer_entry is a naked function that saves and restores
        // every register and ends with iretq, as an interrupt entry must.
        unsafe {
            idt[InterruptIndex::Timer.as_u8()]
                .set_handler_addr(VirtAddr::new(timer_entry as usize as u64));
        }
        idt[InterruptIndex::Keyboard.as_u8()].set_handler_fn(keyboard_interrupt_handler);
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(_stack_frame: InterruptStackFrame) {
    crate::put_str(18, 26, b"EXCEPTION: BREAKPOINT (handled)", crate::CYAN);
}

extern "x86-interrupt" fn double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    crate::put_str(22, 26, b"EXCEPTION: DOUBLE FAULT (caught safely)", crate::RED);
    loop {
        x86_64::instructions::hlt();
    }
}

/// Timer interrupt entry. Saves all general-purpose registers, asks the
/// scheduler which stack to run next, switches to it and returns with iretq.
/// At the call, rsp is 16-byte aligned: the CPU aligns it, pushes 5 words
/// (40 bytes) and we push 15 more (120 bytes), which totals 160 bytes.
#[unsafe(naked)]
extern "C" fn timer_entry() {
    core::arch::naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        "call {handler}",
        "mov rsp, rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        handler = sym timer_handler,
    );
}

extern "C" fn timer_handler(current_rsp: u64) -> u64 {
    let ticks = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    crate::put_num(24, 14, ticks, crate::GRAY);

    // SAFETY: we are ending the timer interrupt we are handling. This must
    // happen before we switch threads, or the PIC never sends another tick.
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }

    crate::scheduler::switch(current_rsp)
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    let mut port = Port::new(0x60);
    // SAFETY: 0x60 is the PS/2 controller data port. Reading it fetches the
    // scancode and clears the interrupt. We only queue it; the keyboard
    // task does the decoding.
    let scancode: u8 = unsafe { port.read() };
    crate::task::keyboard::add_scancode(scancode);

    // SAFETY: we are ending the keyboard interrupt we are handling.
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
