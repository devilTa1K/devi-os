use lazy_static::lazy_static;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

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
