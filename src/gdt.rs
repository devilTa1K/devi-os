use lazy_static::lazy_static;
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{Segment, CS};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Which IST slot holds the emergency stack for double faults.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const STACK_SIZE: usize = 4096 * 5;

static mut DOUBLE_FAULT_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
// The TSS must be writable at runtime: privilege_stack_table[0] (rsp0) is
// updated on every thread switch.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

struct Selectors {
    kernel_code: SegmentSelector,
    tss: SegmentSelector,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
}

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        // SAFETY: TSS is a static that lives forever; the descriptor only
        // records its address and size.
        let tss = gdt.append(unsafe { Descriptor::tss_segment_unchecked(&raw const TSS) });
        (gdt, Selectors { kernel_code, tss, user_code, user_data })
    };
}

pub fn init() {
    // SAFETY: runs once at boot before interrupts are enabled, so nothing
    // else is touching the TSS yet.
    unsafe {
        let stack_start = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
        // Stacks grow downward, so the CPU needs the END address.
        (*(&raw mut TSS)).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            stack_start + STACK_SIZE as u64;
    }
    GDT.0.load();
    // SAFETY: the selectors come from the GDT we just loaded, so they are
    // valid. Loading them tells the CPU which code segment and TSS to use.
    unsafe {
        CS::set_reg(GDT.1.kernel_code);
        load_tss(GDT.1.tss);
    }
}

/// Ring-3 code segment selector (RPL forced to 3).
pub fn user_code_selector() -> u16 {
    GDT.1.user_code.0 | 3
}

/// Ring-3 data/stack segment selector (RPL forced to 3).
pub fn user_data_selector() -> u16 {
    GDT.1.user_data.0 | 3
}

/// Set the stack the CPU switches to when an interrupt or syscall arrives
/// from ring 3. Called by the scheduler for every thread switch.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: only called from the timer interrupt (interrupts are off) or
    // during boot, so there is no concurrent access. The CPU re-reads rsp0
    // on every ring 3 -> ring 0 transition.
    unsafe {
        (*(&raw mut TSS)).privilege_stack_table[0] = VirtAddr::new(top);
    }
}
