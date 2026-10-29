use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::instructions::interrupts;
use x86_64::registers::segmentation::{Segment, CS, SS};

const STACK_SIZE: usize = 16 * 1024;

struct Thread {
    /// Saved stack pointer; the full register state sits on that stack.
    rsp: u64,
    _stack: Box<[u8]>,
}

struct Scheduler {
    threads: Vec<Thread>,
    current: usize,
}

impl Scheduler {
    fn switch(&mut self, current_rsp: u64) -> u64 {
        if self.threads.len() < 2 {
            return current_rsp;
        }
        self.threads[self.current].rsp = current_rsp;
        self.current = (self.current + 1) % self.threads.len();
        self.threads[self.current].rsp
    }
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// Register the code that is running right now (kernel_main) as thread 0.
pub fn init() {
    interrupts::without_interrupts(|| {
        *SCHEDULER.lock() = Some(Scheduler {
            threads: alloc::vec![Thread {
                rsp: 0,
                _stack: Vec::new().into_boxed_slice(),
            }],
            current: 0,
        });
    });
}

/// Create a thread that starts at `entry`. It never returns.
pub fn spawn(entry: extern "C" fn() -> !) {
    let mut stack = alloc::vec![0u8; STACK_SIZE].into_boxed_slice();
    let top = (stack.as_mut_ptr() as u64 + STACK_SIZE as u64) & !0xF;

    // Layout (high to low): 5-word interrupt frame, then 15 saved registers.
    let frame = top - 40;
    let regs = frame - 15 * 8;

    // SAFETY: both ranges lie inside the stack we just allocated and own.
    // We build the state the timer entry expects to pop and iretq from.
    unsafe {
        let r = regs as *mut u64;
        for i in 0..15 {
            r.add(i).write(0);
        }
        let f = frame as *mut u64;
        f.add(0).write(entry as usize as u64); // RIP
        f.add(1).write(CS::get_reg().0 as u64); // CS
        f.add(2).write(0x202); // RFLAGS: interrupts enabled
        f.add(3).write(frame); // RSP after iretq (16-byte aligned + 8)
        f.add(4).write(SS::get_reg().0 as u64); // SS
    }

    interrupts::without_interrupts(|| {
        if let Some(s) = SCHEDULER.lock().as_mut() {
            s.threads.push(Thread { rsp: regs, _stack: stack });
        }
    });
}

/// Called from the timer interrupt. Never blocks: if the scheduler is
/// busy, we simply keep running the current thread.
pub fn switch(current_rsp: u64) -> u64 {
    match SCHEDULER.try_lock() {
        Some(mut guard) => match guard.as_mut() {
            Some(s) => s.switch(current_rsp),
            None => current_rsp,
        },
        None => current_rsp,
    }
}
