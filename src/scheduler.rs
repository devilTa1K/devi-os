use crate::memory;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::instructions::interrupts;
use x86_64::registers::segmentation::{Segment, CS, SS};

const STACK_SIZE: usize = 16 * 1024;

// User-mode layout: each user program gets a 64 KB slot. The first page
// holds its code, the second its stack.
const USER_BASE: u64 = 0x5555_0000_0000;
const USER_SLOT: u64 = 0x1_0000;
const USER_MAX_CODE: usize = 4096;

static NEXT_USER_SLOT: AtomicU64 = AtomicU64::new(0);

struct Thread {
    /// Saved stack pointer; the full register state sits on that stack.
    rsp: u64,
    /// Capability bits granted to this thread when it was created.
    caps: u32,
    /// Top of this thread's kernel stack if it runs in ring 3, else 0.
    kstack_top: u64,
    /// Killed after a fault. The scheduler never runs a dead thread again.
    dead: bool,
    _stack: Box<[u8]>,
}

struct Scheduler {
    threads: Vec<Thread>,
    current: usize,
}

impl Scheduler {
    fn switch(&mut self, current_rsp: u64) -> u64 {
        let n = self.threads.len();
        if n < 2 {
            return current_rsp;
        }
        self.threads[self.current].rsp = current_rsp;
        // Round-robin, skipping dead threads. Thread 0 (the kernel) is
        // never dead, so this always finds a live thread.
        for _ in 0..n {
            self.current = (self.current + 1) % n;
            if !self.threads[self.current].dead {
                break;
            }
        }
        let next = &self.threads[self.current];
        if next.kstack_top != 0 {
            // The CPU must land on THIS thread's kernel stack the next time
            // it arrives from ring 3.
            crate::gdt::set_kernel_stack(next.kstack_top);
        }
        next.rsp
    }
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// Register the code that is running right now (kernel_main) as thread 0,
/// with every capability, because it is the kernel itself.
pub fn init() {
    interrupts::without_interrupts(|| {
        *SCHEDULER.lock() = Some(Scheduler {
            threads: alloc::vec![Thread {
                rsp: 0,
                caps: crate::syscall::CAP_ALL,
                kstack_top: 0,
                dead: false,
                _stack: Vec::new().into_boxed_slice(),
            }],
            current: 0,
        });
    });
}

/// Create a kernel (ring 0) thread. It never returns.
#[allow(dead_code)]
pub fn spawn(entry: extern "C" fn() -> !, caps: u32) {
    let mut stack = alloc::vec![0u8; STACK_SIZE].into_boxed_slice();
    let top = (stack.as_mut_ptr() as u64 + STACK_SIZE as u64) & !0xF;

    // Layout (high to low): 5-word interrupt frame, then 15 saved registers.
    let frame = top - 40;
    let regs = frame - 15 * 8;

    // SAFETY: both ranges lie inside the stack we just allocated and own.
    unsafe {
        let r = regs as *mut u64;
        for i in 0..15 {
            r.add(i).write(0);
        }
        let f = frame as *mut u64;
        f.add(0).write(entry as usize as u64); // RIP
        f.add(1).write(CS::get_reg().0 as u64); // CS
        f.add(2).write(0x202); // RFLAGS: interrupts enabled
        f.add(3).write(frame); // RSP after iretq
        f.add(4).write(SS::get_reg().0 as u64); // SS
    }

    interrupts::without_interrupts(|| {
        if let Some(s) = SCHEDULER.lock().as_mut() {
            s.threads.push(Thread { rsp: regs, caps, kstack_top: 0, dead: false, _stack: stack });
        }
    });
}

/// Create a user-mode (ring 3) thread from machine code in kernel memory
/// at `start..end`. Returns false if it could not be set up.
pub fn spawn_user(start: usize, end: usize, caps: u32) -> bool {
    let len = end.wrapping_sub(start);
    if len == 0 || len > USER_MAX_CODE {
        return false;
    }

    let slot = NEXT_USER_SLOT.fetch_add(1, Ordering::Relaxed);
    let base = USER_BASE + slot * USER_SLOT;

    // Page 1: code. Page 2: stack. Both user-accessible.
    if memory::map_user_page(base, true).is_err()
        || memory::map_user_page(base + 0x1000, true).is_err()
    {
        return false;
    }

    // SAFETY: both pages were just mapped writable at `base`. We zero them
    // first so no leftover kernel data leaks to the app, then copy the code.
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, 0x2000);
        core::ptr::copy_nonoverlapping(start as *const u8, base as *mut u8, len);
    }
    let user_stack_top = base + 0x2000;

    // This thread's own kernel stack (used by the CPU when it arrives from
    // ring 3). It lives on the heap, which ring 3 cannot access.
    let mut kstack = alloc::vec![0u8; STACK_SIZE].into_boxed_slice();
    let top = (kstack.as_mut_ptr() as u64 + STACK_SIZE as u64) & !0xF;
    let frame = top - 40;
    let regs = frame - 15 * 8;

    // SAFETY: both ranges lie inside the kernel stack we just allocated. We
    // build a frame that makes the first iretq enter ring 3 at `base`.
    unsafe {
        let r = regs as *mut u64;
        for i in 0..15 {
            r.add(i).write(0);
        }
        let f = frame as *mut u64;
        f.add(0).write(base); // RIP: start of the user code page
        f.add(1).write(crate::gdt::user_code_selector() as u64); // CS (ring 3)
        f.add(2).write(0x202); // RFLAGS: interrupts enabled, IOPL 0
        f.add(3).write(user_stack_top); // RSP: top of the user stack page
        f.add(4).write(crate::gdt::user_data_selector() as u64); // SS (ring 3)
    }

    interrupts::without_interrupts(|| {
        if let Some(s) = SCHEDULER.lock().as_mut() {
            s.threads.push(Thread { rsp: regs, caps, kstack_top: top, dead: false, _stack: kstack });
            crate::audit::record(crate::audit::START, (s.threads.len() - 1) as u8, caps as u64);
        }
    });
    true
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

/// Capabilities of the running thread. Fails closed: if the scheduler is
/// unavailable for any reason, the answer is "no capabilities".
pub fn current_caps() -> u32 {
    match SCHEDULER.try_lock() {
        Some(guard) => match guard.as_ref() {
            Some(s) => s.threads[s.current].caps,
            None => 0,
        },
        None => 0,
    }
}

/// Mark the running user thread dead and strip its capabilities. Returns its
/// thread number. Called from a fault handler, where interrupts are already
/// off, so taking the lock cannot deadlock. The kernel (thread 0) is never
/// killed.
pub fn kill_current() -> Option<usize> {
    let mut guard = SCHEDULER.lock();
    let s = guard.as_mut()?;
    if s.current == 0 {
        return None;
    }
    let id = s.current;
    s.threads[id].dead = true;
    s.threads[id].caps = 0;
    Some(id)
}


/// Thread number of the running thread, or 255 if the scheduler is busy.
pub fn current_id() -> usize {
    match SCHEDULER.try_lock() {
        Some(guard) => guard.as_ref().map(|s| s.current).unwrap_or(255),
        None => 255,
    }
}
