//! Loads a VALIDATED ELF plan into a fresh address space (M1c-2).
//! Every page is mapped with its final permissions (writable XOR executable),
//! and the kernel fills it through its own window onto physical memory.

use crate::elf::{self, ElfError, PF_W, PF_X};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Fixed stack page for ELF programs. It lies inside the user region, and the
/// page directly below it is never mapped, so it acts as a guard page.
pub const STACK_PAGE: u64 = 0x5555_1010_0000;
pub const STACK_TOP: u64 = STACK_PAGE + 0x1000;

/// Frames taken by loads that then failed. This should always stay at 0.
static LOST: AtomicUsize = AtomicUsize::new(0);

pub enum LoadError {
    Invalid(ElfError),
    OutOfFrames,
    Map,
}

impl LoadError {
    pub fn name(&self) -> &'static [u8] {
        match self {
            LoadError::Invalid(e) => e.name(),
            LoadError::OutOfFrames => b"out of frames",
            LoadError::Map => b"map failed",
        }
    }
}

/// Show the lost-frame counter on row 0.
pub fn show_lost() {
    let n = LOST.load(Ordering::Relaxed);
    crate::put_num(0, 66, n as u64, crate::WHITE);
    crate::put_str(0, 62, b"Frames lost:", crate::GRAY);
}

/// Validate `image`, then load and start it.
pub fn load(image: &[u8], caps: u32) -> Result<(), LoadError> {
    let plan = elf::parse(image).map_err(LoadError::Invalid)?;

    // Count first, so a validated program can only fail before anything is
    // allocated: segment pages, the stack page, the top-level table, and a
    // generous allowance for the page-table pages.
    let mut need: usize = 2;
    for s in &plan.segs[..plan.count] {
        need += ((s.memsz + 0xFFF) >> 12) as usize;
    }
    need += 6;
    if crate::memory::frames_free() < need + 64 {
        return Err(LoadError::OutOfFrames);
    }

    let mut used = 0usize;
    let result = build(image, &plan, caps, &mut used);
    if result.is_err() {
        LOST.fetch_add(used, Ordering::Relaxed);
        show_lost();
    }
    result
}

fn build(image: &[u8], plan: &elf::Plan, caps: u32, used: &mut usize) -> Result<(), LoadError> {
    let p4 = crate::memory::new_address_space().ok_or(LoadError::OutOfFrames)?;
    *used += 1;

    // (start, end, writable) for every range this program owns.
    let mut ranges: [(u64, u64, bool); 6] = [(0, 0, false); 6];
    let mut nr = 0usize;

    for s in &plan.segs[..plan.count] {
        let npages = ((s.memsz + 0xFFF) >> 12) as usize;
        let writable = s.flags & PF_W != 0;
        let executable = s.flags & PF_X != 0;
        for j in 0..npages {
            let page_off = (j as u64) * 4096;
            let va = s.vaddr + page_off;
            // The page is mapped with its FINAL permissions and starts zeroed.
            let frame = crate::memory::map_user_in(p4, va, writable, executable)
                .ok_or(LoadError::Map)?;
            *used += 1;
            // Copy this page's share of the file bytes; the rest stays zero (.bss).
            if page_off < s.filesz {
                let n = core::cmp::min(4096, s.filesz - page_off) as usize;
                let from = (s.offset + page_off) as usize;
                let bytes = image.get(from..from + n).ok_or(LoadError::Map)?;
                crate::memory::copy_to_frame(frame, 0, bytes);
            }
        }
        if nr < ranges.len() {
            ranges[nr] = (s.vaddr, s.vaddr + (npages as u64) * 4096, writable);
            nr += 1;
        }
    }

    crate::memory::map_user_in(p4, STACK_PAGE, true, false).ok_or(LoadError::Map)?;
    *used += 1;
    if nr < ranges.len() {
        ranges[nr] = (STACK_PAGE, STACK_TOP, true);
        nr += 1;
    }

    let cr3 = p4.start_address().as_u64();
    if crate::scheduler::spawn_prepared(cr3, plan.entry, STACK_TOP, caps, &ranges[..nr]) {
        Ok(())
    } else {
        Err(LoadError::Map)
    }
}
