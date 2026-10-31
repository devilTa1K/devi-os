use bootloader::bootinfo::{MemoryMap, MemoryRegionType};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// Build a page-table mapper from the active level-4 table.
///
/// SAFETY: the caller must guarantee that all physical memory is mapped at
/// `physical_memory_offset`, and must call this only once, because it creates
/// a `&mut` reference to the active page table.
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    // CR3 holds the physical address of the top-level page table.
    let (level_4_frame, _) = Cr3::read();
    let phys = level_4_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

/// Hands out each usable physical frame from the bootloader memory map,
/// one at a time, never twice.
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// SAFETY: the caller must guarantee that the memory map is accurate,
    /// meaning every frame marked Usable is really unused.
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator { memory_map, next: 0 }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        let regions = self.memory_map.iter();
        let usable = regions.filter(|r| r.region_type == MemoryRegionType::Usable);
        let addr_ranges = usable.map(|r| r.range.start_addr()..r.range.end_addr());
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

// SAFETY: allocate_frame returns each usable frame at most once, because
// `next` only ever increases.
unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

// ---- Global memory manager and user pages (Stage 6b) ----
use spin::Mutex;
use x86_64::structures::paging::{Mapper, Page, PageTableFlags};

struct Manager {
    mapper: OffsetPageTable<'static>,
    frames: BootInfoFrameAllocator,
}

static MANAGER: Mutex<Option<Manager>> = Mutex::new(None);

/// Hand the mapper and frame allocator to the global manager.
pub fn install(mapper: OffsetPageTable<'static>, frames: BootInfoFrameAllocator) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        *MANAGER.lock() = Some(Manager { mapper, frames });
    });
}

/// Map one fresh physical frame at `addr` so that ring 3 may access it.
/// The parent page tables also get USER_ACCESSIBLE, or the CPU would still
/// refuse user access to the page.
pub fn map_user_page(addr: u64, writable: bool) -> Result<(), ()> {
    let mut guard = MANAGER.lock();
    let m = guard.as_mut().ok_or(())?;

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
    let frame = m.frames.allocate_frame().ok_or(())?;

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    let parent_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    // SAFETY: the frame was just taken from the allocator, so nothing else
    // uses it, and the page lies in the user region (PML4 slot 170), which
    // no kernel mapping overlaps.
    unsafe {
        m.mapper
            .map_to_with_table_flags(page, frame, flags, parent_flags, &mut m.frames)
            .map_err(|_| ())?
            .flush();
    }
    Ok(())
}

/// Turn on the no-execute bit. Must run before any page table entry uses
/// NO_EXECUTE, or the CPU treats that bit as reserved and faults.
pub fn enable_nx() -> bool {
    use x86_64::registers::model_specific::{Efer, EferFlags};
    // SAFETY: setting NXE only changes how the NO_EXECUTE page-table bit is
    // interpreted. We set it at the start of boot, before any page uses it.
    unsafe {
        Efer::update(|f| *f |= EferFlags::NO_EXECUTE_ENABLE);
    }
    Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE)
}

/// Change the permissions of an already-mapped user page.
pub fn protect_user_page(addr: u64, writable: bool, executable: bool) -> Result<(), ()> {
    let mut guard = MANAGER.lock();
    let m = guard.as_mut().ok_or(())?;
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    // SAFETY: the page is one we mapped in map_user_page, so changing only
    // its permission bits cannot break another mapping.
    unsafe {
        m.mapper.update_flags(page, flags).map_err(|_| ())?.flush();
    }
    Ok(())
}

// ---- Stage 9b: SMEP and SMAP ----
use core::sync::atomic::{AtomicBool, Ordering};

static SMAP_ON: AtomicBool = AtomicBool::new(false);

/// Turn on SMEP and SMAP if the CPU has them. Returns (smep, smap).
pub fn enable_smep_smap() -> (bool, bool) {
    use x86_64::registers::control::{Cr4, Cr4Flags};

    let max_leaf = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
    if max_leaf < 7 {
        return (false, false);
    }
    let leaf7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };
    let smep = leaf7.ebx & (1 << 7) != 0;
    let smap = leaf7.ebx & (1 << 20) != 0;

    // SAFETY: we only set CR4 bits that the CPU reports as supported.
    unsafe {
        Cr4::update(|flags| {
            if smep {
                flags.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
            }
            if smap {
                flags.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
            }
        });
    }
    SMAP_ON.store(smap, Ordering::Relaxed);
    (smep, smap)
}

/// Run `f` with kernel access to user pages allowed (a stac/clac window).
pub fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    let on = SMAP_ON.load(Ordering::Relaxed);
    if on {
        // SAFETY: stac only sets EFLAGS.AC. It is used only when SMAP is on,
        // which means the CPU supports the instruction.
        unsafe { core::arch::asm!("stac", options(nostack)) };
    }
    let r = f();
    if on {
        // SAFETY: clac closes the window opened above.
        unsafe { core::arch::asm!("clac", options(nostack)) };
    }
    r
}
