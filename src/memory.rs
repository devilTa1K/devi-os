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

// ---- Stage 9c: kernel stack guard pages ----
use core::sync::atomic::{AtomicU64, AtomicUsize};

const MAX_GUARDS: usize = 32;
static GUARDS: [AtomicU64; MAX_GUARDS] = [const { AtomicU64::new(0) }; MAX_GUARDS];
static GUARD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Unmap the 4 KB page at `addr` (inside the kernel heap) so any access to
/// it faults. Used as a guard page below a kernel stack.
pub fn guard_page(addr: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut guard = MANAGER.lock();
        let m = match guard.as_mut() {
            Some(m) => m,
            None => return,
        };
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
        // SAFETY: the page lies inside a heap buffer we own and never free
        // or touch again, so removing its mapping cannot break anything.
        let result = unsafe { m.mapper.unmap(page) };
        if let Ok((_frame, flush)) = result {
            flush.flush();
            let i = GUARD_COUNT.fetch_add(1, Ordering::Relaxed);
            if i < MAX_GUARDS {
                GUARDS[i].store(addr & !0xFFF, Ordering::Relaxed);
            }
        }
    });
}

/// True if `addr` lies inside a recorded guard page.
pub fn is_guard_address(addr: u64) -> bool {
    let n = GUARD_COUNT.load(Ordering::Relaxed).min(MAX_GUARDS);
    for i in 0..n {
        let g = GUARDS[i].load(Ordering::Relaxed);
        if addr >= g && addr < g + 4096 {
            return true;
        }
    }
    false
}

/// Show how many guard pages exist, on row 3.
pub fn show_guards() {
    let n = GUARD_COUNT.load(Ordering::Relaxed);
    crate::put_num(3, 60, n as u64, crate::WHITE);
    crate::put_str(3, 58, b"Guard pages:", crate::CYAN);
}

// ---- M1a: per-process address spaces ----
static KERNEL_P4: AtomicU64 = AtomicU64::new(0);
static SPACES: AtomicUsize = AtomicUsize::new(0);
/// The level-4 slot that holds all user memory (0x5555_0000_0000 >> 39).
const USER_P4_INDEX: usize = 170;

/// Remember the kernel's own level-4 table. Call once at boot, before any
/// process address space exists.
pub fn record_kernel_p4() {
    let (frame, _) = Cr3::read();
    KERNEL_P4.store(frame.start_address().as_u64(), Ordering::Relaxed);
}

/// Create a private address space: a copy of the kernel's top-level table
/// with the user-region slot left EMPTY. Kernel memory is shared (same
/// sub-tables); user memory exists only in the tree that maps it.
pub fn new_address_space() -> Option<PhysFrame> {
    let mut guard = MANAGER.lock();
    let m = guard.as_mut()?;
    let kernel_p4 = KERNEL_P4.load(Ordering::Relaxed);
    if kernel_p4 == 0 {
        return None;
    }
    let frame = m.frames.allocate_frame()?;
    let off = m.mapper.phys_offset();
    // SAFETY: both tables are 4 KB frames reachable through the kernel's
    // window onto physical memory. The new frame is fresh, so nothing else
    // uses it, and we only read the kernel's table.
    unsafe {
        let src = (off + kernel_p4).as_ptr::<PageTable>();
        let dst = (off + frame.start_address().as_u64()).as_mut_ptr::<PageTable>();
        (*dst).zero();
        for i in 0..512 {
            if i != USER_P4_INDEX {
                (&mut *dst)[i] = (&*src)[i].clone();
            }
        }
    }
    SPACES.fetch_add(1, Ordering::Relaxed);
    Some(frame)
}

/// Map one fresh, zeroed page at `addr` inside the address space `p4`, with
/// its FINAL permissions (writable XOR executable). Returns the frame so the
/// kernel can fill it through its own window.
pub fn map_user_in(p4: PhysFrame, addr: u64, writable: bool, executable: bool) -> Option<PhysFrame> {
    let mut guard = MANAGER.lock();
    let m = guard.as_mut()?;
    let off = m.mapper.phys_offset();
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
    let frame = m.frames.allocate_frame()?;

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    let parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    // SAFETY: the frame is fresh. We zero it through the kernel's own
    // window, then map it into the process tree `p4`, which is not the
    // active one, so no TLB flush is needed.
    unsafe {
        core::ptr::write_bytes((off + frame.start_address().as_u64()).as_mut_ptr::<u8>(), 0, 4096);
        let table = &mut *((off + p4.start_address().as_u64()).as_mut_ptr::<PageTable>());
        let mut mapper = OffsetPageTable::new(table, off);
        mapper
            .map_to_with_table_flags(page, frame, flags, parent, &mut m.frames)
            .ok()?
            .ignore();
    }
    Some(frame)
}

/// Copy bytes into a frame through the kernel's window onto physical memory.
pub fn copy_to_frame(frame: PhysFrame, offset: usize, bytes: &[u8]) {
    if offset > 4096 || bytes.len() > 4096 - offset {
        return;
    }
    let off = match MANAGER.lock().as_ref() {
        Some(m) => m.mapper.phys_offset(),
        None => return,
    };
    // SAFETY: the destination lies inside one frame we own; the bounds were
    // checked above; the source is a normal kernel slice.
    unsafe {
        let dst = (off + frame.start_address().as_u64() + offset as u64).as_mut_ptr::<u8>();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
    }
}

/// Load a thread's page-table root (0 = the kernel's own). Called by the
/// scheduler on every thread switch, with interrupts off.
pub fn switch_address_space(cr3: u64) {
    let target = if cr3 != 0 { cr3 } else { KERNEL_P4.load(Ordering::Relaxed) };
    if target == 0 {
        return;
    }
    let (current, _) = Cr3::read();
    if current.start_address().as_u64() == target {
        return;
    }
    let frame = PhysFrame::containing_address(PhysAddr::new(target));
    // SAFETY: `target` is either the kernel's own level-4 table or one built
    // by new_address_space, which contains every kernel mapping, so the code
    // and stacks we are running on stay mapped across the switch.
    unsafe {
        Cr3::write(frame, x86_64::registers::control::Cr3Flags::empty());
    }
}

/// Show how many private address spaces exist, on row 1.
pub fn show_spaces() {
    let n = SPACES.load(Ordering::Relaxed);
    crate::put_num(1, 14, n as u64, crate::WHITE);
    crate::put_str(1, 2, b"Address spaces:", crate::CYAN);
}


static SHARED_FRAME: AtomicU64 = AtomicU64::new(0);

/// Map ONE physical frame, shared by every caller, at `addr` inside the
/// address space whose level-4 table is at `p4_phys`. The page is writable
/// but never executable. This is a DELIBERATE hole in isolation, used only
/// by the negative control.
pub fn map_shared_in(p4_phys: u64, addr: u64) -> bool {
    if p4_phys == 0 || p4_phys == KERNEL_P4.load(Ordering::Relaxed) {
        return false;
    }
    let mut guard = MANAGER.lock();
    let m = match guard.as_mut() {
        Some(m) => m,
        None => return false,
    };
    let off = m.mapper.phys_offset();

    let mut fr = SHARED_FRAME.load(Ordering::Relaxed);
    if fr == 0 {
        let f = match m.frames.allocate_frame() {
            Some(f) => f,
            None => return false,
        };
        fr = f.start_address().as_u64();
        // SAFETY: the frame is fresh; we zero it through the kernel's window.
        unsafe {
            core::ptr::write_bytes((off + fr).as_mut_ptr::<u8>(), 0, 4096);
        }
        SHARED_FRAME.store(fr, Ordering::Relaxed);
    }

    let frame = PhysFrame::containing_address(PhysAddr::new(fr));
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    let parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    // SAFETY: p4_phys is a process table built by new_address_space (never
    // the kernel's own, checked above) and is not the active one.
    unsafe {
        let table = &mut *((off + p4_phys).as_mut_ptr::<PageTable>());
        let mut mapper = OffsetPageTable::new(table, off);
        match mapper.map_to_with_table_flags(page, frame, flags, parent, &mut m.frames) {
            Ok(flush) => {
                flush.ignore();
                true
            }
            Err(_) => false,
        }
    }
}


impl BootInfoFrameAllocator {
    /// How many usable frames have not been handed out yet.
    pub fn remaining(&self) -> usize {
        self.usable_frames().count().saturating_sub(self.next)
    }
}

/// How many usable physical frames are still unallocated.
pub fn frames_free() -> usize {
    let guard = MANAGER.lock();
    match guard.as_ref() {
        Some(m) => m.frames.remaining(),
        None => 0,
    }
}
