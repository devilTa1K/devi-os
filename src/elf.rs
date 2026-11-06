#![allow(dead_code)]
//! A strict ELF64 validator. Everything in the file is untrusted input, so
//! every offset and size is bounds-checked with overflow-safe arithmetic.
//! This step only VALIDATES and returns a plan. Loading comes next (M1c-2).

use alloc::vec::Vec;

pub const MAX_IMAGE: usize = 64 * 1024;
pub const MAX_SEGS: usize = 4;
pub const MAX_PAGES: u64 = 16;
/// The only virtual range a program may occupy.
pub const USER_LOW: u64 = 0x5555_1000_0000;
pub const USER_HIGH: u64 = 0x5555_1100_0000;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

#[derive(Clone, Copy)]
pub struct Segment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

pub struct Plan {
    pub entry: u64,
    pub segs: [Segment; MAX_SEGS],
    pub count: usize,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfError {
    TooSmall,
    TooLarge,
    Magic,
    Class,
    Endian,
    IdentVersion,
    Type,
    Machine,
    Version,
    HeaderSize,
    PhEntSize,
    PhNum,
    PhRange,
    SegType,
    SegFlags,
    WriteExec,
    NoRead,
    Size,
    Align,
    Range,
    Overlap,
    Bounds,
    TooManySegs,
    TooManyPages,
    NoLoad,
    Entry,
    StackExec,
}

impl ElfError {
    pub fn name(self) -> &'static [u8] {
        match self {
            ElfError::TooSmall => b"too small",
            ElfError::TooLarge => b"too large",
            ElfError::Magic => b"magic",
            ElfError::Class => b"class",
            ElfError::Endian => b"endian",
            ElfError::IdentVersion => b"ident ver",
            ElfError::Type => b"type",
            ElfError::Machine => b"machine",
            ElfError::Version => b"version",
            ElfError::HeaderSize => b"ehsize",
            ElfError::PhEntSize => b"phentsize",
            ElfError::PhNum => b"phnum",
            ElfError::PhRange => b"phrange",
            ElfError::SegType => b"segtype",
            ElfError::SegFlags => b"segflags",
            ElfError::WriteExec => b"write+exec",
            ElfError::NoRead => b"no read",
            ElfError::Size => b"size",
            ElfError::Align => b"align",
            ElfError::Range => b"range",
            ElfError::Overlap => b"overlap",
            ElfError::Bounds => b"bounds",
            ElfError::TooManySegs => b"too many",
            ElfError::TooManyPages => b"too pages",
            ElfError::NoLoad => b"no load",
            ElfError::Entry => b"entry",
            ElfError::StackExec => b"stack exec",
        }
    }
}

fn rd_u16(b: &[u8], o: usize) -> Result<u16, ElfError> {
    let end = o.checked_add(2).ok_or(ElfError::TooSmall)?;
    let s = b.get(o..end).ok_or(ElfError::TooSmall)?;
    Ok(u16::from_le_bytes(s.try_into().map_err(|_| ElfError::TooSmall)?))
}

fn rd_u32(b: &[u8], o: usize) -> Result<u32, ElfError> {
    let end = o.checked_add(4).ok_or(ElfError::TooSmall)?;
    let s = b.get(o..end).ok_or(ElfError::TooSmall)?;
    Ok(u32::from_le_bytes(s.try_into().map_err(|_| ElfError::TooSmall)?))
}

fn rd_u64(b: &[u8], o: usize) -> Result<u64, ElfError> {
    let end = o.checked_add(8).ok_or(ElfError::TooSmall)?;
    let s = b.get(o..end).ok_or(ElfError::TooSmall)?;
    Ok(u64::from_le_bytes(s.try_into().map_err(|_| ElfError::TooSmall)?))
}

/// Validate an ELF image. Returns a loading plan, or the first rule it breaks.
pub fn parse(img: &[u8]) -> Result<Plan, ElfError> {
    if img.len() < 64 {
        return Err(ElfError::TooSmall);
    }
    if img.len() > MAX_IMAGE {
        return Err(ElfError::TooLarge);
    }
    if img[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::Magic);
    }
    if img[4] != 2 {
        return Err(ElfError::Class);
    }
    if img[5] != 1 {
        return Err(ElfError::Endian);
    }
    if img[6] != 1 {
        return Err(ElfError::IdentVersion);
    }
    if rd_u16(img, 16)? != 2 {
        return Err(ElfError::Type);
    }
    if rd_u16(img, 18)? != 62 {
        return Err(ElfError::Machine);
    }
    if rd_u32(img, 20)? != 1 {
        return Err(ElfError::Version);
    }
    let entry = rd_u64(img, 24)?;
    let phoff = rd_u64(img, 32)?;
    if rd_u16(img, 52)? != 64 {
        return Err(ElfError::HeaderSize);
    }
    if rd_u16(img, 54)? != 56 {
        return Err(ElfError::PhEntSize);
    }
    let phnum = rd_u16(img, 56)? as usize;
    if phnum == 0 || phnum > 8 {
        return Err(ElfError::PhNum);
    }
    let table_end = phoff
        .checked_add(phnum as u64 * 56)
        .ok_or(ElfError::PhRange)?;
    if phoff < 64 || table_end > img.len() as u64 {
        return Err(ElfError::PhRange);
    }

    let zero = Segment { vaddr: 0, offset: 0, filesz: 0, memsz: 0, flags: 0 };
    let mut segs = [zero; MAX_SEGS];
    let mut count = 0usize;
    let mut pages = 0u64;

    for i in 0..phnum {
        let o = phoff as usize + i * 56;
        let ptype = rd_u32(img, o)?;
        let flags = rd_u32(img, o + 4)?;
        match ptype {
            // null, note, phdr, eh_frame hint, relro: nothing to load
            0 | 4 | 6 | 0x6474_e550 | 0x6474_e552 => continue,
            // stack: must not ask for an executable stack
            0x6474_e551 => {
                if flags & PF_X != 0 {
                    return Err(ElfError::StackExec);
                }
                continue;
            }
            1 => {}
            // interp, dynamic, shlib, tls and anything unknown
            _ => return Err(ElfError::SegType),
        }

        let offset = rd_u64(img, o + 8)?;
        let vaddr = rd_u64(img, o + 16)?;
        let filesz = rd_u64(img, o + 32)?;
        let memsz = rd_u64(img, o + 40)?;

        if flags & !(PF_R | PF_W | PF_X) != 0 {
            return Err(ElfError::SegFlags);
        }
        if flags & PF_R == 0 {
            return Err(ElfError::NoRead);
        }
        if flags & PF_W != 0 && flags & PF_X != 0 {
            return Err(ElfError::WriteExec);
        }
        if memsz == 0 || filesz > memsz {
            return Err(ElfError::Size);
        }
        if vaddr & 0xFFF != 0 {
            return Err(ElfError::Align);
        }
        let vend = vaddr.checked_add(memsz).ok_or(ElfError::Range)?;
        if vaddr < USER_LOW || vend > USER_HIGH {
            return Err(ElfError::Range);
        }
        let fend = offset.checked_add(filesz).ok_or(ElfError::Bounds)?;
        if fend > img.len() as u64 {
            return Err(ElfError::Bounds);
        }
        if count == MAX_SEGS {
            return Err(ElfError::TooManySegs);
        }

        // memsz is at most 16 MB here (the range check above), so no overflow.
        let npages = (memsz + 0xFFF) >> 12;
        let start_pg = vaddr >> 12;
        let end_pg = start_pg + npages;
        for s in &segs[..count] {
            let sp = s.vaddr >> 12;
            let ep = sp + ((s.memsz + 0xFFF) >> 12);
            if start_pg < ep && sp < end_pg {
                return Err(ElfError::Overlap);
            }
        }
        pages += npages;
        if pages > MAX_PAGES {
            return Err(ElfError::TooManyPages);
        }
        segs[count] = Segment { vaddr, offset, filesz, memsz, flags };
        count += 1;
    }

    if count == 0 {
        return Err(ElfError::NoLoad);
    }
    let mut entry_ok = false;
    for s in &segs[..count] {
        if s.flags & PF_X != 0 && entry >= s.vaddr && entry < s.vaddr + s.memsz {
            entry_ok = true;
        }
    }
    if !entry_ok {
        return Err(ElfError::Entry);
    }
    Ok(Plan { entry, segs, count })
}

// ---- boot-time self-test ----

static SAMPLE: &[u8] = include_bytes!("../user/hello/hello_seg.elf");

struct Layout {
    phoff: usize,
    phnum: usize,
    a: usize,
    b: Option<usize>,
}

fn layout(img: &[u8]) -> Option<Layout> {
    let phoff = rd_u64(img, 32).ok()? as usize;
    let phnum = rd_u16(img, 56).ok()? as usize;
    let mut first = None;
    let mut second = None;
    for i in 0..phnum {
        let o = phoff + i * 56;
        if rd_u32(img, o).ok()? == 1 {
            if first.is_none() {
                first = Some(o);
            } else if second.is_none() {
                second = Some(o);
            }
        }
    }
    Some(Layout { phoff, phnum, a: first?, b: second })
}

fn put_u16(v: &mut [u8], o: usize, x: u16) {
    if let Some(s) = v.get_mut(o..o + 2) {
        s.copy_from_slice(&x.to_le_bytes());
    }
}
fn put_u32(v: &mut [u8], o: usize, x: u32) {
    if let Some(s) = v.get_mut(o..o + 4) {
        s.copy_from_slice(&x.to_le_bytes());
    }
}
fn put_u64(v: &mut [u8], o: usize, x: u64) {
    if let Some(s) = v.get_mut(o..o + 8) {
        s.copy_from_slice(&x.to_le_bytes());
    }
}
fn get_u32(v: &[u8], o: usize) -> u32 {
    rd_u32(v, o).unwrap_or(0)
}
fn get_u64(v: &[u8], o: usize) -> u64 {
    rd_u64(v, o).unwrap_or(0)
}

fn show(color: u8, line: &[u8]) {
    crate::put_str(1, 28, line, color);
}

/// Validate the real program (it must be accepted), then 22 corrupted copies
/// of it (every one must be refused). The result is shown on row 1.
pub fn self_test() {
    if let Err(e) = parse(SAMPLE) {
        let msg = b"ELF check FAILED: valid image rejected: ";
        let mut line = [b' '; 50];
        line[..msg.len()].copy_from_slice(msg);
        let n = e.name();
        let k = if n.len() < 10 { n.len() } else { 10 };
        line[msg.len()..msg.len() + k].copy_from_slice(&n[..k]);
        show(crate::RED, &line);
        return;
    }
    let l = match layout(SAMPLE) {
        Some(l) => l,
        None => {
            show(crate::RED, b"ELF check FAILED: no loadable segment found   ");
            return;
        }
    };

    let muts: [(&[u8], fn(&mut Vec<u8>, &Layout) -> bool); 22] = [
        (b"truncated header", |v, _| { v.truncate(40); true }),
        (b"truncated phdrs", |v, l| { v.truncate(l.phoff + 20); true }),
        (b"bad magic", |v, _| { v[0] = 0; true }),
        (b"32-bit class", |v, _| { v[4] = 1; true }),
        (b"big endian", |v, _| { v[5] = 2; true }),
        (b"not ET_EXEC", |v, _| { put_u16(v, 16, 3); true }),
        (b"wrong machine", |v, _| { put_u16(v, 18, 3); true }),
        (b"zero phnum", |v, _| { put_u16(v, 56, 0); true }),
        (b"huge phnum", |v, _| { put_u16(v, 56, 0xFFFF); true }),
        (b"phoff overflow", |v, _| { put_u64(v, 32, u64::MAX - 16); true }),
        (b"RWX segment", |v, l| { put_u32(v, l.a + 4, 7); true }),
        (b"filesz > memsz", |v, l| {
            let m = get_u64(v, l.a + 40);
            put_u64(v, l.a + 32, m + 1);
            true
        }),
        (b"kernel address", |v, l| { put_u64(v, l.a + 16, 0xFFFF_8000_0000_0000); true }),
        (b"unaligned vaddr", |v, l| {
            let a = get_u64(v, l.a + 16);
            put_u64(v, l.a + 16, a + 1);
            true
        }),
        (b"offset past file", |v, l| { put_u64(v, l.a + 8, u64::MAX - 8); true }),
        (b"huge memsz", |v, l| { put_u64(v, l.a + 40, 1 << 40); true }),
        (b"entry outside", |v, _| { put_u64(v, 24, 0x1000); true }),
        (b"interp segment", |v, l| { put_u32(v, l.a, 3); true }),
        (b"overlap", |v, l| match l.b {
            Some(b) => {
                let a = get_u64(v, l.a + 16);
                put_u64(v, b + 16, a);
                true
            }
            None => false,
        }),
        (b"no loadable segment", |v, l| {
            for i in 0..l.phnum {
                let o = l.phoff + i * 56;
                if get_u32(v, o) == 1 {
                    put_u32(v, o, 0);
                }
            }
            true
        }),
        (b"no read flag", |v, l| { put_u32(v, l.a + 4, PF_X); true }),
        (b"junk flags", |v, l| { put_u32(v, l.a + 4, PF_R | 0x100); true }),
    ];

    let mut executed = 0usize;
    let mut refused = 0usize;
    let mut accepted: Option<&[u8]> = None;
    for (name, mutate) in muts.iter() {
        let mut v = SAMPLE.to_vec();
        if !mutate(&mut v, &l) {
            continue;
        }
        executed += 1;
        match parse(&v) {
            Err(_) => refused += 1,
            Ok(_) => {
                if accepted.is_none() {
                    accepted = Some(*name);
                }
            }
        }
    }

    if let Some(name) = accepted {
        let msg = b"ELF check FAILED: accepted ";
        let mut line = [b' '; 50];
        line[..msg.len()].copy_from_slice(msg);
        let k = if name.len() < 22 { name.len() } else { 22 };
        line[msg.len()..msg.len() + k].copy_from_slice(&name[..k]);
        show(crate::RED, &line);
        return;
    }

    let mut line = *b"ELF check: valid ok, 00/00 refused";
    line[21] = b'0' + (refused / 10 % 10) as u8;
    line[22] = b'0' + (refused % 10) as u8;
    line[24] = b'0' + (executed / 10 % 10) as u8;
    line[25] = b'0' + (executed % 10) as u8;
    show(crate::CYAN, &line);
}
