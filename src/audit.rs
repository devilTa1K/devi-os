use crate::{put_char, put_num, put_str, CYAN, GRAY, RED, WHITE};
use sha2::{Digest, Sha256};
use spin::Mutex;
use x86_64::instructions::interrupts;

const GREEN: u8 = 0x0A;

// Event kinds.
pub const BOOT: u8 = 1;
pub const START: u8 = 2;
pub const DENY: u8 = 3;
pub const KILL: u8 = 4;
pub const GRANT: u8 = 5;
pub const REVOKE: u8 = 6;

/// The log keeps the newest CAP entries (a ring). The hash chain still
/// links every entry to the one before it.
const CAP: usize = 64;

#[derive(Clone, Copy)]
struct Entry {
    seq: u64,
    tick: u64,
    kind: u8,
    thread: u8,
    arg: u64,
    prev: [u8; 32],
    hash: [u8; 32],
}

const EMPTY: Entry = Entry {
    seq: 0,
    tick: 0,
    kind: 0,
    thread: 0,
    arg: 0,
    prev: [0; 32],
    hash: [0; 32],
};

struct Log {
    entries: [Entry; CAP],
    /// Total entries ever appended.
    count: u64,
    /// Hash of the newest entry (the chain head).
    head: [u8; 32],
    /// Demo only: (seq, original arg) of the entry the `tamper` command changed.
    backup: Option<(u64, u64)>,
}

static LOG: Mutex<Log> = Mutex::new(Log {
    entries: [EMPTY; CAP],
    count: 0,
    head: [0; 32],
    backup: None,
});

/// Denial counters per (thread, syscall) so a flood cannot fill the log.
static DENY_COUNTS: Mutex<[[u32; 4]; 16]> = Mutex::new([[0; 4]; 16]);

/// hash = SHA-256(prev_hash || seq || tick || kind || thread || arg)
fn compute(prev: &[u8; 32], seq: u64, tick: u64, kind: u8, thread: u8, arg: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(seq.to_le_bytes());
    h.update(tick.to_le_bytes());
    h.update([kind, thread]);
    h.update(arg.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Append one entry. Only kernel code can call this; apps cannot.
pub fn record(kind: u8, thread: u8, arg: u64) {
    interrupts::without_interrupts(|| {
        let mut log = LOG.lock();
        let seq = log.count;
        let prev = log.head;
        let tick = crate::interrupts::ticks();
        let hash = compute(&prev, seq, tick, kind, thread, arg);
        log.entries[(seq % CAP as u64) as usize] = Entry { seq, tick, kind, thread, arg, prev, hash };
        log.head = hash;
        log.count = seq + 1;
    });
}

/// Log a denied syscall, but only the first one per (thread, call) and then
/// every 512th, so a flood of denials cannot push real evidence out.
pub fn record_denial(thread: usize, call: u64) {
    if call == 0 || call >= 4 {
        return;
    }
    let t = if thread > 15 { 15 } else { thread };
    let n = interrupts::without_interrupts(|| {
        let mut counts = DENY_COUNTS.lock();
        let slot = &mut counts[t][call as usize];
        *slot = slot.wrapping_add(1);
        *slot
    });
    if n == 1 || n % 512 == 0 {
        record(DENY, thread as u8, call);
    }
}

/// Walk the retained entries and recompute every hash. Returns
/// (true, entries_checked) or (false, first_bad_seq).
fn verify_locked(log: &Log) -> (bool, u64) {
    let n = if log.count < CAP as u64 { log.count } else { CAP as u64 };
    if n == 0 {
        return (true, 0);
    }
    let first = log.count - n;
    let mut expected = log.entries[(first % CAP as u64) as usize].prev;
    let mut s = first;
    while s < log.count {
        let e = &log.entries[(s % CAP as u64) as usize];
        if e.seq != s
            || e.prev != expected
            || compute(&e.prev, e.seq, e.tick, e.kind, e.thread, e.arg) != e.hash
        {
            return (false, s);
        }
        expected = e.hash;
        s += 1;
    }
    if expected != log.head {
        return (false, log.count - 1);
    }
    (true, n)
}

fn kind_name(k: u8) -> &'static [u8; 5] {
    match k {
        BOOT => b"BOOT ",
        START => b"START",
        DENY => b"DENY ",
        KILL => b"KILL ",
        GRANT => b"GRANT",
        REVOKE => b"REVOK",
        _ => b"???? ",
    }
}

fn arg_name(kind: u8, arg: u64) -> &'static [u8; 8] {
    match (kind, arg) {
        (DENY, 1) => b"PRINT   ",
        (DENY, 2) => b"NETWORK ",
        (DENY, 3) => b"FILES   ",
        (KILL, 14) => b"PGFAULT ",
        (KILL, 13) => b"GPFAULT ",
        (START, _) => b"RING 3  ",
        (BOOT, _) => b"        ",
        (GRANT, _) => b"SECRET  ",
        (REVOKE, _) => b"SECRET  ",
        _ => b"?       ",
    }
}

fn put_seq(row: usize, col: usize, seq: u64, color: u8) {
    let s = seq % 1000;
    put_char(row, col, b'#', color);
    put_char(row, col + 1, b'0' + (s / 100 % 10) as u8, color);
    put_char(row, col + 2, b'0' + (s / 10 % 10) as u8, color);
    put_char(row, col + 3, b'0' + (s % 10) as u8, color);
}

fn draw_entry(row: usize, e: &Entry) {
    let mut buf = [b' '; 22];
    let s = e.seq % 1000;
    buf[0] = b'#';
    buf[1] = b'0' + (s / 100 % 10) as u8;
    buf[2] = b'0' + (s / 10 % 10) as u8;
    buf[3] = b'0' + (s % 10) as u8;
    buf[5..10].copy_from_slice(kind_name(e.kind));
    buf[11] = b't';
    buf[12] = b'0' + e.thread % 10;
    buf[14..22].copy_from_slice(arg_name(e.kind, e.arg));
    let color = if e.kind == DENY || e.kind == KILL { RED } else { GRAY };
    put_str(row, 2, &buf, color);
}

pub fn draw_panel() {
    interrupts::without_interrupts(|| {
        let log = LOG.lock();
        let (ok, bad) = verify_locked(&log);

        put_str(14, 2, b"-- AUDIT LOG --", CYAN);
        put_str(15, 2, b"Entries:", GRAY);
        put_num(15, 11, log.count, WHITE);

        if ok {
            put_str(16, 2, b"Chain: VERIFIED      ", GREEN);
        } else {
            put_str(16, 2, b"Chain: BROKEN at ", RED);
            put_seq(16, 19, bad, RED);
        }

        const HEX: &[u8; 16] = b"0123456789abcdef";
        put_str(17, 2, b"Head: ", GRAY);
        for i in 0..4 {
            let b = log.head[i];
            put_char(17, 8 + i * 2, HEX[(b >> 4) as usize], WHITE);
            put_char(17, 9 + i * 2, HEX[(b & 0xF) as usize], WHITE);
        }

        // The three newest entries, oldest of the three first.
        let shown = if log.count < 3 { log.count } else { 3 };
        for i in 0..shown {
            let seq = log.count - shown + i;
            let e = &log.entries[(seq % CAP as u64) as usize];
            draw_entry(18 + i as usize, e);
        }
    });
}

pub fn init() {
    put_str(2, 2, b"Commands: type tamper (forge a log entry) or repair, then Enter", GRAY);
    record(BOOT, 0, 0);
    draw_panel();
}

/// A kernel thread that re-verifies the chain and redraws the panel.
pub extern "C" fn monitor() -> ! {
    let mut n: u64 = 0;
    loop {
        n += 1;
        if n % 3_000_000 == 0 {
            draw_panel();
        }
    }
}

fn read_cell(row: usize, col: usize) -> u8 {
    let offset = (row * crate::COLS + col) * 2;
    // SAFETY: callers pass cells inside the 80x25 text buffer (the input
    // line), which is mapped; we only read it.
    unsafe { crate::VGA.add(offset).read_volatile() }
}

/// Called when Enter is pressed. `len` is how many characters were typed.
pub fn handle_enter(len: usize) {
    if len == 0 || len > 16 {
        return;
    }
    let mut buf = [0u8; 16];
    for i in 0..len {
        buf[i] = read_cell(crate::INPUT_ROW, crate::INPUT_COL + i);
    }
    match &buf[..len] {
        b"tamper" => tamper(),
        b"repair" => repair(),
        _ => {}
    }
}

/// Demo: simulate an attacker editing the newest log entry in place.
pub fn tamper() {
    interrupts::without_interrupts(|| {
        let mut log = LOG.lock();
        if log.count == 0 || log.backup.is_some() {
            return;
        }
        let seq = log.count - 1;
        let idx = (seq % CAP as u64) as usize;
        let orig = log.entries[idx].arg;
        log.backup = Some((seq, orig));
        log.entries[idx].arg = orig ^ 1;
    });
}

/// Demo: undo the forged edit.
pub fn repair() {
    interrupts::without_interrupts(|| {
        let mut log = LOG.lock();
        if let Some((seq, orig)) = log.backup {
            let idx = (seq % CAP as u64) as usize;
            if log.entries[idx].seq == seq {
                log.entries[idx].arg = orig;
            }
            log.backup = None;
        }
    });
}

/// Format the n-th newest retained entry (0 = newest) as a 22-character
/// line. Returns the text and whether it is a security event (DENY or KILL).
pub fn newest_line(n: usize) -> Option<([u8; 22], bool)> {
    interrupts::without_interrupts(|| {
        let log = LOG.lock();
        if n >= CAP || (n as u64) >= log.count {
            return None;
        }
        let seq = log.count - 1 - n as u64;
        let e = &log.entries[(seq % CAP as u64) as usize];
        let mut buf = [b' '; 22];
        let s = e.seq % 1000;
        buf[0] = b'#';
        buf[1] = b'0' + (s / 100 % 10) as u8;
        buf[2] = b'0' + (s / 10 % 10) as u8;
        buf[3] = b'0' + (s % 10) as u8;
        buf[5..10].copy_from_slice(kind_name(e.kind));
        buf[11] = b't';
        buf[12] = b'0' + e.thread % 10;
        buf[14..22].copy_from_slice(arg_name(e.kind, e.arg));
        Some((buf, e.kind == DENY || e.kind == KILL))
    })
}





