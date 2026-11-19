//! Who receives the keyboard (M1d-2). The kernel owns this decision and a
//! program never chooses. Rules:
//!  * The shell owns the keyboard by default.
//!  * A program may take it for ONE line, and only if it is the foreground
//!    program (the one most recently started with `run`), holds the INPUT
//!    capability, and the shell is not in passphrase mode.
//!  * Taking the keyboard and entering passphrase mode are each a single
//!    atomic compare-and-swap on OWNER, so they can never overlap.
//!  * Esc is handled here, before any program can see it. It always returns
//!    the keyboard to the shell, cancels the program's wait, and ends its
//!    foreground status.

use crate::{put_char, put_str, CYAN, GRAY, INPUT_COL, INPUT_ROW, RED, WHITE};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

const SHELL: usize = usize::MAX;
const PASSPHRASE: usize = usize::MAX - 1;
const NONE: usize = usize::MAX - 2;

const IDLE: u8 = 0;
const COLLECTING: u8 = 1;
const READY: u8 = 2;
const ABORTED: u8 = 3;

struct Buf {
    data: [u8; 64],
    len: usize,
    state: u8,
}

static BUF: Mutex<Buf> = Mutex::new(Buf { data: [0; 64], len: 0, state: IDLE });
/// SHELL, PASSPHRASE, or the thread number of the program that owns the keyboard.
static OWNER: AtomicUsize = AtomicUsize::new(SHELL);
/// The thread most recently started with `run` (NONE after Esc).
static FOREGROUND: AtomicUsize = AtomicUsize::new(NONE);
/// The thread that is waiting for a line (NONE if nobody is).
static READER: AtomicUsize = AtomicUsize::new(NONE);
static KEYS_SHELL: AtomicU64 = AtomicU64::new(0);
static KEYS_PROG: AtomicU64 = AtomicU64::new(0);

pub enum ReadResult {
    Line(usize),
    Cancelled,
}

pub fn init() {
    draw_indicator();
    draw_counters();
}

/// Called by the shell when it starts a program.
pub fn set_foreground(tid: usize) {
    FOREGROUND.store(tid, Ordering::SeqCst);
}

/// The shell wants a passphrase. Fails if a program owns the keyboard.
pub fn enter_passphrase() -> bool {
    let ok = OWNER
        .compare_exchange(SHELL, PASSPHRASE, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if ok {
        crate::audit::record(crate::audit::FOCUS, 0, 5);
    }
    draw_indicator();
    ok
}

pub fn leave_passphrase() {
    if OWNER
        .compare_exchange(PASSPHRASE, SHELL, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        crate::audit::record(crate::audit::FOCUS, 0, 6);
    }
    draw_indicator();
}

/// A program asks for the keyboard. Granted only to the foreground program,
/// only while the shell owns the keyboard in normal mode, and only if no
/// earlier read is still waiting to be collected.
pub fn begin_read(tid: usize) -> bool {
    if tid >= NONE || FOREGROUND.load(Ordering::SeqCst) != tid {
        return false;
    }
    let ok = without_interrupts(|| {
        let mut b = BUF.lock();
        if READER.load(Ordering::SeqCst) != NONE {
            return false;
        }
        if OWNER
            .compare_exchange(SHELL, tid, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        b.data = [0; 64];
        b.len = 0;
        b.state = COLLECTING;
        READER.store(tid, Ordering::SeqCst);
        crate::audit::record(crate::audit::FOCUS, tid as u8, 1);
        true
    });
    if ok {
        draw_indicator();
        draw_prog_line();
    }
    ok
}

/// The waiting program checks whether its line is ready.
pub fn poll(tid: usize, out: &mut [u8; 64]) -> Option<ReadResult> {
    without_interrupts(|| {
        let b = &mut *BUF.lock();
        if READER.load(Ordering::SeqCst) != tid {
            return Some(ReadResult::Cancelled);
        }
        match b.state {
            READY => {
                *out = b.data;
                let n = b.len;
                b.state = IDLE;
                READER.store(NONE, Ordering::SeqCst);
                Some(ReadResult::Line(n))
            }
            ABORTED => {
                b.state = IDLE;
                READER.store(NONE, Ordering::SeqCst);
                Some(ReadResult::Cancelled)
            }
            _ => None,
        }
    })
}

/// Called by the shell for every key, first. Returns true if the key was
/// consumed here (Esc, or a key for a program).
pub fn handle(c: char) -> bool {
    if c == '\u{1b}' {
        escape();
        return true;
    }
    let owner = OWNER.load(Ordering::SeqCst);
    if owner == SHELL || owner == PASSPHRASE {
        KEYS_SHELL.fetch_add(1, Ordering::Relaxed);
        draw_counters();
        return false;
    }

    // A program owns the keyboard: collect its line.
    KEYS_PROG.fetch_add(1, Ordering::Relaxed);
    let mut finished = false;
    without_interrupts(|| {
        let b = &mut *BUF.lock();
        if b.state != COLLECTING {
            return;
        }
        match c {
            '\n' => {
                b.state = READY;
                finished = true;
            }
            '\u{8}' => {
                if b.len > 0 {
                    b.len -= 1;
                    let l = b.len;
                    b.data[l] = 0;
                }
            }
            c if c.is_ascii() && !c.is_ascii_control() => {
                if b.len < 64 {
                    let l = b.len;
                    b.data[l] = c as u8;
                    b.len = l + 1;
                }
            }
            _ => {}
        }
    });
    if finished {
        // One line per read: the keyboard goes back to the shell at once.
        OWNER.store(SHELL, Ordering::SeqCst);
        crate::audit::record(crate::audit::FOCUS, owner as u8, 2);
        restore_shell_display();
        draw_indicator();
    } else {
        draw_prog_line();
    }
    draw_counters();
    true
}

/// Esc: always returns the keyboard to the shell and ends foreground status.
fn escape() {
    let fg = FOREGROUND.swap(NONE, Ordering::SeqCst);
    let owner0 = OWNER.load(Ordering::SeqCst);
    if fg != NONE && (owner0 == SHELL || owner0 == PASSPHRASE) {
        crate::audit::record(crate::audit::FOCUS, fg as u8, 4);
    }
    let owner = OWNER.load(Ordering::SeqCst);
    if owner != SHELL && owner != PASSPHRASE {
        without_interrupts(|| {
            let b = &mut *BUF.lock();
            if b.state == COLLECTING {
                b.state = ABORTED;
            }
        });
        let _ = OWNER.compare_exchange(owner, SHELL, Ordering::SeqCst, Ordering::SeqCst);
        crate::audit::record(crate::audit::FOCUS, owner as u8, 3);
        restore_shell_display();
    }
    draw_indicator();
}

// ---- display ----

fn push(line: &mut [u8; 56], n: &mut usize, s: &[u8]) {
    for &b in s {
        if *n < line.len() {
            line[*n] = b;
            *n += 1;
        }
    }
}

/// Row 21: who owns the keyboard right now. Drawn only by the kernel.
fn draw_indicator() {
    let owner = OWNER.load(Ordering::SeqCst);
    let mut line = [b' '; 56];
    let mut n = 0usize;
    let color;
    if owner == SHELL {
        push(&mut line, &mut n, b"Input: SHELL  (Esc always returns here)");
        color = CYAN;
    } else if owner == PASSPHRASE {
        push(&mut line, &mut n, b"Input: SHELL - PASSPHRASE MODE (programs locked out)");
        color = RED;
    } else {
        push(&mut line, &mut n, b"Input: PROGRAM t");
        if owner >= 10 {
            push(&mut line, &mut n, &[b'0' + (owner / 10 % 10) as u8]);
        }
        push(&mut line, &mut n, &[b'0' + (owner % 10) as u8]);
        push(&mut line, &mut n, b"  (Esc = back to shell)");
        color = RED;
    }
    put_str(21, 2, &line, color);
}

/// While a program owns the keyboard, show what is typed on the input row,
/// with a different prompt so it cannot be mistaken for the shell.
fn draw_prog_line() {
    let (data, len) = without_interrupts(|| {
        let b = BUF.lock();
        (b.data, b.len)
    });
    put_char(INPUT_ROW, 2, b'<', RED);
    for i in 0..64 {
        let (ch, col) = if i < len {
            (data[i], WHITE)
        } else if i == len {
            (b'_', CYAN)
        } else {
            (b' ', WHITE)
        };
        put_char(INPUT_ROW, INPUT_COL + i, ch, col);
    }
}

fn restore_shell_display() {
    put_char(INPUT_ROW, 2, b'>', RED);
    crate::shell::redraw_input();
}

fn put_left(row: usize, col: usize, mut n: u64, color: u8) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    put_str(row, col, &buf[i..], color);
}

/// Row 2, right side: how many keys went to the shell and to programs.
fn draw_counters() {
    put_str(2, 42, b"Keys: shell ", GRAY);
    put_left(2, 54, KEYS_SHELL.load(Ordering::Relaxed), WHITE);
    put_str(2, 62, b"program ", GRAY);
    put_left(2, 70, KEYS_PROG.load(Ordering::Relaxed), WHITE);
}






