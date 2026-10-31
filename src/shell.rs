use crate::audit;
use crate::fs;
use crate::syscall::{CAP_FILES, CAP_SECRET};
use crate::{put_char, put_str, CYAN, GRAY, INPUT_COL, INPUT_ROW, RED, WHITE};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use spin::Mutex;

const GREEN: u8 = 0x0A;
const MAX: usize = 64;

// Output window: rows 17..=20, columns 26..53.
const OUT_COL: usize = 26;
const OUT_WIDTH: usize = 27;
const OUT_FIRST: usize = 17;
const OUT_LAST: usize = 20;

static INPUT: Mutex<([u8; MAX], usize)> = Mutex::new(([0; MAX], 0));
static OUT_ROW: AtomicUsize = AtomicUsize::new(OUT_FIRST);

/// The console shell starts with FILES only. SECRET must be granted, and
/// every grant and revoke is written to the audit log.
static SHELL_CAPS: AtomicU32 = AtomicU32::new(CAP_FILES);

fn clear_output() {
    for r in OUT_FIRST..=OUT_LAST {
        for c in 0..OUT_WIDTH {
            put_char(r, OUT_COL + c, b' ', GRAY);
        }
    }
    OUT_ROW.store(OUT_FIRST, Ordering::Relaxed);
}

/// Print one line in the output window. Longer text is cut; only printable
/// ASCII is drawn, so file contents cannot inject odd characters.
fn out(s: &[u8], color: u8) {
    let row = OUT_ROW.load(Ordering::Relaxed);
    if row > OUT_LAST {
        return;
    }
    for c in 0..OUT_WIDTH {
        let ch = if c < s.len() && (0x20..0x7f).contains(&s[c]) { s[c] } else { b' ' };
        put_char(row, OUT_COL + c, ch, color);
    }
    OUT_ROW.store(row + 1, Ordering::Relaxed);
}

fn draw_input(buf: &[u8; MAX], len: usize) {
    for i in 0..MAX {
        let (ch, color) = if i < len {
            (buf[i], WHITE)
        } else if i == len {
            (b'_', CYAN)
        } else {
            (b' ', WHITE)
        };
        put_char(INPUT_ROW, INPUT_COL + i, ch, color);
    }
}

pub fn init() {
    // Replace the Stage 7 hint line and the old input label.
    for c in 2..78 {
        put_char(2, c, b' ', GRAY);
    }
    put_str(2, 2, b"Shell commands: help ls cat log caps", CYAN);
    put_str(21, 2, b"Shell: type help, then press Enter", GRAY);
    clear_output();
    put_char(17, 53, b' ', GRAY);
    for c in 53..=56 {
        put_char(18, c, b' ', GRAY);
    }
    out(b"shell ready. try: help", GREEN);
    let g = INPUT.lock();
    draw_input(&g.0, g.1);
}

/// Called by the keyboard task for every decoded character.
pub fn handle_char(c: char) {
    match c {
        '\n' => {
            let (line, len) = {
                let mut g = INPUT.lock();
                let copy = (g.0, g.1);
                g.1 = 0;
                copy
            };
            draw_input(&[0u8; MAX], 0);
            run(&line[..len]);
        }
        '\u{8}' => {
            let mut g = INPUT.lock();
            if g.1 > 0 {
                g.1 -= 1;
                let l = g.1;
                g.0[l] = 0;
            }
            draw_input(&g.0, g.1);
        }
        c if c.is_ascii() && !c.is_ascii_control() => {
            let mut g = INPUT.lock();
            if g.1 < MAX {
                let l = g.1;
                g.0[l] = c as u8;
                g.1 = l + 1;
            }
            draw_input(&g.0, g.1);
        }
        _ => {}
    }
}

fn run(line: &[u8]) {
    if line.is_empty() {
        return;
    }
    clear_output();

    // Split "command argument" at the first space.
    let mut split = line.len();
    for (i, &b) in line.iter().enumerate() {
        if b == b' ' {
            split = i;
            break;
        }
    }
    let cmd = &line[..split];
    let mut arg: &[u8] = if split < line.len() { &line[split + 1..] } else { &line[..0] };
    while !arg.is_empty() && arg[0] == b' ' {
        arg = &arg[1..];
    }

    match cmd {
        b"help" => help(),
        b"ls" => ls(),
        b"cat" => cat(arg),
        b"log" => show_log(),
        b"caps" => caps(),
        b"grant" => change_cap(arg, true),
        b"revoke" => change_cap(arg, false),
        b"tamper" => {
            audit::tamper();
            out(b"log entry forged (demo)", RED);
            out(b"watch the Chain line", GRAY);
        }
        b"repair" => {
            audit::repair();
            out(b"forged edit undone", GREEN);
        }
        b"smaptest" => smaptest(),
        b"overflow" => overflow(),
        b"clear" => {}
        _ => {
            out(b"unknown command", RED);
            out(b"type help", GRAY);
        }
    }
}

fn help() {
    out(b"ls  cat <file>  log  caps", WHITE);
    out(b"grant|revoke secret", WHITE);
    out(b"tamper repair clear help", WHITE);
    out(b"smaptest overflow: halt", RED);
}

fn ls() {
    let caps = SHELL_CAPS.load(Ordering::Relaxed);
    for i in 0..fs::count() {
        let (name, needs) = fs::info(i);
        let mut line = [b' '; OUT_WIDTH];
        let n = name.len().min(12);
        line[..n].copy_from_slice(&name[..n]);
        let tag: &[u8] = if needs == CAP_SECRET { b"SECRET" } else { b"FILES" };
        line[13..13 + tag.len()].copy_from_slice(tag);
        let can = caps & needs != 0;
        let flag: &[u8] = if can { b"ok" } else { b"no" };
        line[21..23].copy_from_slice(flag);
        out(&line, if can { WHITE } else { RED });
    }
}

fn cat(arg: &[u8]) {
    if arg.is_empty() {
        out(b"usage: cat <file>", GRAY);
        return;
    }
    let idx = match fs::find(arg) {
        Some(i) => i,
        None => {
            out(b"no such file", RED);
            return;
        }
    };

    // The same per-file capability rule that applies to apps.
    if SHELL_CAPS.load(Ordering::Relaxed) & fs::required_cap(idx) == 0 {
        fs::note_denied(0, idx);
        audit::record(audit::DENY, 0, 3);
        out(b"DENIED: missing capability", RED);
        out(b"(logged to audit)", GRAY);
        return;
    }

    let _ = fs::read(0, idx);
    let name = fs::info(idx as usize).0;
    let mut head = [b' '; OUT_WIDTH];
    head[0..3].copy_from_slice(b"-- ");
    let n = name.len().min(12);
    head[3..3 + n].copy_from_slice(&name[..n]);
    head[3 + n..6 + n].copy_from_slice(b" --");
    out(&head, CYAN);
    for chunk in fs::data(idx).chunks(OUT_WIDTH).take(2) {
        out(chunk, WHITE);
    }
}

fn show_log() {
    let mut any = false;
    for n in 0..4 {
        if let Some((line, security_event)) = audit::newest_line(n) {
            any = true;
            out(&line, if security_event { RED } else { GRAY });
        }
    }
    if !any {
        out(b"log is empty", GRAY);
    }
}

fn caps() {
    let c = SHELL_CAPS.load(Ordering::Relaxed);
    out(b"shell capabilities:", CYAN);
    let files: &[u8] = if c & CAP_FILES != 0 { b"FILES   yes" } else { b"FILES   no " };
    let secret: &[u8] = if c & CAP_SECRET != 0 { b"SECRET  yes" } else { b"SECRET  no " };
    out(files, WHITE);
    out(secret, WHITE);
}

fn change_cap(arg: &[u8], grant: bool) {
    if arg != &b"secret"[..] {
        out(b"usage: grant secret", GRAY);
        out(b"       revoke secret", GRAY);
        return;
    }
    if grant {
        SHELL_CAPS.fetch_or(CAP_SECRET, Ordering::Relaxed);
        audit::record(audit::GRANT, 0, CAP_SECRET as u64);
        out(b"SECRET granted", GREEN);
    } else {
        SHELL_CAPS.fetch_and(!CAP_SECRET, Ordering::Relaxed);
        audit::record(audit::REVOKE, 0, CAP_SECRET as u64);
        out(b"SECRET revoked", GREEN);
    }
    out(b"(logged to audit)", GRAY);
}




/// Deliberately make the kernel read user memory WITHOUT a stac/clac window.
/// With SMAP on, the CPU faults and the kernel halts. If SMAP is off, the
/// read succeeds and we say so.
fn smaptest() {
    out(b"kernel reads user memory", RED);
    out(b"with NO stac/clac window", RED);
    out(b"SMAP should HALT the box", GRAY);
    // SAFETY: deliberate. 0x5555_0000_0000 is a mapped user page, so the
    // read is valid unless SMAP stops it, which is what this test shows.
    let v = unsafe { core::ptr::read_volatile(0x5555_0000_0000usize as *const u8) };
    let _ = v;
    out(b"read succeeded: SMAP OFF", RED);
}

/// Recurses without end, using about 300 bytes of stack per call.
#[inline(never)]
fn recurse(depth: u64) -> u64 {
    let pad = [depth as u8; 256];
    core::hint::black_box(&pad);
    let r = recurse(depth + 1);
    core::hint::black_box(&pad);
    r.wrapping_add(depth)
}

extern "C" fn overflow_thread() -> ! {
    recurse(0);
    loop {}
}

/// Spawn a kernel thread that overflows its own stack. The guard page
/// should stop it, and the machine halts with a message.
fn overflow() {
    out(b"kernel thread recurses", RED);
    out(b"until its stack ends", RED);
    out(b"guard page should HALT", GRAY);
    crate::scheduler::spawn(overflow_thread, 0);
}


