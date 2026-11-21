use crate::audit;
use crate::auth;
use crate::fs;
use crate::syscall::{CAP_FILES, CAP_SECRET};
use crate::{put_char, put_str, CYAN, GRAY, INPUT_COL, INPUT_ROW, RED, WHITE};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

/// True while the shell is waiting for a passphrase (input is masked).
static AWAITING: AtomicBool = AtomicBool::new(false);
static FAILS: AtomicU32 = AtomicU32::new(0);
/// grant is locked until this tick count (about 18 ticks per second).
static LOCKED_UNTIL: AtomicU64 = AtomicU64::new(0);
const LOCKOUT_TICKS: u64 = 540;

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
            (if AWAITING.load(Ordering::Relaxed) { b'*' } else { buf[i] }, WHITE)
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
    if crate::input::handle(c) {
        return;
    }
    match c {
        '\n' => {
            let (line, len) = {
                let mut g = INPUT.lock();
                let copy = (g.0, g.1);
                g.1 = 0;
                g.0 = [0u8; MAX];
                copy
            };
            draw_input(&[0u8; MAX], 0);
            if AWAITING.swap(false, Ordering::Relaxed) {
                crate::input::leave_passphrase();
                finish_grant(&line[..len]);
            } else {
                run(&line[..len]);
            }
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
        b"run" => run_program(arg),
        b"mem" => mem_command(),
        b"mem2" => mem2_command(),
        b"kill" => kill_command(arg),
        b"threads" => threads_command(),
        b"stress" => stress_command(arg),
        b"loadfail" => {
            crate::loader::inject_failure(2);
            run_program(b"helloelf");
        }
        b"export" => {
            audit::export_all();
            out(b"audit log re-sent to", GREEN);
            out(b"COM1 (serial.log)", GRAY);
        }
        b"forge" => {
            audit::forge();
            out(b"log forged AND rehashed", RED);
            out(b"in-kernel check: green", RED);
            out(b"run export; host will see", GRAY);
        }
        b"clear" => {}
        _ => {
            out(b"unknown command", RED);
            out(b"type help", GRAY);
        }
    }
}

fn help() {
    out(b"ls cat log caps run <prog>", WHITE);
    out(b"grant|revoke secret", WHITE);
    out(b"tamper repair export forge", WHITE);
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
        begin_grant();
        return;
        
        
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












/// `grant secret` starts here: ask for the passphrase, unless locked out.
fn begin_grant() {
    let now = crate::interrupts::ticks();
    if now < LOCKED_UNTIL.load(Ordering::Relaxed) {
        out(b"grant is locked, wait", RED);
        out(b"(about 30 s after 3 fails)", GRAY);
        return;
    }
    if !crate::input::enter_passphrase() {
        out(b"keyboard busy", RED);
        return;
    }
    AWAITING.store(true, Ordering::Relaxed);
    out(b"enter passphrase + Enter", CYAN);
    out(b"(masked, empty = cancel)", GRAY);
}

/// Called with the typed passphrase when Enter is pressed in passphrase mode.
fn finish_grant(pass: &[u8]) {
    clear_output();
    if pass.is_empty() {
        out(b"grant cancelled", GRAY);
        return;
    }
    if auth::verify(pass) {
        FAILS.store(0, Ordering::Relaxed);
        SHELL_CAPS.fetch_or(CAP_SECRET, Ordering::Relaxed);
        audit::record(audit::GRANT, 0, CAP_SECRET as u64);
        out(b"SECRET granted", GREEN);
        out(b"(logged to audit)", GRAY);
    } else {
        let n = FAILS.fetch_add(1, Ordering::Relaxed) + 1;
        audit::record(audit::AUTH_FAIL, 0, n as u64);
        out(b"wrong passphrase", RED);
        if n >= 3 {
            FAILS.store(0, Ordering::Relaxed);
            LOCKED_UNTIL.store(crate::interrupts::ticks() + LOCKOUT_TICKS, Ordering::Relaxed);
            out(b"3 fails: grant locked", RED);
            out(b"for about 30 seconds", GRAY);
        } else {
            out(b"(logged to audit)", GRAY);
        }
    }
}



/// Programs started with `run` cannot exit or be freed yet (M1e), so only a
/// few may be started per boot.
static RUNS: AtomicU32 = AtomicU32::new(0);
const MAX_RUNS: u32 = 6;

fn run_program(arg: &[u8]) {
    if arg.is_empty() {
        out(b"usage: run <program>", GRAY);
        out(b"hello badwrite helloelf", GRAY);
        out(b"data rotest nxtest exittest", GRAY);
        out(b"echo snoop", GRAY);
        return;
    }
    let p = match crate::programs::find(arg) {
        Some(p) => p,
        None => {
            out(b"no such program", RED);
            return;
        }
    };
    if let Err(why) = crate::scheduler::admission() {
        out(b"cannot start program:", RED);
        out(why, GRAY);
        return;
    }
    if crate::programs::run(p) {
        out(b"started in ring 3", CYAN);
        crate::input::set_foreground(crate::scheduler::last_thread_id());
    } else {
        out(b"could not start program", RED);
    }
}

/// Output from a user program (SYS_WRITE). The prefix is chosen by the
/// kernel, not by the program, and only printable ASCII is kept.
pub fn program_out(tid: usize, msg: &[u8]) {
    let mut line = [b' '; OUT_WIDTH];
    line[0] = b't';
    let mut i = 1;
    if tid >= 10 {
        line[i] = b'0' + (tid / 10 % 10) as u8;
        i += 1;
    }
    line[i] = b'0' + (tid % 10) as u8;
    i += 1;
    line[i] = b':';
    i += 2;
    for &b in msg {
        if i >= OUT_WIDTH {
            break;
        }
        line[i] = if (0x20..0x7f).contains(&b) { b } else { b'.' };
        i += 1;
    }
    out(&line, CYAN);
}



/// Report why a program could not be started.
pub fn note_error(msg: &[u8]) {
    out(b"program rejected:", RED);
    out(msg, RED);
}



/// Redraw the shell's own input line (used when the keyboard returns to it).
pub fn redraw_input() {
    let g = INPUT.lock();
    draw_input(&g.0, g.1);
}






/// A line made of a label and a number, for the `mem` command.
fn label_num(label: &[u8], n: u64) -> [u8; OUT_WIDTH] {
    let mut line = [b' '; OUT_WIDTH];
    let mut i = 0usize;
    for &b in label {
        if i < OUT_WIDTH {
            line[i] = b;
            i += 1;
        }
    }
    let mut digits = [0u8; 20];
    let mut d = digits.len();
    let mut v = n;
    if v == 0 {
        d -= 1;
        digits[d] = b'0';
    }
    while v > 0 {
        d -= 1;
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for &b in &digits[d..] {
        if i < OUT_WIDTH {
            line[i] = b;
            i += 1;
        }
    }
    line
}

/// `mem`: where the memory stands. Used to check that nothing leaks.
fn mem_command() {
    out(&label_num(b"frames free: ", crate::memory::frames_free() as u64), WHITE);
    out(&label_num(b"frames freed: ", crate::memory::frames_freed_total()), WHITE);
    out(&label_num(b"frees refused: ", crate::memory::frees_refused()), WHITE);
    out(&label_num(b"heap free: ", crate::allocator::heap_free() as u64), WHITE);
}


/// `mem2`: teardown and loader statistics.
fn mem2_command() {
    out(&label_num(b"spaces freed: ", crate::memory::spaces_destroyed()), WHITE);
    out(&label_num(b"teardown anomalies: ", crate::memory::teardown_anomalies()), WHITE);
    out(&label_num(b"frames lost: ", crate::loader::lost() as u64), WHITE);
    out(&label_num(b"reap failures: ", crate::scheduler::reap_failures()), WHITE);
}


/// `kill <n>`: end one user program from the console.
fn kill_command(arg: &[u8]) {
    let mut n: usize = 0;
    let mut ok = !arg.is_empty();
    for &b in arg {
        if b.is_ascii_digit() && n < 1000 {
            n = n * 10 + (b - b'0') as usize;
        } else {
            ok = false;
            break;
        }
    }
    if !ok {
        out(b"usage: kill <thread>", GRAY);
        return;
    }
    if crate::scheduler::kill_thread(n) {
        audit::record(audit::KILL, n as u8, 18);
        crate::input::release(n);
        out(&label_num(b"ended thread ", n as u64), WHITE);
        out(b"(memory is reclaimed soon)", GRAY);
    } else {
        out(b"cannot end that thread", RED);
        out(b"(kernel, dead or unknown)", GRAY);
    }
}

/// `threads`: how many threads exist, how many are alive, how many were reaped.
fn threads_command() {
    let (total, live) = crate::scheduler::thread_stats();
    out(&label_num(b"threads started: ", total as u64), WHITE);
    out(&label_num(b"threads alive: ", live as u64), WHITE);
    out(&label_num(b"reaped: ", crate::scheduler::reaped_total()), WHITE);
    out(&label_num(b"stack pool: ", crate::scheduler::pool_len() as u64), WHITE);
}

/// `stress <program> <n>`: start a program n times, one at a time, waiting for
/// each to end and be reaped. A leak test: use it with programs that end
/// themselves (exittest) or are killed (rotest).
fn stress_command(arg: &[u8]) {
    let mut sp = arg.len();
    for (i, &b) in arg.iter().enumerate() {
        if b == b' ' {
            sp = i;
            break;
        }
    }
    if sp == arg.len() {
        out(b"usage: stress <prog> <n>", GRAY);
        return;
    }
    let name = &arg[..sp];
    let mut count: u32 = 0;
    for &b in &arg[sp + 1..] {
        if b.is_ascii_digit() && count < 1000 {
            count = count * 10 + (b - b'0') as u32;
        } else if b != b' ' {
            out(b"usage: stress <prog> <n>", GRAY);
            return;
        }
    }
    if count == 0 || count > 200 {
        out(b"n must be 1 to 200", GRAY);
        return;
    }
    let p = match crate::programs::find(name) {
        Some(p) => p,
        None => {
            out(b"no such program", RED);
            return;
        }
    };

    let mut done = 0u32;
    while done < count {
        if let Err(why) = crate::scheduler::admission() {
            clear_output();
            out(why, RED);
            break;
        }
        if !crate::programs::run(p) {
            clear_output();
            out(b"start failed", RED);
            break;
        }
        let tid = crate::scheduler::last_thread_id();
        // Wait (about 80 seconds at most) for it to end and be reaped.
        let mut waited = 0u32;
        loop {
            crate::scheduler::reap_pending();
            if crate::scheduler::is_reaped(tid) {
                break;
            }
            if waited > 1500 {
                clear_output();
                out(b"stuck: never reaped", RED);
                out(&label_num(b"thread ", tid as u64), WHITE);
                return;
            }
            x86_64::instructions::hlt();
            waited += 1;
        }
        done += 1;
    }
    clear_output();
    out(&label_num(b"stress cycles done: ", done as u64), WHITE);
}





