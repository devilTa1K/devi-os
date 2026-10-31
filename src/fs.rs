use crate::syscall::{CAP_FILES, CAP_SECRET, UNKNOWN};
use crate::{put_str, CYAN, GRAY, RED, WHITE};

struct File {
    name: &'static [u8],
    /// Capability a caller must hold to read this file.
    needs: u32,
    data: &'static [u8],
}

static FILES: [File; 3] = [
    File { name: b"readme.txt", needs: CAP_FILES, data: b"DevilTalk: nothing is trusted by default." },
    File { name: b"notes.txt", needs: CAP_FILES, data: b"Every syscall is checked against capabilities." },
    File { name: b"secret.key", needs: CAP_SECRET, data: b"DEMO-KEY-NOT-A-REAL-SECRET" },
];

/// Capability needed for file `idx`. An invalid index falls back to FILES,
/// so a caller with no capabilities is denied before we say anything about
/// which files exist.
pub fn required_cap(idx: u64) -> u32 {
    if idx < FILES.len() as u64 {
        FILES[idx as usize].needs
    } else {
        CAP_FILES
    }
}

/// Read file `idx` for `thread`. The caller has already passed the
/// capability check. Returns the file length, or UNKNOWN for a bad index.
pub fn read(thread: usize, idx: u64) -> u64 {
    if idx >= FILES.len() as u64 {
        return UNKNOWN;
    }
    let f = &FILES[idx as usize];
    show_access(thread, f.name, true);
    f.data.len() as u64
}

/// Record on screen that `thread` was refused file `idx`.
pub fn note_denied(thread: usize, idx: u64) {
    if idx < FILES.len() as u64 {
        show_access(thread, FILES[idx as usize].name, false);
    }
}

fn show_access(thread: usize, name: &[u8], ok: bool) {
    let mut line = [b' '; 24];
    let prefix: &[u8; 5] = if ok { b"OK  t" } else { b"NO  t" };
    line[..5].copy_from_slice(prefix);
    line[5] = b'0' + (thread % 10) as u8;
    let n = if name.len() > 12 { 12 } else { name.len() };
    line[7..7 + n].copy_from_slice(&name[..n]);
    if ok {
        put_str(19, 54, &line, WHITE);
    } else {
        put_str(20, 54, &line, RED);
    }
}

pub fn init() {
    put_str(14, 54, b"-- FILES (read-only) --", CYAN);
    put_str(15, 54, b"readme.txt  needs FILES", GRAY);
    put_str(16, 54, b"notes.txt   needs FILES", GRAY);
    put_str(17, 54, b"secret.key  needs SECRET", GRAY);
}

/// Number of files in the store.
pub fn count() -> usize {
    FILES.len()
}

/// Find a file by exact name.
pub fn find(name: &[u8]) -> Option<u64> {
    for (i, f) in FILES.iter().enumerate() {
        if f.name == name {
            return Some(i as u64);
        }
    }
    None
}

/// Name and required capability of file `i`. The caller keeps i < count().
pub fn info(i: usize) -> (&'static [u8], u32) {
    (FILES[i].name, FILES[i].needs)
}

/// Contents of file `idx`, or an empty slice for a bad index.
pub fn data(idx: u64) -> &'static [u8] {
    if idx < FILES.len() as u64 {
        FILES[idx as usize].data
    } else {
        &[]
    }
}
