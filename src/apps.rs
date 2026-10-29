use crate::syscall::{syscall, SYS_PRINT};

/// App A: holds the PRINT capability and uses it.
pub extern "C" fn trusted_app() -> ! {
    let mut n: u64 = 0;
    loop {
        n += 1;
        if n % 500_000 == 0 {
            syscall(SYS_PRINT, b'#' as u64);
        }
    }
}

/// App B: holds no capabilities. It keeps trying NETWORK, FILES and PRINT
/// in turn (call numbers 1, 2, 3). Every attempt should be denied.
pub extern "C" fn untrusted_app() -> ! {
    let mut n: u64 = 0;
    let mut which: u64 = 0;
    loop {
        n += 1;
        if n % 500_000 == 0 {
            which = which % 3 + 1;
            syscall(which, b'X' as u64);
        }
    }
}
