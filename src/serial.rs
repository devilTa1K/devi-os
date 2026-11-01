use x86_64::instructions::port::Port;

const COM1: u16 = 0x3F8;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Set up COM1 as 38400 baud, 8 data bits, no parity, 1 stop bit, FIFO on.
pub fn init() {
    // SAFETY: these are the standard 16550 UART registers of COM1. Writing
    // them only configures the serial port; it touches no memory.
    unsafe {
        Port::<u8>::new(COM1 + 1).write(0x00); // no interrupts
        Port::<u8>::new(COM1 + 3).write(0x80); // baud divisor latch on
        Port::<u8>::new(COM1).write(0x03); // divisor low byte
        Port::<u8>::new(COM1 + 1).write(0x00); // divisor high byte
        Port::<u8>::new(COM1 + 3).write(0x03); // 8N1, latch off
        Port::<u8>::new(COM1 + 2).write(0xC7); // FIFO on
        Port::<u8>::new(COM1 + 4).write(0x03); // DTR + RTS
    }
}

fn write_byte(b: u8) {
    let mut status: Port<u8> = Port::new(COM1 + 5);
    let mut data: Port<u8> = Port::new(COM1);
    for _ in 0..100_000 {
        // SAFETY: reading the line status register has no side effects, and
        // writing the data register only sends one byte out of the port.
        unsafe {
            if status.read() & 0x20 != 0 {
                data.write(b);
                return;
            }
        }
    }
    // The transmitter never became ready. Drop the byte instead of hanging
    // with interrupts off. The host verifier reports this as a gap.
}

fn write_bytes(s: &[u8]) {
    for &b in s {
        write_byte(b);
    }
}

fn write_dec(mut n: u64) {
    if n == 0 {
        write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    write_bytes(&buf[i..]);
}

fn write_hex(bytes: &[u8]) {
    for &b in bytes {
        write_byte(HEX[(b >> 4) as usize]);
        write_byte(HEX[(b & 0xF) as usize]);
    }
}

/// Send one audit entry as a text line:
/// TAG seq tick kind thread arg prev_hash hash
pub fn emit_line(
    tag: &[u8],
    seq: u64,
    tick: u64,
    kind: u8,
    thread: u8,
    arg: u64,
    prev: &[u8; 32],
    hash: &[u8; 32],
) {
    write_bytes(tag);
    write_byte(b' ');
    write_dec(seq);
    write_byte(b' ');
    write_dec(tick);
    write_byte(b' ');
    write_dec(kind as u64);
    write_byte(b' ');
    write_dec(thread as u64);
    write_byte(b' ');
    write_dec(arg);
    write_byte(b' ');
    write_hex(prev);
    write_byte(b' ');
    write_hex(hash);
    write_byte(b'\n');
}
