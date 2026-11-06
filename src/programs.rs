//! Programs compiled into the kernel image. Until there is a disk (M2),
//! "installing" a program means rebuilding the kernel with its binary.
//! Build the binaries first with build-user.ps1.

pub struct Program {
    pub name: &'static [u8],
    pub image: &'static [u8],
    pub caps: u32,
}

/// Where every program image is loaded inside its own address space. It must
/// match the address in user/hello/link.ld, and it must lie in the level-4
/// slot reserved for user memory.
pub const PROGRAM_BASE: u64 = 0x5555_1000_0000;

pub static PROGRAMS: [Program; 2] = [
    Program {
        name: b"hello",
        image: include_bytes!("../user/hello/hello.bin"),
        caps: crate::syscall::CAP_PRINT,
    },
    Program {
        name: b"badwrite",
        image: include_bytes!("../user/hello/badwrite.bin"),
        caps: crate::syscall::CAP_PRINT,
    },
];

pub fn find(name: &[u8]) -> Option<&'static Program> {
    PROGRAMS.iter().find(|p| p.name == name)
}

/// Start a program in its own address space.
pub fn run(p: &Program) -> bool {
    let start = p.image.as_ptr() as usize;
    let end = start + p.image.len();
    crate::scheduler::spawn_isolated_at(start, end, p.caps, PROGRAM_BASE)
}
