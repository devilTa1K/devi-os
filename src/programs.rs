//! Programs compiled into the kernel image. Until there is a disk (M2),
//! "installing" a program means rebuilding the kernel with its binary.
//! Build the binaries first with build-user.ps1.

pub struct Program {
    pub name: &'static [u8],
    pub image: &'static [u8],
    pub caps: u32,
    /// true: an ELF file (validated, then loaded by segment).
    /// false: a flat binary (one code page plus one stack page).
    pub elf: bool,
}

/// Where flat binaries are loaded. It must match user/hello/link.ld.
pub const PROGRAM_BASE: u64 = 0x5555_1000_0000;

pub static PROGRAMS: [Program; 6] = [
    Program {
        name: b"hello",
        image: include_bytes!("../user/hello/hello.bin"),
        caps: crate::syscall::CAP_PRINT,
        elf: false,
    },
    Program {
        name: b"badwrite",
        image: include_bytes!("../user/hello/badwrite.bin"),
        caps: crate::syscall::CAP_PRINT,
        elf: false,
    },
    Program {
        name: b"helloelf",
        image: include_bytes!("../user/hello/hello_seg.elf"),
        caps: crate::syscall::CAP_PRINT,
        elf: true,
    },
    Program {
        name: b"data",
        image: include_bytes!("../user/hello/data.elf"),
        caps: crate::syscall::CAP_PRINT,
        elf: true,
    },
    Program {
        name: b"rotest",
        image: include_bytes!("../user/hello/rotest.elf"),
        caps: crate::syscall::CAP_PRINT,
        elf: true,
    },
    Program {
        name: b"nxtest",
        image: include_bytes!("../user/hello/nxtest.elf"),
        caps: crate::syscall::CAP_PRINT,
        elf: true,
    },
];

pub fn find(name: &[u8]) -> Option<&'static Program> {
    PROGRAMS.iter().find(|p| p.name == name)
}

/// Start a program in its own address space.
pub fn run(p: &Program) -> bool {
    if p.elf {
        return match crate::loader::load(p.image, p.caps) {
            Ok(()) => true,
            Err(e) => {
                crate::shell::note_error(e.name());
                false
            }
        };
    }
    let start = p.image.as_ptr() as usize;
    let end = start + p.image.len();
    crate::scheduler::spawn_isolated_at(start, end, p.caps, PROGRAM_BASE)
}
