# DevilTalk (devi-os)

A small, security-first hobby operating system written in Rust for x86_64, running in QEMU.

It is a learning and portfolio project, not production-grade. The focus is on isolation and auditability: user programs run in ring 3 in their own address spaces, every privileged action goes through capability-checked syscalls, and everything important is recorded in a tamper-evident audit log.

## What works today

**Kernel basics**
- Bare-metal boot in QEMU, VGA text output
- IDT, CPU exceptions, double-fault handler on its own stack
- PIC, timer, keyboard
- Paging, frame allocator, kernel heap
- Async tasks and preemptive round-robin threads

**Security features**
- Ring 3 user mode with capability-checked syscalls; fault handlers kill hostile apps
- NX, W^X user pages, non-executable heap
- SMEP and SMAP
- Guard pages under kernel stacks
- Syscall filtering with one-way narrowing
- Per-process address spaces (own page tables, shared kernel half, W^X from the first mapping)
- SHA-256 hash-chained audit log, with a serial export and a host-side verifier (`verify-audit.ps1`) and a rule-based explainer (`explain-audit.ps1`)
- Capability-gated RAM files; shell with audited grants protected by a passphrase (masked input, lockout, audited failures)
- Log-read syscall with validated user pointers

**User programs (in progress)**
- Separately built Rust user programs, run from the shell, with `SYS_WRITE` and validated user pointers
- Strict ELF validator with a boot-time malformed-input self-test (segment loading is next)

See [ROADMAP.md](ROADMAP.md) for the full plan and the known limits.

## Build and run

Windows with PowerShell is the setup this project is developed on.

**Requirements**
- Rust nightly (pinned by `rust-toolchain.toml`)
- `rustup component add rust-src llvm-tools-preview`
- `cargo install bootimage`
- QEMU (`qemu-system-x86_64`) on your `PATH`

**Steps**

```powershell
.\setup-auth.ps1     # once: creates src\auth_config.rs (gitignored) with the shell passphrase hash
.\build-user.ps1     # builds the user programs the kernel embeds
cargo run            # builds the kernel and boots it in QEMU
```

QEMU writes the serial output (including the audit export) to `serial.log`.

## Known limits

This is a learning project and has real limitations, listed honestly in the roadmap. A few examples:

- A dead process's memory is not freed yet
- Ring-0 code can rewrite the log and its hash chain in RAM; the host verifier only catches that for history it already received
- The log is a 64-entry RAM ring and is lost on reboot
- The shell runs in ring 0, and the tamper/repair demo commands are still open

## Roadmap highlights

- ELF loader: load segments with their permissions
- Program syscalls: write, read_line, exit
- Process lifecycle: exit, free memory, `ps`, `kill`
- Manifest capabilities, with the audit log recording the SHA-256 of each program started
- A small user library and sample programs (echo, calc, notes)

## Contributing

Issues and feedback are welcome, especially on the security model and the audit log design. Look for issues labeled `good first issue`.

## License

[MIT](LICENSE)
