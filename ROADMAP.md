# DevilTalk roadmap

A small, security-first hobby OS in Rust (x86_64, runs in QEMU).
A learning and portfolio project, not production-grade.

## Done
- [x] Stage 0-1: toolchain, bare-metal kernel, VGA text output
- [x] Stage 2: IDT, CPU exceptions, double-fault handler on its own stack
- [x] Stage 3: PIC, timer, keyboard
- [x] Stage 4: paging, frame allocator, kernel heap
- [x] Stage 5: async tasks, preemptive round-robin threads
- [x] Stage 6: ring 3 user mode, capability-checked syscalls, fault handlers that kill hostile apps
- [x] Stage 7: SHA-256 hash-chained audit log
- [x] Stage 8: capability-gated RAM files, shell with audited grants
- [x] Stage 9a: NX, W^X user pages, non-executable heap
- [x] Stage 9b: SMEP and SMAP
- [x] Stage 9c: guard pages under kernel stacks
- [x] Stage 9d: syscall filtering, with one-way narrowing
- [x] Stage 9e: shell passphrase for grants (masked input, lockout, audited failures); manually functionally tested
- [x] Stage 10a: serial audit export, host-side verifier (verify-audit.ps1), forge demo for the external anchor

## In progress
- [ ] Stage 10b: host-side plain-language explainer for the audit log
- [ ] Stage 10c: ring-3 explainer with an AUDIT_READ capability and a log-read syscall

## Next

- [ ] Later: remove or protect the tamper and repair demo commands

## Known limits
- All apps share one address space (no per-process page tables yet)
- Ring-0 code can rewrite the log and its hash chain in RAM. verify-audit.ps1 catches that only for history the host already received; an attacker can also stop sending, and the serial stream is unsigned
- The log is a 64-entry RAM ring and is lost on reboot
- The shell runs in ring 0. grant needs a passphrase, but tamper and repair are still open demo commands
- SMEP is enabled but has no dedicated test
- The passphrase hash is built into the kernel image and uses 20,000 SHA-256 rounds, so only a long random passphrase is safe




## Build note
- Run .\setup-auth.ps1 once to create src\auth_config.rs (gitignored) before cargo run.








