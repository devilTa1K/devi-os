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

## In progress
- [ ] Stage 9e: shell passphrase for grants

## Next

- [ ] Stage 10: userspace AI layer that reads the audit log

## Known limits
- All apps share one address space (no per-process page tables yet)
- Ring-0 code can rewrite the audit log and its hash chain; the head hash is not anchored outside the machine
- The log is a 64-entry RAM ring and is lost on reboot
- The shell runs in ring 0 and has no login yet
- SMEP is enabled but has no dedicated test



