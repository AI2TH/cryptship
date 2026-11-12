//go:build linux

package main

import "syscall"

// PR_SET_DUMPABLE from <linux/prctl.h>.
const prSetDumpable = 4

// hardenProcess marks the loader process non-dumpable (prctl PR_SET_DUMPABLE 0).
// This blocks ptrace, process_vm_readv, and core dumps by a non-root user, and
// makes /proc/<pid>/mem root-owned, protecting the content key and decrypted
// payload while they live in the loader's memory.
//
// IMPORTANT: execve resets the dumpable flag, so this protects the loader /
// decrypt window, NOT the application after exec. To harden the running app,
// run the container as non-root with dropped capabilities and the seccomp
// profile in deploy/ (and, against host root, use a confidential-compute key
// provider — see docs/ARCHITECTURE.md).
func hardenProcess() {
	_, _, _ = syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
}
