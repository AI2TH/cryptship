//go:build linux

package main

import "github.com/AI2TH/cryptship/pkg/harden"

// hardenProcess marks the loader process non-dumpable (prctl PR_SET_DUMPABLE 0).
// This blocks ptrace, process_vm_readv, and core dumps by a non-root user, and
// makes /proc/<pid>/mem root-owned, protecting the content key and decrypted
// payload while they live in the loader's memory.
//
// IMPORTANT: execve resets the dumpable flag, so this protects the loader /
// decrypt window, NOT the application after exec. The application can set it
// again first thing (pkg/harden for Go, helpers/python/cryptship_harden.py for
// Python); also run the container as non-root with dropped capabilities and
// the seccomp profile in deploy/ (and, against host root, use a
// confidential-compute key provider — see docs/ARCHITECTURE.md).
func hardenProcess() { _ = harden.NonDumpable() }
