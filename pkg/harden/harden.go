// Package harden has small process-hardening helpers for applications that
// cryptship-loader starts.
//
// The loader marks itself non-dumpable (prctl PR_SET_DUMPABLE 0) while it
// holds the content key, but execve resets that flag, so the application
// starts dumpable: the same uid can ptrace it and read /proc/<pid>/mem and
// /proc/<pid>/exe. Call NonDumpable first thing in main to close that again.
// A Python equivalent lives in helpers/python/cryptship_harden.py.
//
// This raises the bar against other processes of the same uid; it does not
// stop root (see docs/ARCHITECTURE.md, threat model).
package harden
