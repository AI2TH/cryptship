//go:build linux

package harden

import "syscall"

// From <linux/prctl.h>.
const (
	prGetDumpable = 3
	prSetDumpable = 4
)

// NonDumpable marks the calling process non-dumpable: no core dumps, and
// ptrace, process_vm_readv and /proc/<pid>/{mem,exe} are refused to
// non-root processes. The flag applies to the whole process.
func NonDumpable() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// Dumpable reports the process's current dumpable flag.
func Dumpable() (bool, error) {
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		return false, errno
	}
	return r != 0, nil
}

// Supported reports whether NonDumpable has an effect on this platform.
func Supported() bool { return true }
