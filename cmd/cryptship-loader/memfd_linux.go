//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/AI2TH/cryptship/pkg/crypto"
)

// From <linux/memfd.h> and <linux/fcntl.h>.
const (
	mfdCloexec      = 0x1
	mfdAllowSealing = 0x2
	fAddSeals       = 1033
	fSealSeal       = 0x1
	fSealShrink     = 0x2
	fSealGrow       = 0x4
	fSealWrite      = 0x8
)

// execMemfd runs a single-binary payload without writing it to any
// filesystem: the binary goes into an anonymous memfd, which is sealed
// against changes and executed through /proc/self/fd (what fexecve does). bin
// is wiped once copied. The memfd is close-on-exec, so this works for ELF
// executables; a "#!" script cannot be run this way (its interpreter could
// not open the closed fd).
//
// The binary still lives in RAM, and /proc/<pid>/exe of the running app reads
// it back for anyone allowed to ptrace the app (its own uid, root): have the
// app make itself non-dumpable again (pkg/harden, cryptship_harden.py).
func execMemfd(bin []byte, argv, envv []string, user *appUser) error {
	defer crypto.Wipe(bin)
	if sysMemfdCreate == 0 {
		return errors.New("CRYPTSHIP_EXEC_MEMFD: memfd_create is not wired up for this architecture")
	}
	if len(bin) < 4 || string(bin[:4]) != "\x7fELF" {
		return errors.New("CRYPTSHIP_EXEC_MEMFD: the entry is not an ELF executable (scripts cannot run from a close-on-exec memfd)")
	}
	name, _ := syscall.BytePtrFromString("cryptship-app")
	r, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(name)), mfdCloexec|mfdAllowSealing, 0)
	if errno != 0 {
		return fmt.Errorf("memfd_create: %w", errno)
	}
	fd := int(r)
	f := os.NewFile(uintptr(fd), "memfd:cryptship-app")
	if _, err := f.Write(bin); err != nil {
		f.Close()
		return fmt.Errorf("write memfd: %w", err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), fAddSeals, fSealSeal|fSealShrink|fSealGrow|fSealWrite); errno != 0 {
		f.Close()
		return fmt.Errorf("seal memfd: %w", errno)
	}
	if user != nil {
		if err := dropPrivileges(user); err != nil {
			f.Close()
			return err
		}
	}
	crypto.Wipe(bin)
	err := syscall.Exec(fmt.Sprintf("/proc/self/fd/%d", fd), argv, envv)
	f.Close()
	return fmt.Errorf("exec memfd: %w", err)
}
