//go:build linux

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// secureTree gives every entry under dir (and dir itself) to owner:gid:
// directories and executables 0750, other files 0640, symlinks re-owned only.
// It runs as root before the app starts, on a tree only root has written.
func secureTree(dir string, owner, gid int) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := os.Lchown(p, owner, gid); err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o640)
		if d.IsDir() || fi.Mode().Perm()&0o111 != 0 {
			mode = 0o750
		}
		return os.Chmod(p, mode)
	})
}

// dropPrivileges switches the whole process (all threads) to the app's uid
// and gid with no supplementary groups, then checks root cannot be regained.
func dropPrivileges(u *appUser) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(u.gid); err != nil {
		return fmt.Errorf("setgid %d: %w", u.gid, err)
	}
	if err := syscall.Setuid(u.uid); err != nil {
		return fmt.Errorf("setuid %d: %w", u.uid, err)
	}
	if os.Getuid() != u.uid || os.Geteuid() != u.uid || os.Getgid() != u.gid || os.Getegid() != u.gid {
		return fmt.Errorf("privilege drop incomplete: uid %d/%d gid %d/%d", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())
	}
	if err := syscall.Setuid(0); err == nil {
		return fmt.Errorf("privilege drop failed: root can be regained")
	}
	return nil
}
