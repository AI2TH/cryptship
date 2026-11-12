//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkTmpfs verifies the extract dir is memory-backed. If it is not, require=true
// fails closed; otherwise it warns. Called before any plaintext is written.
func checkTmpfs(dir string, require bool) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	const tmpfsMagic = 0x01021994
	if int64(st.Type) == tmpfsMagic {
		return nil
	}
	msg := fmt.Sprintf("%s is not tmpfs; decrypted code would be on disk (docker --tmpfs %s / k8s emptyDir medium=Memory)", dir, dir)
	if require {
		return errors.New(msg)
	}
	fmt.Fprintln(os.Stderr, "cryptship-loader: WARNING:", msg)
	return nil
}
