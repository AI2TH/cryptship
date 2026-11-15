//go:build !linux

package main

import "errors"

func execMemfd([]byte, []string, []string, *appUser) error {
	return errors.New("CRYPTSHIP_EXEC_MEMFD is only supported on Linux")
}
