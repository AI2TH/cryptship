//go:build !linux

package main

import "errors"

var errNotLinux = errors.New("CRYPTSHIP_APP_USER is only supported on Linux")

func secureTree(string, int, int) error { return errNotLinux }
func dropPrivileges(*appUser) error     { return errNotLinux }
