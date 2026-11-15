//go:build linux && arm64

package main

import "syscall"

const sysMemfdCreate = syscall.SYS_MEMFD_CREATE
