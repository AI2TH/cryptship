//go:build linux && amd64

package main

// memfd_create on linux/amd64 (the stdlib syscall package predates it).
const sysMemfdCreate = 319
