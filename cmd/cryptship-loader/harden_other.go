//go:build !linux

package main

// hardenProcess is a no-op on non-Linux platforms (the loader ships in Linux
// containers; this keeps `go build ./...` green elsewhere).
func hardenProcess() {}
