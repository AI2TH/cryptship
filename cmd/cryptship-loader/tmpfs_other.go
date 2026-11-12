//go:build !linux

package main

// checkTmpfs is a no-op on non-Linux platforms (the loader ships in Linux
// containers; this keeps `go build ./...` green on a developer's machine).
func checkTmpfs(dir string, require bool) error { return nil }
