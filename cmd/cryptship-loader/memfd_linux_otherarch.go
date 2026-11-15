//go:build linux && !amd64 && !arm64

package main

// memfd mode is wired up for amd64 and arm64 only.
const sysMemfdCreate = 0
