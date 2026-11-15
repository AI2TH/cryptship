//go:build !linux

package harden

// NonDumpable is a no-op outside Linux (the loader ships in Linux containers).
func NonDumpable() error { return nil }

// Dumpable always reports true outside Linux.
func Dumpable() (bool, error) { return true, nil }

// Supported reports whether NonDumpable has an effect on this platform.
func Supported() bool { return false }
