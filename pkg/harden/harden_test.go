package harden

import "testing"

func TestNonDumpable(t *testing.T) {
	if !Supported() {
		t.Skip("PR_SET_DUMPABLE is Linux-only")
	}
	if err := NonDumpable(); err != nil {
		t.Fatal(err)
	}
	d, err := Dumpable()
	if err != nil {
		t.Fatal(err)
	}
	if d {
		t.Fatal("process is still dumpable")
	}
}
