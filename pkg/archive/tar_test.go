package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildTar makes a tar archive from a list of synthetic entries.
type entry struct {
	name, link string
	typ        byte
	body       []byte
	mode       int64
}

func buildTar(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: mode, Linkname: e.link, Size: int64(len(e.body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.name, err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write(%s): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestTarDirUntarRoundTrip(t *testing.T) {
	src := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0o644))
	must(os.MkdirAll(filepath.Join(src, "sub", "deeper"), 0o755))
	must(os.WriteFile(filepath.Join(src, "sub", "deeper", "b.bin"), []byte{0, 1, 2, 3, 255}, 0o600))
	must(os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755))
	must(os.Symlink("a.txt", filepath.Join(src, "link-to-a")))

	data, err := TarDir(src)
	if err != nil {
		t.Fatalf("TarDir: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	if err := Untar(data, dest); err != nil {
		t.Fatalf("Untar: %v", err)
	}

	check := func(rel string, want []byte, wantMode os.FileMode) {
		t.Helper()
		p := filepath.Join(dest, rel)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s content = %q, want %q", rel, got, want)
		}
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != wantMode {
			t.Fatalf("%s mode = %o, want %o", rel, fi.Mode().Perm(), wantMode)
		}
	}
	check("a.txt", []byte("alpha"), 0o644)
	check(filepath.Join("sub", "deeper", "b.bin"), []byte{0, 1, 2, 3, 255}, 0o600)
	check("run.sh", []byte("#!/bin/sh\necho hi\n"), 0o755)

	// In-tree symlink must be preserved and resolve inside dest.
	l, err := os.Readlink(filepath.Join(dest, "link-to-a"))
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if l != "a.txt" {
		t.Fatalf("symlink target = %q, want a.txt", l)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "link-to-a")); err != nil || string(b) != "alpha" {
		t.Fatalf("reading through symlink: %q, %v", b, err)
	}
}

func TestUntarRejectsPathTraversal(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	data := buildTar(t, []entry{
		{name: "ok.txt", typ: tar.TypeReg, body: []byte("fine")},
		{name: "../escape", typ: tar.TypeReg, body: []byte("pwned")},
	})

	err := Untar(data, dest)

	// Hard invariant: nothing may land outside dest, whatever the error status.
	if _, statErr := os.Stat(filepath.Join(parent, "escape")); statErr == nil {
		t.Fatalf("SECURITY: ../escape was written outside dest at %s", filepath.Join(parent, "escape"))
	}
	// Spec: an entry named ../escape must be REJECTED (error), not silently re-rooted.
	if err == nil {
		inside := filepath.Join(dest, "escape")
		_, insideErr := os.Stat(inside)
		t.Fatalf("Untar accepted entry %q without error (file inside dest exists: %v)", "../escape", insideErr == nil)
	}
}

func TestUntarRejectsAbsolutePath(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	data := buildTar(t, []entry{{name: "/abs/evil", typ: tar.TypeReg, body: []byte("x")}})
	if err := Untar(data, dest); err == nil {
		t.Fatalf("Untar accepted an absolute entry name without error")
	}
}

func TestUntarRejectsSymlinkEscapeRelative(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	data := buildTar(t, []entry{
		{name: "link", typ: tar.TypeSymlink, link: "../outside"},
	})
	err := Untar(data, dest)
	if err == nil {
		t.Errorf("Untar accepted symlink link -> ../outside without error")
	}
	// Whether or not it errored, no symlink pointing outside dest may exist.
	if l, rlErr := os.Readlink(filepath.Join(dest, "link")); rlErr == nil {
		resolved := filepath.Clean(filepath.Join(dest, l))
		if !isUnder(resolved, dest) {
			t.Errorf("SECURITY: symlink created pointing outside dest: %s -> %s (resolves to %s)", "link", l, resolved)
		}
	}
}

func TestUntarRejectsSymlinkEscapeAbsolute(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	data := buildTar(t, []entry{
		{name: "link", typ: tar.TypeSymlink, link: "/etc"},
	})
	err := Untar(data, dest)
	if err == nil {
		t.Errorf("Untar accepted symlink link -> /etc without error")
	}
	if l, rlErr := os.Readlink(filepath.Join(dest, "link")); rlErr == nil && filepath.IsAbs(l) {
		t.Errorf("SECURITY: absolute symlink created inside dest: link -> %s", l)
	}
}

// Classic two-step escape: a symlink out of dest, then a regular file written
// *through* it. Verifies no file lands outside dest.
func TestUntarNoWriteThroughSymlink(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	data := buildTar(t, []entry{
		{name: "link", typ: tar.TypeSymlink, link: "../outside"},
		{name: "link/pwned", typ: tar.TypeReg, body: []byte("owned")},
	})
	err := Untar(data, dest)
	if _, statErr := os.Stat(filepath.Join(outside, "pwned")); statErr == nil {
		t.Fatalf("SECURITY: file written outside dest via symlink: %s (Untar err=%v)", filepath.Join(outside, "pwned"), err)
	}
	if err == nil {
		t.Fatalf("Untar accepted a symlink-escape archive without error")
	}
}

func isUnder(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel != ".." && !bytes.HasPrefix([]byte(rel), []byte(".."+string(os.PathSeparator)))
}
