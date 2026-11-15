package archive

import (
	"archive/tar"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzUntar: whatever the archive, extraction never panics, never writes
// outside dest, and never leaves a symlink in dest that resolves outside it.
func FuzzUntar(f *testing.F) {
	seeds := [][]entry{
		{{name: "a.txt", typ: tar.TypeReg, body: []byte("x")}, {name: "d/", typ: tar.TypeDir}, {name: "d/l", typ: tar.TypeSymlink, link: "../a.txt"}},
		{{name: "../escape", typ: tar.TypeReg, body: []byte("x")}},
		{{name: "/abs", typ: tar.TypeReg, body: []byte("x")}},
		{{name: "s", typ: tar.TypeSymlink, link: "."}, {name: "s/../x", typ: tar.TypeReg, body: []byte("x")}},
		{{name: "s", typ: tar.TypeSymlink, link: "/etc"}},
		{{name: "d/", typ: tar.TypeDir}, {name: "d/s", typ: tar.TypeSymlink, link: "../.."}},
		{{name: "s", typ: tar.TypeSymlink, link: "d"}, {name: "d/", typ: tar.TypeDir}, {name: "s/f", typ: tar.TypeReg, body: []byte("x")}},
		{{name: "h", typ: tar.TypeLink, link: "/etc/passwd"}},
	}
	for _, s := range seeds {
		f.Add(buildTar(f, s))
	}
	f.Add([]byte("not a tar"))

	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		dest := filepath.Join(parent, "dest")
		_ = UntarLimit(data, dest, 1<<20) // errors are fine; escapes are not

		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "dest" {
				t.Fatalf("wrote outside dest: %s", e.Name())
			}
		}
		destReal, err := filepath.EvalSymlinks(dest)
		if err != nil {
			return // nothing extracted
		}
		_ = filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			target, _ := os.Readlink(p)
			if lex := filepath.Clean(filepath.Join(filepath.Dir(p), target)); !within(dest, lex) {
				t.Fatalf("symlink %s -> %s points outside dest", p, target)
			}
			if real, err := filepath.EvalSymlinks(p); err == nil && !within(destReal, real) {
				t.Fatalf("symlink %s resolves outside dest: %s", p, real)
			}
			return nil
		})
	})
}

func within(root, p string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// FuzzReadFile: reading one entry from an arbitrary archive never panics and
// never returns more than the limit.
func FuzzReadFile(f *testing.F) {
	f.Add(buildTar(f, []entry{{name: "bin/app", typ: tar.TypeReg, body: []byte("\x7fELF")}}), "bin/app")
	f.Add(buildTar(f, []entry{{name: "l", typ: tar.TypeSymlink, link: "bin/app"}}), "l")
	f.Add([]byte{}, "../x")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		b, err := ReadFile(data, name, 64)
		if err == nil && len(b) > 64 {
			t.Fatalf("returned %d bytes over the limit", len(b))
		}
	})
}
