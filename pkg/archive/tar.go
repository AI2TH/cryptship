// Package archive packs a directory into a tar stream and safely extracts one.
// Extraction is hardened against path traversal and symlink escape, since the
// loader extracts attacker-reachable archives into a runtime directory. File and
// directory creation goes through an os.Root, so containment is enforced by the
// kernel, not by string checks.
package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// DefaultMaxExtractBytes caps total regular-file bytes written by Untar (guards
// against a hostile or broken archive expanding without bound).
const DefaultMaxExtractBytes int64 = 2 << 30

// TarDir walks root and returns a tar archive of its contents. Regular files,
// directories, and symlinks are included; modes are preserved. Paths in the
// archive are relative to root.
func TarDir(root string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		var link string
		if fi.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Untar extracts a tar archive into dest with the default size limit.
func Untar(data []byte, dest string) error { return UntarLimit(data, dest, DefaultMaxExtractBytes) }

// UntarLimit extracts a tar archive into dest. Files and directories are created
// through an os.Root, so the kernel — not a string check — guarantees nothing is
// written outside dest, even through symlinks created by earlier entries. Entry
// names that are absolute or escape the root are rejected, never remapped.
func UntarLimit(data []byte, dest string, maxBytes int64) error {
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destAbs, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(destAbs)
	if err != nil {
		return err
	}
	defer root.Close()

	var written int64
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := cleanEntry(hdr.Name)
		if err != nil {
			return err
		}
		if name == "." {
			continue
		}
		// Never setuid/setgid/sticky, never group/world-writable.
		mode := os.FileMode(hdr.Mode) & 0o777 &^ 0o022

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAll(root, name, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 || hdr.Size > maxBytes-written {
				return fmt.Errorf("archive: %q (%d bytes) exceeds extraction limit of %d bytes", hdr.Name, hdr.Size, maxBytes)
			}
			if err := mkdirAll(root, path.Dir(name), 0o700); err != nil {
				return err
			}
			f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode|0o600)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
			written += n
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := checkLink(root, name, hdr.Linkname); err != nil {
				return err
			}
			if err := mkdirAll(root, path.Dir(name), 0o700); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, filepath.Join(destAbs, filepath.FromSlash(name))); err != nil {
				return err
			}
		default:
			// Hard links, devices, fifos: fail loudly rather than ship a broken tree.
			return fmt.Errorf("archive: unsupported entry type %q for %q", hdr.Typeflag, hdr.Name)
		}
	}
}

// cleanEntry normalises a tar name to a slash-separated relative path and
// rejects (does not remap) absolute names and names that leave the root.
func cleanEntry(name string) (string, error) {
	n := path.Clean(filepath.ToSlash(name))
	if n == "" || path.IsAbs(n) || n == ".." || strings.HasPrefix(n, "../") || strings.ContainsRune(n, 0) {
		return "", fmt.Errorf("archive: unsafe path in archive: %q", name)
	}
	return n, nil
}

func mkdirAll(root *os.Root, dir string, perm os.FileMode) error {
	if dir == "." || dir == "" {
		return nil
	}
	parts := strings.Split(dir, "/")
	for i := range parts {
		if err := root.Mkdir(strings.Join(parts[:i+1], "/"), perm); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

// checkLink verifies a symlink entry stays within dest: the target must be
// relative and lexically contained, and no ancestor of the link may itself be a
// symlink (so the link cannot be redirected outside the root when created).
func checkLink(root *os.Root, name, linkname string) error {
	ln := filepath.ToSlash(linkname)
	if ln == "" || path.IsAbs(ln) || filepath.IsAbs(linkname) {
		return fmt.Errorf("archive: refusing absolute or empty symlink %s -> %q", name, linkname)
	}
	resolved := path.Clean(path.Join(path.Dir(name), ln))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("archive: refusing symlink escaping dest: %s -> %s", name, linkname)
	}
	for d := path.Dir(name); d != "." && d != "/"; d = path.Dir(d) {
		fi, err := root.Lstat(d)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive: refusing symlink under symlinked directory: %s", name)
		}
	}
	return nil
}
