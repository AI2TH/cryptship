package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI2TH/cryptship/pkg/license"
)

func TestPrepareDirRefusesForeignNonEmptyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home", "user")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(dir, "thesis.tex")
	if err := os.WriteFile(precious, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareDir(dir); err == nil {
		t.Fatal("prepareDir emptied a directory it did not create")
	}
	if _, err := os.Stat(precious); err != nil {
		t.Fatalf("file deleted: %v", err)
	}
}

func TestPrepareDirReusesItsOwnDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run", "app")
	// Fresh (missing) dir.
	if err := prepareDir(dir); err != nil {
		t.Fatal(err)
	}
	// Simulate a completed prior run: extracted files plus the manifest that
	// marks the dir as cryptship's.
	if err := os.WriteFile(filepath.Join(dir, "old.py"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	// Second run over that tree: emptied because the manifest marks it as ours.
	if err := prepareDir(dir); err != nil {
		t.Fatalf("second prepareDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.py")); !os.IsNotExist(err) {
		t.Fatal("old extraction not removed")
	}
}

func TestWriteManifestDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", filepath.Join(dir, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, license.Claims{LicenseID: "l"}); err == nil {
		t.Fatal("writeManifest wrote through a pre-existing symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target overwritten: %q", b)
	}
}

func TestStateFileStaysInStateDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CRYPTSHIP_STATE_DIR", dir)
	for _, id := range []string{"lic_1", "../../etc/x", "a/../../b", "..", "/abs"} {
		p := stateFile("revocation", id)
		if filepath.Dir(p) != dir {
			t.Errorf("license id %q: state file %s is outside %s", id, p, dir)
		}
	}
	if got := stateFile("revocation", "lic_abc"); got != filepath.Join(dir, "revocation-lic_abc") {
		t.Errorf("plain id renamed: %s", got)
	}
}
