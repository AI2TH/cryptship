package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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
	if err := os.WriteFile(filepath.Join(dir, "old.py"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Second run over the first run's tree: emptied and re-marked.
	if err := prepareDir(dir); err != nil {
		t.Fatalf("second prepareDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.py")); !os.IsNotExist(err) {
		t.Fatal("old extraction not removed")
	}
	if _, err := os.Stat(filepath.Join(dir, extractMarker)); err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	// A dir left by an older loader (manifest, no marker) is accepted too.
	if err := os.Remove(filepath.Join(dir, extractMarker)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := prepareDir(dir); err != nil {
		t.Fatalf("prepareDir over an older loader's dir: %v", err)
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

// grace: a last-success time in the future is not "within grace".
func TestRevocationGraceIgnoresFutureTimestamp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	dir := t.TempDir()
	t.Setenv("CRYPTSHIP_STATE_DIR", dir)
	t.Setenv("CRYPTSHIP_REVOCATION", "grace:1h")
	lic := &license.License{Claims: license.Claims{LicenseID: "lic_g", RevocationURL: ts.URL}}
	write := func(ts int64) {
		if err := os.WriteFile(stateFile("revocation", "lic_g"), []byte(strconv.FormatInt(ts, 10)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(time.Now().Add(-10 * time.Minute).Unix())
	if err := enforceRevocation(lic); err != nil {
		t.Fatalf("recent success should be within grace: %v", err)
	}
	write(time.Now().Add(-2 * time.Hour).Unix())
	if err := enforceRevocation(lic); err == nil {
		t.Fatal("old success accepted as within grace")
	}
	write(time.Now().Add(365 * 24 * time.Hour).Unix())
	if err := enforceRevocation(lic); err == nil {
		t.Fatal("future success timestamp accepted as within grace")
	}
}
