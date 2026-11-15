package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI2TH/cryptship/pkg/archive"
	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
)

// The loader's last step replaces the process, so end-to-end tests run it in
// a child: the test binary re-executes itself with CRYPTSHIP_TEST_LOADER set,
// and the child calls run() with the arguments in CRYPTSHIP_TEST_ARGS.
func TestMain(m *testing.M) {
	if os.Getenv("CRYPTSHIP_TEST_LOADER") == "1" {
		var args []string
		_ = json.Unmarshal([]byte(os.Getenv("CRYPTSHIP_TEST_ARGS")), &args)
		if err := run(parseConfig(args)); err != nil {
			os.Stderr.WriteString("loader: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// loaderFixture writes a vendor key ring, a binding-"none" license and the
// encrypted payload of appDir, and returns the loader environment.
func loaderFixture(t *testing.T, appDir string) []string {
	t.Helper()
	work := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	contentKey, _ := crypto.RandomKey()
	tarBytes, err := archive.TarDir(appDir)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.SealPayload(contentKey, tarBytes, "build-e2e")
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := crypto.RandomKey()
	c := license.Claims{Version: license.FormatVersion, LicenseID: "lic_e2e", CustomerID: "acme", Product: "w",
		PayloadID: "build-e2e", SigningKeyID: "v1", Binding: license.Binding{Policy: license.BindNone}, UnboundSecret: secret}
	bctx, _ := c.BindingContext()
	kek, _ := crypto.DeriveKEK(secret, []byte(c.LicenseID), bctx)
	wk, _ := crypto.WrapKey(kek, contentKey)
	c.WrappedKeys = [][]byte{wk}
	lic, err := license.Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := lic.Marshal()
	files := map[string][]byte{
		"license.json": lb, "payload.enc": blob,
		"vendor.pub": []byte(base64.StdEncoding.EncodeToString(pub) + "\n"),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(work, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return []string{
		"CRYPTSHIP_LICENSE=" + filepath.Join(work, "license.json"),
		"CRYPTSHIP_PAYLOAD=" + filepath.Join(work, "payload.enc"),
		"CRYPTSHIP_PUBKEY=" + filepath.Join(work, "vendor.pub"),
		"CRYPTSHIP_STATE_DIR=" + filepath.Join(work, "state"),
	}
}

// runLoader runs the loader in a child process with env and args and returns
// its stdout; stderr is folded into the error.
func runLoader(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	a, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), env...), "CRYPTSHIP_TEST_LOADER=1", "CRYPTSHIP_TEST_ARGS="+string(a))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(out), err
}

func requireLinuxRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs Linux and root (run the suite in the golang container)")
	}
}

// As root with CRYPTSHIP_APP_USER, the app runs as that user, can read and run
// its code, but cannot change it; the tree is owner:appgroup, 0750/0640.
func TestExtractAsSeparateOwnerAndDropPrivileges(t *testing.T) {
	requireLinuxRoot(t)
	app := t.TempDir()
	if err := os.WriteFile(filepath.Join(app, "data.txt"), []byte("payload-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "entrypoint"), []byte("#!/bin/sh\nid -u; id -g\n(echo x >> data.txt) 2>/dev/null && echo WRITABLE || echo READONLY\n(touch new) 2>/dev/null && echo CREATED || echo NOCREATE\ncat data.txt; echo\nstat -c '%u:%g %a' . data.txt entrypoint\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The extract dir's parent must be traversable by the app user.
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	for d := filepath.Dir(parent); d != "/"; d = filepath.Dir(d) {
		_ = os.Chmod(d, 0o755)
	}
	extract := filepath.Join(parent, "run", "app")
	env := append(loaderFixture(t, app), "CRYPTSHIP_EXTRACT="+extract, "CRYPTSHIP_APP_USER=65532:65533")

	out, err := runLoader(t, env)
	if err != nil {
		t.Fatalf("loader: %v\n%s", err, out)
	}
	want := []string{"65532", "65533", "READONLY", "NOCREATE", "payload-data", "0:65533 750", "0:65533 640", "0:65533 750"}
	if got := strings.Split(strings.TrimSpace(out), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("app output:\n%s\nwant %q", out, want)
	}

	// A non-root uid as extract owner works too.
	env = append(env, "CRYPTSHIP_EXTRACT_OWNER=65531")
	if out, err = runLoader(t, env); err != nil || !strings.Contains(out, "65531:65533 640") {
		t.Fatalf("custom owner: %v\n%s", err, out)
	}
}

func TestAppUserValidation(t *testing.T) {
	for _, tc := range []struct{ user, owner string }{
		{"0", ""}, {"65532:0", ""}, {"65532", "65532"}, {"abc", ""}, {"-1", ""},
	} {
		t.Setenv("CRYPTSHIP_APP_USER", tc.user)
		t.Setenv("CRYPTSHIP_EXTRACT_OWNER", tc.owner)
		if _, err := appUserFromEnv(); err == nil {
			t.Errorf("user %q owner %q: accepted", tc.user, tc.owner)
		}
	}
	t.Setenv("CRYPTSHIP_APP_USER", "")
	if u, err := appUserFromEnv(); u != nil || err != nil {
		t.Fatalf("unset: %v %v", u, err)
	}
	if os.Geteuid() != 0 {
		t.Setenv("CRYPTSHIP_APP_USER", "65532")
		t.Setenv("CRYPTSHIP_EXTRACT_OWNER", "")
		if _, err := appUserFromEnv(); err == nil {
			t.Fatal("accepted without root")
		}
	}
}

// buildArgEchoer compiles a minimal static ELF that prints os.Args[1]. It
// ignores argv[0], so it runs correctly from a memfd regardless of the exe name.
func buildArgEchoer(t *testing.T, out string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "main.go")
	const code = `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		fmt.Println(os.Args[1])
	}
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build arg-echoer: %v\n%s", err, b)
	}
}

// CRYPTSHIP_EXEC_MEMFD runs a single ELF binary from memory: nothing is
// extracted, and the extract dir is never created.
func TestExecMemfd(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("memfd mode is Linux amd64/arm64 only")
	}
	app := t.TempDir()
	if err := os.MkdirAll(filepath.Join(app, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A tiny, self-contained ELF that echoes its first argument. Built here
	// rather than borrowing the system `echo`: some echo / multi-call binaries
	// reject a mismatched argv[0] when run from a memfd (argv[0]="tool" vs the
	// exe path "/memfd:cryptship-app"), which made this test fail on some
	// runners while passing on others.
	buildArgEchoer(t, filepath.Join(app, "bin", "tool"))
	if err := os.WriteFile(filepath.Join(app, "script.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	extract := filepath.Join(t.TempDir(), "never", "created")
	env := append(loaderFixture(t, app), "CRYPTSHIP_EXTRACT="+extract, "CRYPTSHIP_EXEC_MEMFD=bin/tool")

	out, err := runLoader(t, env, "--", "tool", "hello-from-memfd")
	if err != nil || strings.TrimSpace(out) != "hello-from-memfd" {
		t.Fatalf("memfd exec: %v\n%s", err, out)
	}
	if _, err := os.Stat(extract); !os.IsNotExist(err) {
		t.Fatal("memfd mode created the extract dir")
	}

	// With a privilege drop too (root only).
	if os.Geteuid() == 0 {
		out, err = runLoader(t, append(env, "CRYPTSHIP_APP_USER=65532"), "--", "tool", "dropped")
		if err != nil || strings.TrimSpace(out) != "dropped" {
			t.Fatalf("memfd exec with privilege drop: %v\n%s", err, out)
		}
	}

	// Scripts and missing entries are refused with a clear error.
	for _, entry := range []string{"script.sh", "missing"} {
		bad := append(loaderFixture(t, app), "CRYPTSHIP_EXTRACT="+extract, "CRYPTSHIP_EXEC_MEMFD="+entry)
		if out, err := runLoader(t, bad); err == nil {
			t.Fatalf("%s: ran\n%s", entry, out)
		}
	}
}
