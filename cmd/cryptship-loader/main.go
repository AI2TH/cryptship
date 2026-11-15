// Command cryptship-loader is the image ENTRYPOINT. It verifies the license,
// obtains the content key through a key provider, decrypts the payload into a
// runtime directory (ideally tmpfs), and execs the real app.
//
// Design principle: there is no "is the license valid?" boolean to patch. The
// content key is derived from the license + binding material, so tampering
// yields a failed AEAD tag, not a bypass.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AI2TH/cryptship/pkg/archive"
	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/keyprovider"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/online"
)

type config struct {
	licensePath string
	payloadPath string
	pubKeyPath  string
	extractDir  string
	// memfdEntry, when set (CRYPTSHIP_EXEC_MEMFD), names a single ELF binary in
	// the payload that is executed from a memfd; nothing is extracted.
	memfdEntry string
	command    []string
}

func main() {
	cfg := parseConfig(os.Args[1:])
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "cryptship-loader: fatal:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseConfig(args []string) config {
	cfg := config{
		licensePath: env("CRYPTSHIP_LICENSE", "/cryptship/license.json"),
		payloadPath: env("CRYPTSHIP_PAYLOAD", "/cryptship/payload.enc"),
		pubKeyPath:  env("CRYPTSHIP_PUBKEY", "/cryptship/vendor.pub"),
		extractDir:  env("CRYPTSHIP_EXTRACT", "/run/cryptship/app"),
		memfdEntry:  os.Getenv("CRYPTSHIP_EXEC_MEMFD"),
	}
	for i, a := range args {
		if a == "--" {
			cfg.command = args[i+1:]
			return cfg
		}
	}
	cfg.command = args
	return cfg
}

func run(cfg config) error {
	// 0. Mark the loader non-dumpable while the key/plaintext are in its memory.
	hardenProcess()
	user, err := appUserFromEnv()
	if err != nil {
		return err
	}

	// 1. Load and verify the license signature against the key ring.
	ringBytes, err := os.ReadFile(cfg.pubKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	ring, err := license.ParseKeyRing(ringBytes)
	if err != nil {
		return fmt.Errorf("parse key ring: %w", err)
	}
	licBytes, err := os.ReadFile(cfg.licensePath)
	if err != nil {
		return fmt.Errorf("read license: %w", err)
	}
	lic, err := license.Parse(licBytes)
	if err != nil {
		return fmt.Errorf("parse license: %w", err)
	}
	if err := lic.VerifyWith(ring); err != nil {
		return fmt.Errorf("license verification: %w", err)
	}

	// 2. Policy checks.
	if lic.Claims.Expired(time.Now().Unix()) {
		return fmt.Errorf("license outside validity window (expires %d)", lic.Claims.NotAfter)
	}

	// 3. Acquire the content key via a provider matching the binding policy.
	provider, err := keyprovider.Select(lic, buildProviders(ring)...)
	if err != nil {
		return err
	}
	keys, err := keyprovider.Unlock(context.Background(), provider, lic)
	if err != nil {
		return fmt.Errorf("key acquisition (%s): %w", provider.Name(), err)
	}
	defer keys.Wipe()
	contentKey := keys.ContentKey
	// Local state is sealed under the binding-derived state key. A
	// third-party provider without one falls back to the content key.
	stateKey := keys.StateKey
	if stateKey == nil {
		stateKey = contentKey
	}

	// 3a. Optional revocation check. It runs after key acquisition so the
	// grace record can be sealed under a key only this license unlocks.
	if err := enforceRevocation(lic, ring, stateKey); err != nil {
		return err
	}

	// 3b. Refuse a clock set back to keep an expiring license alive.
	if err := checkClock(stateDir(), lic.Claims, stateKey, contentKey, time.Now()); err != nil {
		return err
	}

	// 4. Decrypt the payload (AEAD bound to the signed payload id).
	blob, err := os.ReadFile(cfg.payloadPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	tarBytes, err := crypto.OpenPayload(contentKey, blob, lic.Claims.PayloadID)
	if err != nil {
		return fmt.Errorf("decrypt payload (tampered or wrong key): %w", err)
	}

	// 5a. Single-binary payloads can run from memory with nothing on disk.
	if cfg.memfdEntry != "" {
		bin, err := archive.ReadFile(tarBytes, cfg.memfdEntry, archive.DefaultMaxExtractBytes)
		crypto.Wipe(tarBytes)
		if err != nil {
			return fmt.Errorf("CRYPTSHIP_EXEC_MEMFD: %w", err)
		}
		argv := cfg.command
		if len(argv) == 0 {
			argv = []string{filepath.Base(cfg.memfdEntry)}
		}
		return execMemfd(bin, argv, appEnv(lic.Claims), user)
	}

	// 5. Extract into the runtime dir, enforcing/warning tmpfs before writing.
	if err := prepareDir(cfg.extractDir); err != nil {
		return err
	}
	if err := checkTmpfs(cfg.extractDir, os.Getenv("CRYPTSHIP_REQUIRE_TMPFS") != ""); err != nil {
		return err
	}
	if err := archive.Untar(tarBytes, cfg.extractDir); err != nil {
		return fmt.Errorf("extract payload: %w", err)
	}
	crypto.Wipe(tarBytes)
	if err := writeManifest(cfg.extractDir, lic.Claims); err != nil {
		fmt.Fprintln(os.Stderr, "cryptship-loader: WARNING: manifest not written:", err)
	}
	if user != nil {
		// The app may read and run its code, but not change it.
		if err := secureTree(cfg.extractDir, user.owner, user.gid); err != nil {
			return fmt.Errorf("hand extract dir to uid %d, gid %d: %w", user.owner, user.gid, err)
		}
	}

	// 6. Hand off to the real application.
	return execApp(cfg, lic.Claims, user)
}

// manifestName is the per-license watermark written after extraction. Its
// presence also marks the extract dir as cryptship's to empty on a later run,
// so there is no separate marker file to collide with payload contents.
const manifestName = ".cryptship-manifest.json"

// prepareDir empties the extract dir for a fresh extraction. It only deletes
// the contents of a directory that is empty or that an earlier run marked as
// an extract dir, so a mistyped CRYPTSHIP_EXTRACT (say, a home directory)
// fails instead of being wiped.
func prepareDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if strings.Count(filepath.Clean(abs), string(os.PathSeparator)) < 2 {
		return fmt.Errorf("refusing to use %q as extract dir (too close to /)", abs)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("create extract dir: %w", err)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return err
	}
	if len(entries) > 0 && !hasEntry(entries, manifestName) {
		return fmt.Errorf("refusing to empty extract dir %s: it is not empty and has no %s from a previous cryptship run; point CRYPTSHIP_EXTRACT at an empty directory", abs, manifestName)
	}
	// Empty the dir without removing it — it may be the tmpfs mount point.
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(abs, e.Name())); err != nil {
			return fmt.Errorf("clean extract dir: %w", err)
		}
	}
	return os.Chmod(abs, 0o700)
}

func hasEntry(entries []os.DirEntry, name string) bool {
	for _, e := range entries {
		if e.Name() == name {
			return true
		}
	}
	return false
}

func execApp(cfg config, c license.Claims, user *appUser) error {
	if len(cfg.command) == 0 {
		cfg.command = []string{"./entrypoint"}
	}
	if err := os.Chdir(cfg.extractDir); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	if user != nil {
		if err := dropPrivileges(user); err != nil {
			return err
		}
	}
	resolved, err := exec.LookPath(cfg.command[0])
	if err != nil {
		return fmt.Errorf("locate command %q: %w", cfg.command[0], err)
	}
	return syscall.Exec(resolved, cfg.command, appEnv(c))
}

// appEnv is the app's environment: the loader's, minus CRYPTSHIP_* settings,
// plus the license watermark variables.
func appEnv(c license.Claims) []string {
	var envv []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CRYPTSHIP_") {
			envv = append(envv, kv)
		}
	}
	return append(envv,
		"CRYPTSHIP_LICENSE_ID="+c.LicenseID,
		"CRYPTSHIP_CUSTOMER="+c.CustomerID,
		"CRYPTSHIP_PAYLOAD_ID="+c.PayloadID,
	)
}

// writeManifest drops a per-license marker into the extracted tree so a leaked
// running instance names its licensee. Traceability aid, not prevention. It
// is created with O_EXCL, so it never follows or overwrites a path the
// payload put there.
func writeManifest(dir string, c license.Claims) error {
	m, err := json.Marshal(struct {
		LicenseID string `json:"license_id"`
		Customer  string `json:"customer"`
		Product   string `json:"product"`
		PayloadID string `json:"payload_id"`
		StartedAt int64  `json:"started_at"`
	}{c.LicenseID, c.CustomerID, c.Product, c.PayloadID, time.Now().Unix()})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, manifestName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	_, err = f.Write(append(m, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// stateDir is where the loader keeps revocation-grace and clock state.
func stateDir() string { return env("CRYPTSHIP_STATE_DIR", "/var/lib/cryptship") }

// stateFile names a per-license state file in the state dir.
func stateFile(kind, licenseID string) string {
	return filepath.Join(stateDir(), kind+"-"+escapeID(licenseID))
}

// escapeID makes a license id safe as one path component: "/" is escaped, so
// an id cannot point a state file outside the state dir.
func escapeID(licenseID string) string { return url.PathEscape(licenseID) }

// revocationStateInfo labels the sealed revocation-grace record.
const revocationStateInfo = "cryptship/revocation-grace/v1"

// enforceRevocation performs the optional revocation check and applies the
// operator's failure policy (CRYPTSHIP_REVOCATION): "open" (default, run on
// error), "closed" (refuse on error), "grace:<dur>" (run if a prior signed
// "not revoked" answer is younger than <dur>). Only "closed" is a hard
// guarantee.
//
// A cryptship-server signs the check response; the loader verifies it against
// the vendor key ring, so an on-path attacker or captive portal cannot forge
// "not revoked". In "closed" mode an UNSIGNED "active" answer is rejected, and
// only a signed answer refreshes the grace record.
//
// The time of the last signed success is sealed (AES-GCM) under a key derived
// from secret, so editing or copying the record does not extend grace, and a
// record dated in the future (clock set back) does not count.
func enforceRevocation(lic *license.License, ring license.KeyRing, secret []byte) error {
	if lic.Claims.RevocationURL == "" {
		return nil
	}
	mode := env("CRYPTSHIP_REVOCATION", "open")
	st := sealedState{info: revocationStateInfo, licenseID: lic.Claims.LicenseID, path: stateFile("revocation", lic.Claims.LicenseID)}

	revoked, signed, err := checkRevocation(lic, ring)
	if err == nil && revoked {
		return fmt.Errorf("license %s has been revoked", lic.Claims.LicenseID)
	}
	if err == nil && signed {
		// Only a SIGNED "active" answer refreshes the grace clock; an unsigned
		// answer (captive portal / on-path) must not be able to extend grace.
		if werr := st.write(secret, time.Now().Unix()); werr != nil && strings.HasPrefix(mode, "grace:") {
			warnf("revocation grace record not written: %v", werr)
		}
		return nil
	}
	if err == nil { // an unsigned "not revoked": accepted unless closed, never refreshes grace
		if mode != "closed" {
			return nil
		}
		err = errors.New("revocation response was unsigned; CRYPTSHIP_REVOCATION=closed requires a signing cryptship-server")
	}

	switch {
	case mode == "closed":
		return fmt.Errorf("revocation check failed and CRYPTSHIP_REVOCATION=closed: %w", err)
	case strings.HasPrefix(mode, "grace:"):
		d, perr := time.ParseDuration(strings.TrimPrefix(mode, "grace:"))
		if perr != nil {
			return fmt.Errorf("bad CRYPTSHIP_REVOCATION %q: %w", mode, perr)
		}
		last, rerr := st.read(secret)
		now := time.Now().Unix()
		switch {
		case rerr != nil:
			if errors.Is(rerr, errBadState) {
				warnf("revocation grace record %s is not valid for this license; ignored", st.path)
			}
		case last > now+license.ClockSkew:
			// A last success in the future (clock set back) is not within grace.
			warnf("revocation grace record %s is dated in the future; ignored", st.path)
		case time.Since(time.Unix(last, 0)) <= d:
			fmt.Fprintln(os.Stderr, "cryptship-loader: revocation check failed, within grace:", err)
			return nil
		}
		return fmt.Errorf("revocation check failed and no signed successful check within grace: %w", err)
	default:
		fmt.Fprintln(os.Stderr, "cryptship-loader: revocation check skipped (fail-open):", err)
		return nil
	}
}

// checkRevocation returns (revoked, signed, err). It sends a nonce; a signed
// online.CheckResponse that verifies against the ring and answers this license
// and nonce is authoritative (signed=true). A signed answer that fails to
// verify or has expired is an error. Anything else (not a signed answer, or
// one for another license or nonce) falls back to the legacy status-code
// reading (200 active / 410 revoked), reported as unsigned.
func checkRevocation(lic *license.License, ring license.KeyRing) (revoked bool, signed bool, err error) {
	u, err := url.Parse(lic.Claims.RevocationURL)
	if err != nil {
		return false, false, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return false, false, err
	}
	q := u.Query()
	q.Set("license_id", lic.Claims.LicenseID)
	q.Set("nonce", hex.EncodeToString(nonce))
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, online.MaxResponseBytes))
	if err != nil {
		return false, false, err
	}

	cr, verr := online.VerifyCheckResponse(body, ring, lic.Claims.LicenseID, nonce, time.Now())
	switch {
	case verr == nil:
		return cr.Revoked, true, nil
	case !errors.Is(verr, online.ErrUnsigned) && !errors.Is(verr, online.ErrMismatch):
		return false, false, fmt.Errorf("revocation check: %w", verr)
	}

	// Legacy unsigned path.
	switch resp.StatusCode {
	case http.StatusOK:
		return false, false, nil
	case http.StatusGone:
		return true, false, nil
	default:
		return false, false, fmt.Errorf("unexpected status %s", resp.Status)
	}
}
