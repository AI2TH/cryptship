// Command cryptship-loader is the image ENTRYPOINT. It verifies the license,
// obtains the content key through a key provider, decrypts the payload into a
// runtime directory (ideally tmpfs), and execs the real app.
//
// Design principle: there is no "is the license valid?" boolean to patch. The
// content key is derived from the license + binding material, so tampering
// yields a failed AEAD tag, not a bypass.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"strconv"
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
	command     []string
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
	if err := enforceRevocation(lic, ring); err != nil {
		return err
	}

	// 3. Acquire the content key via a provider matching the binding policy.
	provider, err := keyprovider.Select(lic, buildProviders(ring)...)
	if err != nil {
		return err
	}
	contentKey, err := provider.ContentKey(context.Background(), lic)
	if err != nil {
		return fmt.Errorf("key acquisition (%s): %w", provider.Name(), err)
	}
	defer crypto.Wipe(contentKey)

	// 3b. Refuse a clock set back to keep an expiring license alive.
	if err := checkClock(stateDir(), lic.Claims, contentKey, time.Now()); err != nil {
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

	// 6. Hand off to the real application.
	return execApp(cfg, lic.Claims)
}

// extractMarker is created in the extract dir before anything is extracted,
// so a later run knows the directory is cryptship's to empty.
const extractMarker = ".cryptship-extract-dir"

// manifestName is the per-license watermark written after extraction.
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
	if len(entries) > 0 && !hasEntry(entries, extractMarker) && !hasEntry(entries, manifestName) {
		return fmt.Errorf("refusing to empty extract dir %s: it is not empty and was not created by cryptship-loader (no %s); point CRYPTSHIP_EXTRACT at an empty directory", abs, extractMarker)
	}
	// Empty the dir without removing it — it may be the tmpfs mount point.
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(abs, e.Name())); err != nil {
			return fmt.Errorf("clean extract dir: %w", err)
		}
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(abs, extractMarker), nil, 0o400)
}

func hasEntry(entries []os.DirEntry, name string) bool {
	for _, e := range entries {
		if e.Name() == name {
			return true
		}
	}
	return false
}

func execApp(cfg config, c license.Claims) error {
	if len(cfg.command) == 0 {
		cfg.command = []string{"./entrypoint"}
	}
	if err := os.Chdir(cfg.extractDir); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	resolved, err := exec.LookPath(cfg.command[0])
	if err != nil {
		return fmt.Errorf("locate command %q: %w", cfg.command[0], err)
	}
	var envv []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CRYPTSHIP_") {
			envv = append(envv, kv)
		}
	}
	envv = append(envv,
		"CRYPTSHIP_LICENSE_ID="+c.LicenseID,
		"CRYPTSHIP_CUSTOMER="+c.CustomerID,
		"CRYPTSHIP_PAYLOAD_ID="+c.PayloadID,
	)
	return syscall.Exec(resolved, cfg.command, envv)
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

// enforceRevocation performs the optional revocation check and applies the
// operator's failure policy (CRYPTSHIP_REVOCATION): "open" (default, run on
// error), "closed" (refuse on error), "grace:<dur>" (run if a prior successful
// check is younger than <dur>). Only "closed" is a hard guarantee.
//
// A cryptship-server signs the check response; the loader verifies it against
// the vendor key ring, so an on-path attacker or captive portal cannot forge
// "not revoked". In "closed" mode an UNSIGNED "active" answer is rejected.
func enforceRevocation(lic *license.License, ring license.KeyRing) error {
	if lic.Claims.RevocationURL == "" {
		return nil
	}
	mode := env("CRYPTSHIP_REVOCATION", "open")
	sf := stateFile("revocation", lic.Claims.LicenseID)

	revoked, signed, err := checkRevocation(lic, ring)
	if err == nil && revoked {
		return fmt.Errorf("license %s has been revoked", lic.Claims.LicenseID)
	}
	if err == nil && (signed || mode != "closed") {
		_ = os.MkdirAll(filepath.Dir(sf), 0o700)
		_ = os.WriteFile(sf, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
		return nil
	}
	if err == nil && !signed && mode == "closed" {
		err = errors.New("revocation response was unsigned; CRYPTSHIP_REVOCATION=closed requires a signing cryptship-server")
	}

	switch {
	case mode == "closed":
		return fmt.Errorf("revocation check failed and CRYPTSHIP_REVOCATION=closed: %w", err)
	case strings.HasPrefix(mode, "grace:"):
		if d, perr := time.ParseDuration(strings.TrimPrefix(mode, "grace:")); perr == nil {
			if b, rerr := os.ReadFile(sf); rerr == nil {
				// A last-success time in the future (clock set back, or a
				// hand-edited file) does not count as within grace.
				if last, lerr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); lerr == nil &&
					last <= time.Now().Unix()+license.ClockSkew &&
					time.Since(time.Unix(last, 0)) <= d {
					fmt.Fprintln(os.Stderr, "cryptship-loader: revocation check failed, within grace:", err)
					return nil
				}
			}
		}
		return fmt.Errorf("revocation check failed and no successful check within grace: %w", err)
	default:
		fmt.Fprintln(os.Stderr, "cryptship-loader: revocation check skipped (fail-open):", err)
		return nil
	}
}

// checkRevocation returns (revoked, signed, err). It sends a nonce and, if the
// server returns a signed online.CheckResponse that verifies against the ring
// and echoes the nonce, trusts its Revoked flag (signed=true). Otherwise it
// falls back to the legacy status-code reading (200 active / 410 revoked),
// reported as unsigned.
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	// Signed path: a valid, nonce-matching CheckResponse is authoritative.
	var cr online.CheckResponse
	if json.Unmarshal(body, &cr) == nil && len(cr.Sig) > 0 &&
		cr.LicenseID == lic.Claims.LicenseID && bytes.Equal(cr.Nonce, nonce) {
		pub, ok := ring[cr.SigningKeyID]
		if !ok {
			pub, ok = ring["*"]
		}
		if !ok || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, online.CheckSigningInput(cr), cr.Sig) {
			return false, false, errors.New("revocation check: bad response signature")
		}
		if cr.NotAfter != 0 && time.Now().Unix() > cr.NotAfter {
			return false, false, errors.New("revocation check: response expired")
		}
		return cr.Revoked, true, nil
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
