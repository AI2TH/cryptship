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

	"github.com/cryptship/cryptship/pkg/archive"
	"github.com/cryptship/cryptship/pkg/crypto"
	"github.com/cryptship/cryptship/pkg/keyprovider"
	"github.com/cryptship/cryptship/pkg/license"
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
	if err := enforceRevocation(lic); err != nil {
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
	writeManifest(cfg.extractDir, lic.Claims)

	// 6. Hand off to the real application.
	return execApp(cfg, lic.Claims)
}

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
	// Empty the dir without removing it — it may be the tmpfs mount point.
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(abs, e.Name())); err != nil {
			return fmt.Errorf("clean extract dir: %w", err)
		}
	}
	return os.Chmod(abs, 0o700)
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
// running instance names its licensee. Traceability aid, not prevention.
func writeManifest(dir string, c license.Claims) {
	m := fmt.Sprintf(`{"license_id":%q,"customer":%q,"product":%q,"payload_id":%q,"started_at":%d}`+"\n",
		c.LicenseID, c.CustomerID, c.Product, c.PayloadID, time.Now().Unix())
	_ = os.WriteFile(filepath.Join(dir, ".cryptship-manifest.json"), []byte(m), 0o400)
}

// enforceRevocation performs the optional revocation check and applies the
// operator's failure policy (CRYPTSHIP_REVOCATION): "open" (default, run on
// error), "closed" (refuse on error), "grace:<dur>" (run if a prior successful
// check is younger than <dur>). Only "closed" is a hard guarantee.
func enforceRevocation(lic *license.License) error {
	if lic.Claims.RevocationURL == "" {
		return nil
	}
	mode := env("CRYPTSHIP_REVOCATION", "open")
	stateFile := filepath.Join(env("CRYPTSHIP_STATE_DIR", "/var/lib/cryptship"), "revocation-"+lic.Claims.LicenseID)

	revoked, err := checkRevocation(lic)
	if err == nil {
		if revoked {
			return fmt.Errorf("license %s has been revoked", lic.Claims.LicenseID)
		}
		_ = os.MkdirAll(filepath.Dir(stateFile), 0o700)
		_ = os.WriteFile(stateFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
		return nil
	}
	switch {
	case mode == "closed":
		return fmt.Errorf("revocation check failed and CRYPTSHIP_REVOCATION=closed: %w", err)
	case strings.HasPrefix(mode, "grace:"):
		if d, perr := time.ParseDuration(strings.TrimPrefix(mode, "grace:")); perr == nil {
			if b, rerr := os.ReadFile(stateFile); rerr == nil {
				if last, lerr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); lerr == nil &&
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

// checkRevocation returns (revoked, err). 200 = active, 410 = revoked, anything
// else is an error so the operator's policy decides.
func checkRevocation(lic *license.License) (bool, error) {
	u, err := url.Parse(lic.Claims.RevocationURL)
	if err != nil {
		return false, err
	}
	q := u.Query()
	q.Set("license_id", lic.Claims.LicenseID)
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		return false, nil
	case http.StatusGone:
		return true, nil
	default:
		return false, fmt.Errorf("unexpected status %s", resp.Status)
	}
}
