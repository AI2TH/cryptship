package keyprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/machine"
	"github.com/AI2TH/cryptship/pkg/online"
)

// HTTPClient is the minimal client the network providers need (satisfied by
// *http.Client).
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Online fetches the binding secret from the vendor's license server, then
// unwraps exactly like Offline. The license carries no secret: revocation is
// the server declining; the response is signed and echoes a nonce so a proxy
// cannot forge or replay it.
//
// If CacheDir and Grace are both set, a successful fetch is cached — the secret
// sealed under a machine-bound key — so a later server OUTAGE can be ridden out
// for up to Grace. Grace applies to online binding only; attested never uses it
// (it must always re-attest).
type Online struct {
	Keys     license.KeyRing
	Client   HTTPClient
	CacheDir string        // where to seal the grace cache (empty = disabled)
	Grace    time.Duration // how long a cached secret may ride out an outage
}

// Name implements Provider.
func (Online) Name() string { return "online" }

// Handles implements Provider.
func (Online) Handles(p license.BindingPolicy) bool { return p == license.BindOnline }

// ContentKey implements Provider.
func (o Online) ContentKey(ctx context.Context, lic *license.License) ([]byte, error) {
	return contentKeyOnly(o.Unlock(ctx, lic))
}

// Unlock implements Unlocker.
func (o Online) Unlock(ctx context.Context, lic *license.License) (Unlocked, error) {
	var g *graceConfig
	if o.CacheDir != "" && o.Grace > 0 {
		g = &graceConfig{dir: o.CacheDir, window: o.Grace}
	}
	return fetchAndUnwrap(ctx, o.Keys, o.Client, lic, g)
}

// graceConfig configures the outage cache (online only).
type graceConfig struct {
	dir    string
	window time.Duration
}

// fetchAndUnwrap runs the online request / verify / unwrap flow. grace is nil
// when the outage cache is disabled.
func fetchAndUnwrap(ctx context.Context, keys license.KeyRing, client HTTPClient, lic *license.License, grace *graceConfig) (Unlocked, error) {
	c := lic.Claims
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Unlocked{}, err
	}
	m, _ := machine.ID()
	respBody, err := postJSON(ctx, client, c, "/v1/key", online.KeyRequest{
		LicenseID: c.LicenseID, Machine: m, Nonce: nonce,
		Policy: string(c.Binding.Policy), SecretVersion: c.Binding.SecretVersion,
	})
	if err != nil {
		// Server unreachable: ride out the outage with the cached content key, if any.
		var ue *unreachableError
		if grace != nil && errors.As(err, &ue) {
			if u, gerr := graceUnwrap(grace, c); gerr == nil {
				fmt.Fprintln(os.Stderr, "cryptship: license server unreachable, using grace cache:", err)
				return u, nil
			} else if !errors.Is(gerr, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "cryptship: grace cache present but unusable:", gerr)
			}
		}
		return Unlocked{}, err
	}
	kr, err := online.VerifyKeyResponse(respBody, keys, c.LicenseID, nonce, time.Now())
	if err != nil {
		return Unlocked{}, err
	}
	defer crypto.Wipe(kr.Secret)
	u, err := UnwrapKeys(c, kr.Secret)
	if err != nil {
		return Unlocked{}, err
	}
	if grace != nil {
		// Cache the content key (and the local state key), not the
		// per-license secret: the content key is per build and already lives
		// in the running app's memory, and the state key only seals local
		// state, so caching them adds no portable license-wide credential.
		graceStore(grace, c, u, kr.NotAfter) // best effort
	}
	return u, nil
}

// unreachableError marks a transport failure (no answer from the server), the
// only failure the outage grace cache may cover.
type unreachableError struct{ err error }

func (e *unreachableError) Error() string { return "online: " + e.err.Error() }
func (e *unreachableError) Unwrap() error { return e.err }

// postJSON POSTs v to the license's server at path and returns the body of a
// 200 answer. 410 maps to ErrRevoked and 403 to ErrDenied; a transport
// failure is an *unreachableError.
func postJSON(ctx context.Context, client HTTPClient, c license.Claims, path string, v any) ([]byte, error) {
	if c.Binding.Server == "" {
		return nil, errors.New("online: license has no binding.server")
	}
	if client == nil {
		return nil, errors.New("online: no HTTP client configured")
	}
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Binding.Server, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, &unreachableError{err}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusGone:
		return nil, ErrRevoked
	case http.StatusForbidden:
		return nil, ErrDenied
	default:
		return nil, fmt.Errorf("online: server returned %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, online.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("online: read response: %w", err)
	}
	return b, nil
}

// --- outage grace cache ---

const graceAAD = "cryptship/online-grace/v1"

type graceRecord struct {
	Sealed   []byte `json:"sealed"`    // AES-256-GCM(content key); AAD binds cached_at+not_after
	CachedAt int64  `json:"cached_at"` // unix seconds (authenticated via AAD)
	NotAfter int64  `json:"not_after"` // server-stated validity (authenticated and enforced)
}

// graceAD binds the timestamps into the AEAD, so editing cached_at/not_after in
// the on-disk JSON (to extend the window) makes the open fail.
func graceAD(licenseID string, cachedAt, notAfter int64) []byte {
	return []byte(fmt.Sprintf("%s|%s|%d|%d", graceAAD, licenseID, cachedAt, notAfter))
}

// graceKEK derives the key that seals the cached secret. It binds to the machine
// fingerprint when one is readable (so the cache cannot be copied to another
// machine); otherwise it falls back to a random key stored in the state dir, so
// grace still works (bound to this install rather than the machine). Best effort.
func graceKEK(dir, licenseID string) ([]byte, error) {
	material, err := graceMaterial(dir)
	if err != nil {
		return nil, err
	}
	return crypto.DeriveKEK(material, []byte("online-grace|"+licenseID), []byte(graceAAD))
}

func graceMaterial(dir string) ([]byte, error) {
	if id, err := machine.ID(); err == nil && id != "" {
		return []byte("machine:" + id), nil
	}
	keyPath := filepath.Join(dir, "online-grace.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) >= 32 {
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func gracePath(dir, licenseID string) string {
	return filepath.Join(dir, "online-grace-"+url.PathEscape(licenseID))
}

func graceStore(g *graceConfig, c license.Claims, u Unlocked, serverNotAfter int64) {
	kek, err := graceKEK(g.dir, c.LicenseID)
	if err != nil {
		return
	}
	defer crypto.Wipe(kek)
	cachedAt := time.Now().Unix()
	// The sealed value is content key || state key (64 bytes); a 32-byte
	// record from an older loader holds the content key only.
	pt := append(append([]byte{}, u.ContentKey...), u.StateKey...)
	defer crypto.Wipe(pt)
	sealed, err := crypto.Seal(kek, pt, graceAD(c.LicenseID, cachedAt, serverNotAfter))
	if err != nil {
		return
	}
	rec, err := json.Marshal(graceRecord{Sealed: sealed, CachedAt: cachedAt, NotAfter: serverNotAfter})
	if err != nil {
		return
	}
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(gracePath(g.dir, c.LicenseID), rec, 0o600)
}

// graceUnwrap returns the cached keys if the cache is present, within the
// local window AND the server-stated NotAfter, not clock-rolled-back, and its
// authenticated timestamps are intact.
func graceUnwrap(g *graceConfig, c license.Claims) (Unlocked, error) {
	b, err := os.ReadFile(gracePath(g.dir, c.LicenseID))
	if err != nil {
		return Unlocked{}, err
	}
	var rec graceRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return Unlocked{}, err
	}
	now := time.Now().Unix()
	if rec.CachedAt > now+license.ClockSkew {
		return Unlocked{}, errors.New("grace cache: cached in the future (clock rollback)")
	}
	if time.Since(time.Unix(rec.CachedAt, 0)) > g.window {
		return Unlocked{}, errors.New("grace cache: older than the grace window")
	}
	if rec.NotAfter != 0 && now > rec.NotAfter {
		return Unlocked{}, errors.New("grace cache: past the server-stated validity")
	}
	kek, err := graceKEK(g.dir, c.LicenseID)
	if err != nil {
		return Unlocked{}, err
	}
	defer crypto.Wipe(kek)
	// Open also authenticates CachedAt/NotAfter via the AAD: editing them to
	// widen the window makes this fail.
	pt, err := crypto.Open(kek, rec.Sealed, graceAD(c.LicenseID, rec.CachedAt, rec.NotAfter))
	if err != nil {
		return Unlocked{}, fmt.Errorf("grace cache: %w (tampered, or a different machine)", err)
	}
	switch len(pt) {
	case 2 * crypto.KeySize:
		return Unlocked{ContentKey: pt[:crypto.KeySize], StateKey: pt[crypto.KeySize:]}, nil
	case crypto.KeySize:
		return Unlocked{ContentKey: pt}, nil
	default:
		crypto.Wipe(pt)
		return Unlocked{}, errors.New("grace cache: malformed record")
	}
}
