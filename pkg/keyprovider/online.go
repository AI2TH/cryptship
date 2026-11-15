package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	var g *graceConfig
	if o.CacheDir != "" && o.Grace > 0 {
		g = &graceConfig{dir: o.CacheDir, window: o.Grace}
	}
	return fetchAndUnwrap(ctx, o.Keys, o.Client, lic, nil, g)
}

// graceConfig configures the outage cache (online only).
type graceConfig struct {
	dir    string
	window time.Duration
}

// fetchAndUnwrap runs the request / verify / unwrap flow shared by the online
// and attested providers. evidence is nil for online; for attested it returns
// evidence bound to the request nonce. grace is non-nil only for online.
func fetchAndUnwrap(ctx context.Context, keys license.KeyRing, client HTTPClient, lic *license.License, evidence func(nonce []byte) ([]byte, error), grace *graceConfig) ([]byte, error) {
	c := lic.Claims
	if c.Binding.Server == "" {
		return nil, errors.New("online: license has no binding.server")
	}
	if client == nil {
		return nil, errors.New("online: no HTTP client configured")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	var attestation []byte
	if evidence != nil {
		var err error
		if attestation, err = evidence(nonce); err != nil {
			return nil, err
		}
	}
	m, _ := machine.ID()
	body, err := json.Marshal(online.KeyRequest{LicenseID: c.LicenseID, Machine: m, Nonce: nonce, Attestation: attestation})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Binding.Server, "/")+"/v1/key", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Server unreachable: ride out the outage with a cached secret, if any.
		if grace != nil {
			if key, gerr := graceUnwrap(grace, c); gerr == nil {
				fmt.Fprintln(os.Stderr, "cryptship: license server unreachable, using grace cache:", err)
				return key, nil
			}
		}
		return nil, fmt.Errorf("online: %w", err)
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

	var kr online.KeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&kr); err != nil {
		return nil, fmt.Errorf("online: bad response: %w", err)
	}
	pub, ok := keys[kr.SigningKeyID]
	if !ok {
		pub, ok = keys["*"]
	}
	if !ok {
		return nil, fmt.Errorf("online: response signed by unknown key %q", kr.SigningKeyID)
	}
	if kr.LicenseID != c.LicenseID || !bytes.Equal(kr.Nonce, nonce) || len(kr.Secret) != online.SecretSize {
		return nil, errors.New("online: response does not match request")
	}
	if kr.NotAfter != 0 && time.Now().Unix() > kr.NotAfter {
		return nil, errors.New("online: response already expired")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, online.ResponseSigningInput(kr), kr.Sig) {
		return nil, errors.New("online: bad response signature")
	}
	if grace != nil {
		graceStore(grace, c, kr.Secret, kr.NotAfter) // best effort
	}
	defer crypto.Wipe(kr.Secret)
	return Unwrap(c, kr.Secret)
}

// --- outage grace cache ---

const graceAAD = "cryptship/online-grace/v1"

type graceRecord struct {
	Sealed   []byte `json:"sealed"`    // AES-256-GCM(secret) under the machine KEK
	CachedAt int64  `json:"cached_at"` // unix seconds
	NotAfter int64  `json:"not_after"` // server-stated validity (informational)
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

func graceStore(g *graceConfig, c license.Claims, secret []byte, serverNotAfter int64) {
	kek, err := graceKEK(g.dir, c.LicenseID)
	if err != nil {
		return
	}
	defer crypto.Wipe(kek)
	sealed, err := crypto.Seal(kek, secret, []byte(graceAAD+"|"+c.LicenseID))
	if err != nil {
		return
	}
	rec, err := json.Marshal(graceRecord{Sealed: sealed, CachedAt: time.Now().Unix(), NotAfter: serverNotAfter})
	if err != nil {
		return
	}
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(gracePath(g.dir, c.LicenseID), rec, 0o600)
}

func graceUnwrap(g *graceConfig, c license.Claims) ([]byte, error) {
	b, err := os.ReadFile(gracePath(g.dir, c.LicenseID))
	if err != nil {
		return nil, err
	}
	var rec graceRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	if rec.CachedAt > time.Now().Unix()+license.ClockSkew {
		return nil, errors.New("grace cache: cached in the future (clock rollback)")
	}
	if time.Since(time.Unix(rec.CachedAt, 0)) > g.window {
		return nil, errors.New("grace cache: older than the grace window")
	}
	kek, err := graceKEK(g.dir, c.LicenseID)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kek)
	secret, err := crypto.Open(kek, rec.Sealed, []byte(graceAAD+"|"+c.LicenseID))
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(secret)
	return Unwrap(c, secret)
}
