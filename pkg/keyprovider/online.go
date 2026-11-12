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
	"strings"
	"time"

	"github.com/cryptship/cryptship/pkg/crypto"
	"github.com/cryptship/cryptship/pkg/license"
	"github.com/cryptship/cryptship/pkg/machine"
	"github.com/cryptship/cryptship/pkg/online"
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
type Online struct {
	Keys   license.KeyRing
	Client HTTPClient
}

// Name implements Provider.
func (Online) Name() string { return "online" }

// Handles implements Provider.
func (Online) Handles(p license.BindingPolicy) bool { return p == license.BindOnline }

// ContentKey implements Provider.
func (o Online) ContentKey(ctx context.Context, lic *license.License) ([]byte, error) {
	return fetchAndUnwrap(ctx, o.Keys, o.Client, lic, nil)
}

// fetchAndUnwrap runs the request / verify / unwrap flow shared by the online
// and attested providers. attestation is nil for online.
func fetchAndUnwrap(ctx context.Context, keys license.KeyRing, client HTTPClient, lic *license.License, attestation []byte) ([]byte, error) {
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
	m, _ := machine.ID()
	body, _ := json.Marshal(online.KeyRequest{LicenseID: c.LicenseID, Machine: m, Nonce: nonce, Attestation: attestation})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Binding.Server, "/")+"/v1/key", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("online: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusGone, http.StatusForbidden:
		return nil, ErrRevoked
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
	defer crypto.Wipe(kr.Secret)
	return Unwrap(c, kr.Secret)
}
