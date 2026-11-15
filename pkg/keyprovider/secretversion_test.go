package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/attest/attesttest"
	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/licenseserver"
	"github.com/AI2TH/cryptship/pkg/online"
)

func newKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte, []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	contentKey, _ := crypto.RandomKey()
	return pub, priv, master, contentKey
}

// An online server (no verifier) that shares the master key must not be able
// to release a secret that unwraps a version-2 attested license, whatever
// policy or secret version the caller asks for.
func TestOnlineServerCannotReleaseAttestedSecret(t *testing.T) {
	pub, priv, master, contentKey := newKeys(t)
	ts := httptest.NewServer((&licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1"}).Handler())
	defer ts.Close()
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindAttested, ts.URL)
	keys := map[string]ed25519.PublicKey{"v1": pub}

	for _, policy := range []string{"", "online", "attested", "none"} {
		for _, sv := range []int{0, 2, 3} {
			nonce := make([]byte, 16)
			_, _ = rand.Read(nonce)
			b, _ := json.Marshal(online.KeyRequest{LicenseID: lic.Claims.LicenseID, Nonce: nonce, Policy: policy, SecretVersion: sv})
			resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				continue
			}
			kr, err := online.VerifyKeyResponse(body, keys, lic.Claims.LicenseID, nonce, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Unwrap(lic.Claims, kr.Secret); err == nil {
				t.Fatalf("policy %q secret_v %d: an online server released a secret that unwraps the attested license", policy, sv)
			}
		}
	}
	// The real attested path still fails there (no verifier) ...
	if _, err := (Attested{Keys: keys, Client: ts.Client(), Attester: attesttest.Attester{}}).ContentKey(context.Background(), lic); !errors.Is(err, ErrDenied) {
		t.Fatalf("attested on an online server: %v", err)
	}
	// ... and works on a verifying server with the same master key.
	vs := httptest.NewServer((&licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Verifier: attesttest.Verifier{}}).Handler())
	defer vs.Close()
	lic2 := serverBoundLicense(t, priv, master, contentKey, license.BindAttested, vs.URL)
	if got, err := (Attested{Keys: keys, Client: vs.Client(), Attester: attesttest.Attester{}}).ContentKey(context.Background(), lic2); err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("attested on a verifying server: %v", err)
	}
}

// Licenses issued before secret version 2 keep working, until the server is
// told to refuse the legacy derivation.
func TestLegacySecretVersion(t *testing.T) {
	pub, priv, master, contentKey := newKeys(t)
	keys := license.KeyRing{"v1": pub}
	srv := &licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1"}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	legacy := serverBoundLicenseV(t, priv, master, contentKey, license.BindOnline, ts.URL, license.SecretVersionLegacy)
	if got, err := (Online{Keys: keys, Client: ts.Client()}).ContentKey(context.Background(), legacy); err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("legacy online license: %v", err)
	}
	v2 := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	if got, err := (Online{Keys: keys, Client: ts.Client()}).ContentKey(context.Background(), v2); err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("v2 online license: %v", err)
	}

	srv.NoLegacySecrets = true
	if _, err := (Online{Keys: keys, Client: ts.Client()}).ContentKey(context.Background(), legacy); !errors.Is(err, ErrDenied) {
		t.Fatalf("legacy license with NoLegacySecrets: err = %v, want ErrDenied", err)
	}
	if _, err := (Online{Keys: keys, Client: ts.Client()}).ContentKey(context.Background(), v2); err != nil {
		t.Fatalf("v2 license with NoLegacySecrets: %v", err)
	}
}

// A verifying server also serves v2 online licenses (their secret cannot open
// an attested license), but never legacy ones over the plain path.
func TestVerifyingServerServesOnlineV2Only(t *testing.T) {
	pub, priv, master, contentKey := newKeys(t)
	keys := license.KeyRing{"v1": pub}
	ts := httptest.NewServer((&licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Verifier: attesttest.Verifier{}}).Handler())
	defer ts.Close()
	v2 := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	if _, err := (Online{Keys: keys, Client: ts.Client()}).ContentKey(context.Background(), v2); err != nil {
		t.Fatalf("v2 online on a verifying server: %v", err)
	}
	legacy := serverBoundLicenseV(t, priv, master, contentKey, license.BindOnline, ts.URL, license.SecretVersionLegacy)
	if _, err := (Online{Keys: keys, Client: ts.Client()}).ContentKey(context.Background(), legacy); !errors.Is(err, ErrDenied) {
		t.Fatalf("legacy online on a verifying server: err = %v, want ErrDenied", err)
	}
}
