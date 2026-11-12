package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cryptship/cryptship/pkg/crypto"
	"github.com/cryptship/cryptship/pkg/license"
	"github.com/cryptship/cryptship/pkg/licenseserver"
	"github.com/cryptship/cryptship/pkg/online"
)

// serverBoundLicense builds a license whose content key is wrapped under the KEK
// derived from the server-held binding secret (what `cryptship issue --binding
// online|attested` does).
func serverBoundLicense(t *testing.T, priv ed25519.PrivateKey, master, contentKey []byte, policy license.BindingPolicy, server string) *license.License {
	t.Helper()
	now := time.Now().Unix()
	c := license.Claims{
		Version:      license.FormatVersion,
		LicenseID:    "lic_srv_1",
		CustomerID:   "acme",
		Product:      "widget",
		PayloadID:    "build-xyz",
		IssuedAt:     now,
		NotAfter:     now + 3600,
		SigningKeyID: "v1",
		Binding:      license.Binding{Policy: policy, Server: server},
	}
	secret, err := online.DeriveSecret(master, c.LicenseID)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := crypto.DeriveKEK(secret, []byte(c.LicenseID), c.BindingContext())
	if err != nil {
		t.Fatal(err)
	}
	wk, err := crypto.WrapKey(kek, contentKey)
	if err != nil {
		t.Fatal(err)
	}
	c.WrappedKeys = [][]byte{wk}
	lic, err := license.Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	return lic
}

func TestOfflineNoneRoundTrip(t *testing.T) {
	contentKey, _ := crypto.RandomKey()
	secret, _ := crypto.RandomKey()
	now := time.Now().Unix()
	c := license.Claims{
		Version: license.FormatVersion, LicenseID: "lic_n", Product: "p", PayloadID: "b",
		IssuedAt: now, NotAfter: now + 3600,
		Binding: license.Binding{Policy: license.BindNone}, UnboundSecret: secret,
	}
	kek, _ := crypto.DeriveKEK(secret, []byte(c.LicenseID), c.BindingContext())
	wk, _ := crypto.WrapKey(kek, contentKey)
	c.WrappedKeys = [][]byte{wk}

	got, err := Offline{}.ContentKey(context.Background(), &license.License{Claims: c})
	if err != nil {
		t.Fatalf("ContentKey: %v", err)
	}
	if !bytes.Equal(got, contentKey) {
		t.Fatalf("content key mismatch")
	}
}

func TestOnlineProviderRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	contentKey, _ := crypto.RandomKey()

	srv := &licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	lic := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	ring := license.KeyRing{"v1": pub}

	got, err := (Online{Keys: ring, Client: ts.Client()}).ContentKey(context.Background(), lic)
	if err != nil {
		t.Fatalf("ContentKey: %v", err)
	}
	if !bytes.Equal(got, contentKey) {
		t.Fatalf("content key mismatch")
	}

	// Revoked -> ErrRevoked.
	srv.Revoked[lic.Claims.LicenseID] = true
	if _, err := (Online{Keys: ring, Client: ts.Client()}).ContentKey(context.Background(), lic); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: err = %v, want ErrRevoked", err)
	}
}

func TestAttestedProviderRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	contentKey, _ := crypto.RandomKey()

	srv := &licenseserver.Server{
		Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{},
		Verify: func(e []byte) error {
			if len(e) == 0 {
				return errors.New("no evidence")
			}
			return nil
		},
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	lic := serverBoundLicense(t, priv, master, contentKey, license.BindAttested, ts.URL)
	ring := license.KeyRing{"v1": pub}

	// Mock attester -> KBS accepts and returns the secret.
	got, err := (Attested{Keys: ring, Client: ts.Client(), Attester: MockAttester{}}).ContentKey(context.Background(), lic)
	if err != nil {
		t.Fatalf("attested ContentKey: %v", err)
	}
	if !bytes.Equal(got, contentKey) {
		t.Fatalf("attested content key mismatch")
	}

	// No TEE attester -> cannot produce evidence.
	if _, err := (Attested{Keys: ring, Client: ts.Client(), Attester: DefaultAttester()}).ContentKey(context.Background(), lic); !errors.Is(err, ErrNoTEE) {
		t.Fatalf("no-TEE: err = %v, want ErrNoTEE", err)
	}
}
