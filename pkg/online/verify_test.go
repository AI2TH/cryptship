package online

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestVerifyCheckResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"v1": pub}
	nonce := []byte("0123456789abcdef")
	now := time.Now()
	sign := func(r CheckResponse) []byte {
		SignCheck(priv, "v1", &r)
		b, _ := json.Marshal(r)
		return b
	}
	good := CheckResponse{LicenseID: "lic", Nonce: nonce, NotAfter: now.Add(time.Hour).Unix()}

	if r, err := VerifyCheckResponse(sign(good), keys, "lic", nonce, now); err != nil || r.Revoked {
		t.Fatalf("good answer: %+v %v", r, err)
	}
	revoked := good
	revoked.Revoked = true
	if r, err := VerifyCheckResponse(sign(revoked), keys, "lic", nonce, now); err != nil || !r.Revoked {
		t.Fatalf("revoked answer: %+v %v", r, err)
	}

	tampered := good
	SignCheck(priv, "v1", &tampered)
	tampered.Revoked = true
	tb, _ := json.Marshal(tampered)
	expired := good
	expired.NotAfter = now.Add(-time.Minute).Unix()

	cases := []struct {
		name string
		body []byte
		lic  string
		want error
	}{
		{"not json", []byte("OK"), "lic", ErrUnsigned},
		{"no signature", []byte(`{"license_id":"lic"}`), "lic", ErrUnsigned},
		{"tampered", tb, "lic", ErrBadSignature},
		{"other license", sign(good), "lic_other", ErrMismatch},
		{"expired", sign(expired), "lic", ErrExpired},
	}
	for _, tc := range cases {
		if _, err := VerifyCheckResponse(tc.body, keys, tc.lic, nonce, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := VerifyCheckResponse(sign(good), keys, "lic", []byte("fedcba9876543210"), now); !errors.Is(err, ErrMismatch) {
		t.Errorf("replayed nonce: err = %v", err)
	}
	if _, err := VerifyCheckResponse(sign(good), map[string]ed25519.PublicKey{"v2": pub}, "lic", nonce, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("unknown key id: err = %v", err)
	}
}

// A key answer's signature cannot be presented as a check answer.
func TestCheckAndKeySignaturesAreDomainSeparated(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := KeyResponse{LicenseID: "lic", Nonce: []byte("0123456789abcdef"), NotAfter: time.Now().Add(time.Hour).Unix(), SigningKeyID: "v1"}
	kr.Sig = ed25519.Sign(priv, ResponseSigningInput(kr))
	cr := CheckResponse{LicenseID: kr.LicenseID, Nonce: kr.Nonce, NotAfter: kr.NotAfter, SigningKeyID: "v1", Sig: kr.Sig}
	b, _ := json.Marshal(cr)
	if _, err := VerifyCheckResponse(b, map[string]ed25519.PublicKey{"v1": pub}, "lic", kr.Nonce, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("key-answer signature accepted on a check answer: %v", err)
	}
}
