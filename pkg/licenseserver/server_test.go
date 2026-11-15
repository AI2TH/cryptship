package licenseserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AI2TH/cryptship/pkg/attest/attesttest"
	"github.com/AI2TH/cryptship/pkg/online"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	return &Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{"lic_revoked": true}}
}

func post(t *testing.T, h http.Handler, req online.KeyRequest) int {
	t.Helper()
	b, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/key", bytes.NewReader(b)))
	return rec.Code
}

func TestKeyRequiresVerifiedAttestation(t *testing.T) {
	s := newServer(t)
	s.Verifier = attesttest.Verifier{}
	h := s.Handler()
	nonce := []byte("0123456789abcdef")
	good, _ := attesttest.Attester{}.Evidence(t.Context(), online.AttestationNonce("lic_1", nonce))

	cases := []struct {
		name string
		req  online.KeyRequest
		want int
	}{
		{"valid evidence", online.KeyRequest{LicenseID: "lic_1", Nonce: nonce, Attestation: good}, http.StatusOK},
		{"no evidence", online.KeyRequest{LicenseID: "lic_1", Nonce: nonce}, http.StatusForbidden},
		{"arbitrary evidence", online.KeyRequest{LicenseID: "lic_1", Nonce: nonce, Attestation: []byte("anything")}, http.StatusForbidden},
		{"other nonce", online.KeyRequest{LicenseID: "lic_1", Nonce: []byte("fedcba9876543210"), Attestation: good}, http.StatusForbidden},
		{"other license", online.KeyRequest{LicenseID: "lic_2", Nonce: nonce, Attestation: good}, http.StatusForbidden},
		{"revoked", online.KeyRequest{LicenseID: "lic_revoked", Nonce: nonce, Attestation: good}, http.StatusGone},
	}
	for _, tc := range cases {
		if got := post(t, h, tc.req); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestKeyWithoutVerifier(t *testing.T) {
	h := newServer(t).Handler()
	if got := post(t, h, online.KeyRequest{LicenseID: "lic_1", Nonce: []byte("0123456789abcdef")}); got != http.StatusOK {
		t.Fatalf("status %d, want 200", got)
	}
	if got := post(t, h, online.KeyRequest{LicenseID: "lic_revoked", Nonce: []byte("0123456789abcdef")}); got != http.StatusGone {
		t.Fatalf("revoked: status %d, want 410", got)
	}
}
