package licenseserver

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// attestedRequest runs the client side of the attested protocol against h
// up to the key request.
func attestedRequest(t *testing.T, h http.Handler, licenseID string) (online.KeyRequest, *ecdh.PrivateKey) {
	t.Helper()
	b, _ := json.Marshal(online.ChallengeRequest{LicenseID: licenseID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(b)))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: status %d", rec.Code)
	}
	var ch online.ChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := eph.PublicKey().Bytes()
	ev, _ := attesttest.Attester{}.Evidence(t.Context(), online.AttestationBinding(licenseID, ch.Challenge, pub))
	return online.KeyRequest{LicenseID: licenseID, Nonce: ch.Challenge, Attestation: ev, EphemeralPub: pub}, eph
}

func TestAttestedProtocol(t *testing.T) {
	s := newServer(t)
	s.Verifier = attesttest.Verifier{}
	h := s.Handler()

	// Genuine exchange: 200, signed, and the secret opens only with eph.
	req, eph := attestedRequest(t, h, "lic_1")
	b, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/key", bytes.NewReader(b)))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid attested request: %d", rec.Code)
	}
	keys := map[string]ed25519.PublicKey{"v1": s.SignKey.Public().(ed25519.PublicKey)}
	kr, err := online.VerifyAttestedKeyResponse(rec.Body.Bytes(), keys, "lic_1", req.Nonce, req.EphemeralPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := online.OpenFromServer(eph, kr.ServerPub, "lic_1", req.Nonce, kr.SealedSecret)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := online.DeriveSecret(s.Master, "lic_1"); !bytes.Equal(secret, want) {
		t.Fatal("wrong secret")
	}
	// The same request again: challenge spent.
	if got := post(t, h, req); got != http.StatusForbidden {
		t.Errorf("replayed request: %d, want 403", got)
	}

	fresh := func() online.KeyRequest { r, _ := attestedRequest(t, h, "lic_1"); return r }
	attackerKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	swapped := fresh()
	swapped.EphemeralPub = attackerKey.PublicKey().Bytes() // genuine evidence, attacker's key
	noEvidence := fresh()
	noEvidence.Attestation = nil
	junk := fresh()
	junk.Attestation = []byte("anything")
	forged := fresh()
	forged.Nonce = bytes.Repeat([]byte{1}, online.ChallengeSize)
	otherLic := fresh()
	otherLic.LicenseID = "lic_2"
	badKey := fresh()
	badKey.EphemeralPub = []byte("short")

	cases := []struct {
		name string
		req  online.KeyRequest
		want int
	}{
		{"evidence for another ephemeral key", swapped, http.StatusForbidden},
		{"no evidence", noEvidence, http.StatusForbidden},
		{"arbitrary evidence", junk, http.StatusForbidden},
		{"forged challenge", forged, http.StatusForbidden},
		{"challenge for another license", otherLic, http.StatusForbidden},
		{"malformed ephemeral key", badKey, http.StatusBadRequest},
		{"plain request (no attestation protocol)", online.KeyRequest{LicenseID: "lic_1", Nonce: []byte("0123456789abcdef")}, http.StatusForbidden},
	}
	for _, tc := range cases {
		if got := post(t, h, tc.req); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}

	// An expired challenge is refused.
	s.ChallengeTTL = -time.Second
	if got := post(t, h, fresh()); got != http.StatusForbidden {
		t.Errorf("expired challenge: %d, want 403", got)
	}
	s.ChallengeTTL = 0

	// Revoked: no challenge is issued.
	rb, _ := json.Marshal(online.ChallengeRequest{LicenseID: "lic_revoked"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(rb)))
	if rr.Code != http.StatusGone {
		t.Errorf("challenge for revoked license: %d, want 410", rr.Code)
	}
}

func TestAttestedRefusedWithoutVerifier(t *testing.T) {
	s := newServer(t)
	h := s.Handler()
	rb, _ := json.Marshal(online.ChallengeRequest{LicenseID: "lic_1"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(rb)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("challenge without a verifier: %d, want 403", rr.Code)
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	req := online.KeyRequest{LicenseID: "lic_1", Nonce: make([]byte, online.ChallengeSize), EphemeralPub: eph.PublicKey().Bytes(), Attestation: []byte("x")}
	if got := post(t, h, req); got != http.StatusForbidden {
		t.Fatalf("attested request without a verifier: %d, want 403", got)
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
