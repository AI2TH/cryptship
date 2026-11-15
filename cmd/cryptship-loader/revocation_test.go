package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/licenseserver"
	"github.com/AI2TH/cryptship/pkg/online"
)

// revocationFixture is a signing cryptship-server plus a license that points
// its revocation_url at it.
type revocationFixture struct {
	srv    *licenseserver.Server
	ts     *httptest.Server
	ring   license.KeyRing
	lic    *license.License
	secret []byte
}

func newRevocationFixture(t *testing.T) *revocationFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := &licenseserver.Server{Master: make([]byte, 32), SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	secret, _ := crypto.RandomKey()
	t.Setenv("CRYPTSHIP_STATE_DIR", t.TempDir())
	return &revocationFixture{
		srv: srv, ts: ts, ring: license.KeyRing{"v1": pub}, secret: secret,
		lic: &license.License{Claims: license.Claims{LicenseID: "lic_r", RevocationURL: ts.URL + "/v1/check"}},
	}
}

func (f *revocationFixture) graceState() sealedState {
	return sealedState{info: revocationStateInfo, licenseID: f.lic.Claims.LicenseID, path: stateFile("revocation", f.lic.Claims.LicenseID)}
}

func TestRevocationSignedAnswer(t *testing.T) {
	f := newRevocationFixture(t)
	for _, mode := range []string{"open", "closed", "grace:1h"} {
		t.Setenv("CRYPTSHIP_REVOCATION", mode)
		if err := enforceRevocation(f.lic, f.ring, f.secret); err != nil {
			t.Fatalf("%s: active license refused: %v", mode, err)
		}
	}
	if _, err := f.graceState().read(f.secret); err != nil {
		t.Fatalf("a signed success must record a sealed grace time: %v", err)
	}
	f.srv.Revoked["lic_r"] = true
	for _, mode := range []string{"open", "closed", "grace:1h"} {
		t.Setenv("CRYPTSHIP_REVOCATION", mode)
		if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("%s: revoked license: err = %v", mode, err)
		}
	}
}

// An on-path attacker answers in place of the server.
func TestRevocationRejectsForgedAndReplayedAnswers(t *testing.T) {
	f := newRevocationFixture(t)
	f.srv.Revoked["lic_r"] = true

	// Capture one genuine signed answer ("revoked: true") for a fixed nonce.
	resp, err := http.Get(f.ts.URL + "/v1/check?license_id=lic_r&nonce=00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	var captured online.CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&captured); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	attackers := map[string]func(w http.ResponseWriter, r *http.Request){
		"captive portal 200": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
		"flipped revoked flag": func(w http.ResponseWriter, r *http.Request) {
			c := captured
			c.Nonce = mustHex(t, r.URL.Query().Get("nonce"))
			c.Revoked = false // signature no longer matches
			_ = json.NewEncoder(w).Encode(c)
		},
		"replayed answer": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(captured) // genuine, but for another nonce
		},
		"unknown signer": func(w http.ResponseWriter, r *http.Request) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			c := online.CheckResponse{LicenseID: "lic_r", Nonce: mustHex(t, r.URL.Query().Get("nonce")), NotAfter: time.Now().Add(time.Hour).Unix()}
			online.SignCheck(other, "v1", &c)
			_ = json.NewEncoder(w).Encode(c)
		},
	}
	for name, h := range attackers {
		ts := httptest.NewServer(http.HandlerFunc(h))
		f.lic.Claims.RevocationURL = ts.URL
		t.Setenv("CRYPTSHIP_REVOCATION", "closed")
		if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
			t.Errorf("%s: forged answer accepted in closed mode", name)
		}
		// In open / grace mode an unsigned answer may let the app run, but
		// it must never refresh the grace record.
		t.Setenv("CRYPTSHIP_REVOCATION", "grace:1h")
		_ = enforceRevocation(f.lic, f.ring, f.secret)
		ts.Close()
	}
	if _, err := os.Stat(f.graceState().path); !os.IsNotExist(err) {
		t.Fatal("a forged answer wrote a grace record")
	}
}

func TestRevocationUnsignedNeverRefreshesGrace(t *testing.T) {
	f := newRevocationFixture(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer ts.Close()
	f.lic.Claims.RevocationURL = ts.URL
	for _, mode := range []string{"open", "grace:1h"} {
		t.Setenv("CRYPTSHIP_REVOCATION", mode)
		if err := enforceRevocation(f.lic, f.ring, f.secret); err != nil {
			t.Fatalf("%s mode accepts an unsigned 200: %v", mode, err)
		}
	}
	t.Setenv("CRYPTSHIP_REVOCATION", "closed")
	if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
		t.Fatal("closed mode accepted an unsigned 200")
	}
	if _, err := os.Stat(f.graceState().path); !os.IsNotExist(err) {
		t.Fatal("an unsigned answer wrote a grace record")
	}
}

func TestRevocationGraceIsSealed(t *testing.T) {
	f := newRevocationFixture(t)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	f.lic.Claims.RevocationURL = down.URL
	t.Setenv("CRYPTSHIP_REVOCATION", "grace:1h")
	st := f.graceState()
	write := func(ts int64) {
		t.Helper()
		if err := st.write(f.secret, ts); err != nil {
			t.Fatal(err)
		}
	}

	write(time.Now().Add(-10 * time.Minute).Unix())
	if err := enforceRevocation(f.lic, f.ring, f.secret); err != nil {
		t.Fatalf("recent signed success should be within grace: %v", err)
	}
	write(time.Now().Add(-2 * time.Hour).Unix())
	if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
		t.Fatal("old success accepted as within grace")
	}
	write(time.Now().Add(365 * 24 * time.Hour).Unix())
	if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
		t.Fatal("future success timestamp accepted as within grace")
	}

	// A hand-written plain-text timestamp (the old format) is not trusted.
	if err := os.WriteFile(st.path, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
		t.Fatal("plain-text grace record accepted")
	}

	// A record sealed for another license, or under another key, is not trusted.
	other := sealedState{info: revocationStateInfo, licenseID: "lic_other", path: st.path}
	if err := other.write(f.secret, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
		t.Fatal("grace record of another license accepted")
	}
	otherKey, _ := crypto.RandomKey()
	if err := st.write(otherKey, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := enforceRevocation(f.lic, f.ring, f.secret); err == nil {
		t.Fatal("grace record sealed under another key accepted")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		b[i] = byte(v)
	}
	return b
}
