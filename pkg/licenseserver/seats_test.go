package licenseserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/online"
)

func TestSeatTracker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seats.json")
	st := &SeatTracker{Lease: time.Hour, Path: path}
	now := time.Now()
	for _, m := range []string{"m1", "m2", "m1"} {
		if err := st.Claim("lic", m, 2, now); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	if err := st.Claim("lic", "m3", 2, now); !errors.Is(err, ErrSeatLimit) {
		t.Fatalf("third machine: err = %v", err)
	}
	if err := st.Claim("lic_other", "m3", 2, now); err != nil {
		t.Fatalf("seats are per license: %v", err)
	}
	if err := st.Claim("lic", "", 2, now); !errors.Is(err, ErrSeatLimit) {
		t.Fatalf("no machine id: err = %v", err)
	}
	if err := st.Claim("lic", "m9", 0, now); err != nil {
		t.Fatalf("max 0 is unlimited: %v", err)
	}

	// Seats survive a restart.
	st2 := &SeatTracker{Lease: time.Hour, Path: path}
	if n := st2.InUse("lic", now); n != 2 {
		t.Fatalf("after reload: %d seats, want 2", n)
	}
	if err := st2.Claim("lic", "m3", 2, now); !errors.Is(err, ErrSeatLimit) {
		t.Fatalf("after reload, third machine: %v", err)
	}
	// A lapsed lease frees the seat; Release frees one at once.
	if err := st2.Claim("lic", "m3", 2, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("after the lease lapsed: %v", err)
	}
	st2.Release("lic", "m3")
	if n := st2.InUse("lic", now.Add(2*time.Hour)); n != 0 {
		t.Fatalf("after release: %d seats", n)
	}
}

func seatLicense(t *testing.T, priv ed25519.PrivateKey, id string, max int) json.RawMessage {
	t.Helper()
	c := license.Claims{Version: license.FormatVersion, LicenseID: id, PayloadID: "p", SigningKeyID: "v1",
		Binding: license.Binding{Policy: license.BindOnline, Server: "https://k", Max: max, SecretVersion: license.SecretVersion2}}
	lic, err := license.Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := lic.Marshal()
	return b
}

func TestServerEnforcesSeats(t *testing.T) {
	s := newServer(t)
	s.Seats = &SeatTracker{}
	h := s.Handler()
	lic := seatLicense(t, s.SignKey, "lic_1", 2)
	req := func(machine string, l json.RawMessage, id string) int {
		r := online.KeyRequest{LicenseID: id, Machine: machine, Nonce: []byte("0123456789abcdef"),
			Policy: "online", SecretVersion: license.SecretVersion2, License: l}
		b, _ := json.Marshal(r)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/key", bytes.NewReader(b)))
		return rec.Code
	}
	if c := req("m1", lic, "lic_1"); c != http.StatusOK {
		t.Fatalf("m1: %d", c)
	}
	if c := req("m2", lic, "lic_1"); c != http.StatusOK {
		t.Fatalf("m2: %d", c)
	}
	if c := req("m3", lic, "lic_1"); c != http.StatusConflict {
		t.Fatalf("m3: %d, want 409", c)
	}
	if c := req("m1", lic, "lic_1"); c != http.StatusOK {
		t.Fatalf("m1 again: %d", c)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]int{
		"no license":            req("m4", nil, "lic_1"),
		"forged license":        req("m4", seatLicense(t, other, "lic_1", 100), "lic_1"),
		"another license's max": req("m4", seatLicense(t, s.SignKey, "lic_2", 100), "lic_1"),
		"garbage":               req("m4", json.RawMessage(`{"claims":{}}`), "lic_1"),
	}
	for name, code := range cases {
		if code == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unlimited license (max 0).
	if c := req("anything", seatLicense(t, s.SignKey, "lic_3", 0), "lic_3"); c != http.StatusOK {
		t.Fatalf("max 0: %d", c)
	}
}
