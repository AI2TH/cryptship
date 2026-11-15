package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/licenseserver"
)

// TestOnlineGraceRidesOutOutage: after one successful fetch, an unreachable
// server is survived within the grace window; without grace it fails.
func TestOnlineGraceRidesOutOutage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	contentKey, _ := crypto.RandomKey()
	srv := &licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}}
	ts := httptest.NewServer(srv.Handler())
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	ring := license.KeyRing{"v1": pub}
	dir := t.TempDir()

	o := Online{Keys: ring, Client: ts.Client(), CacheDir: dir, Grace: time.Hour}
	got, err := o.ContentKey(context.Background(), lic)
	if err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("first fetch: err=%v", err)
	}

	ts.Close() // server now unreachable

	got2, err := o.ContentKey(context.Background(), lic)
	if err != nil {
		t.Fatalf("grace should ride out the outage: %v", err)
	}
	if !bytes.Equal(got2, contentKey) {
		t.Fatalf("grace content key mismatch")
	}

	// Without grace configured, the same outage is fatal.
	if _, err := (Online{Keys: ring, Client: ts.Client()}).ContentKey(context.Background(), lic); err == nil {
		t.Fatal("no grace: outage should fail")
	}
}

// TestOnlineGraceExpires: a cache older than the window is not used.
func TestOnlineGraceExpires(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	contentKey, _ := crypto.RandomKey()
	srv := &licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}}
	ts := httptest.NewServer(srv.Handler())
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	ring := license.KeyRing{"v1": pub}
	dir := t.TempDir()

	// Prime the cache with a 1ns window, then let it lapse.
	o := Online{Keys: ring, Client: ts.Client(), CacheDir: dir, Grace: time.Nanosecond}
	if _, err := o.ContentKey(context.Background(), lic); err != nil {
		t.Fatalf("prime: %v", err)
	}
	ts.Close()
	time.Sleep(2 * time.Millisecond)
	if _, err := o.ContentKey(context.Background(), lic); err == nil {
		t.Fatal("stale cache should not satisfy an outage")
	}
}

// Editing cached_at (the only way to extend grace without the server) breaks
// the seal: the record opens only with the exact time it was sealed with.
func TestOnlineGraceCachedAtIsAuthenticated(t *testing.T) {
	pub, priv, master, contentKey := newKeys(t)
	ts := httptest.NewServer((&licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1"}).Handler())
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	dir := t.TempDir()
	o := Online{Keys: license.KeyRing{"v1": pub}, Client: ts.Client(), CacheDir: dir, Grace: time.Hour}
	if _, err := o.ContentKey(context.Background(), lic); err != nil {
		t.Fatal(err)
	}
	ts.Close()
	if _, err := o.ContentKey(context.Background(), lic); err != nil {
		t.Fatalf("genuine record refused: %v", err)
	}

	path := gracePath(dir, lic.Claims.LicenseID)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec graceRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	rec.CachedAt-- // still inside the window and not in the future
	edited, _ := json.Marshal(rec)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ContentKey(context.Background(), lic); err == nil {
		t.Fatal("record with an edited cached_at accepted")
	}
}

// A 503 from a proxy in front of the server is an outage: grace applies. A
// revoked answer is not.
func TestOnlineGraceOnGatewayErrorButNotRevocation(t *testing.T) {
	pub, priv, master, contentKey := newKeys(t)
	srv := &licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}}
	var down atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "upstream down", http.StatusServiceUnavailable)
			return
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindOnline, ts.URL)
	o := Online{Keys: license.KeyRing{"v1": pub}, Client: ts.Client(), CacheDir: t.TempDir(), Grace: time.Hour}
	if _, err := o.ContentKey(context.Background(), lic); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	if got, err := o.ContentKey(context.Background(), lic); err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("503 should be ridden out: %v", err)
	}
	down.Store(false)
	srv.Revoked[lic.Claims.LicenseID] = true
	if _, err := o.ContentKey(context.Background(), lic); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: err = %v, want ErrRevoked (grace must not cover revocation)", err)
	}
}
