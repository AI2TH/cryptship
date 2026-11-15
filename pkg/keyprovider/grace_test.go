package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
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
