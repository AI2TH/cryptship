package keyprovider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/licenseserver"
)

// TestOnlineGraceTimestampTamperRejected: the cached_at/not_after timestamps are
// authenticated via the AEAD AAD, so editing them on disk (to widen the window)
// makes the cache fail to open rather than extend grace.
func TestOnlineGraceTimestampTamperRejected(t *testing.T) {
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
	if _, err := o.ContentKey(context.Background(), lic); err != nil {
		t.Fatalf("prime: %v", err)
	}
	ts.Close()

	p := filepath.Join(dir, "online-grace-"+url.PathEscape(lic.Claims.LicenseID))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["cached_at"] = float64(time.Now().Unix() + 5) // different from the sealed value
	nb, _ := json.Marshal(m)
	if err := os.WriteFile(p, nb, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := o.ContentKey(context.Background(), lic); err == nil {
		t.Fatal("tampered grace cached_at was accepted")
	}
}
