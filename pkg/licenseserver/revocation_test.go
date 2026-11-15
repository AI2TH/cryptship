package licenseserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI2TH/cryptship/pkg/online"
)

func newTestServer(t *testing.T) (*Server, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	return &Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}}, pub
}

// TestRevokedFileLiveReload: editing the denylist file revokes/restores a
// license without restarting the server.
func TestRevokedFileLiveReload(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.RevokedFile = filepath.Join(t.TempDir(), "deny.txt")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	keyStatus := func(id string) int {
		resp, err := http.Post(ts.URL+"/v1/key", "application/json",
			strings.NewReader(`{"license_id":"`+id+`","nonce":"AAAAAAAAAAAAAAAAAAAAAA=="}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := keyStatus("lic_x"); code != http.StatusOK {
		t.Fatalf("before revoke: got %d, want 200", code)
	}
	if err := os.WriteFile(srv.RevokedFile, []byte("lic_x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := keyStatus("lic_x"); code != http.StatusGone {
		t.Fatalf("after revoke-file write: got %d, want 410", code)
	}
	if err := os.WriteFile(srv.RevokedFile, []byte("# cleared\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := keyStatus("lic_x"); code != http.StatusOK {
		t.Fatalf("after revoke-file clear: got %d, want 200", code)
	}
}

// TestRevokedFileSameLengthSwap: a same-byte-length edit to the denylist is seen
// (the file is re-read every request, so no mtime/size staleness).
func TestRevokedFileSameLengthSwap(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.RevokedFile = filepath.Join(t.TempDir(), "deny.txt")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	post := func(id string) int {
		resp, err := http.Post(ts.URL+"/v1/key", "application/json",
			strings.NewReader(`{"license_id":"`+id+`","nonce":"AAAAAAAAAAAAAAAAAAAAAA=="}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if err := os.WriteFile(srv.RevokedFile, []byte("lic_aaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if post("lic_aaaaaaaa") != http.StatusGone {
		t.Fatal("A should be revoked")
	}
	// Same byte length (13 bytes) — must still be observed.
	if err := os.WriteFile(srv.RevokedFile, []byte("lic_bbbbbbbb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if post("lic_aaaaaaaa") != http.StatusOK {
		t.Fatal("A should be active after the swap")
	}
	if post("lic_bbbbbbbb") != http.StatusGone {
		t.Fatal("B should be revoked after the swap")
	}
}

// TestSignedCheckResponse: /v1/check with a nonce returns a signed answer whose
// Revoked flag the loader can trust.
func TestSignedCheckResponse(t *testing.T) {
	srv, pub := newTestServer(t)
	srv.Revoked["lic_bad"] = true
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	check := func(id string) online.CheckResponse {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		resp, err := http.Get(ts.URL + "/v1/check?license_id=" + id + "&nonce=" + hex.EncodeToString(nonce))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var cr online.CheckResponse
		if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cr.Nonce, nonce) {
			t.Fatalf("%s: nonce not echoed", id)
		}
		if !ed25519.Verify(pub, online.CheckSigningInput(cr), cr.Sig) {
			t.Fatalf("%s: bad signature", id)
		}
		return cr
	}

	if check("lic_ok").Revoked {
		t.Fatal("lic_ok reported revoked")
	}
	if !check("lic_bad").Revoked {
		t.Fatal("lic_bad not reported revoked")
	}
}
